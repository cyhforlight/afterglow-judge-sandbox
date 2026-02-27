package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	cgroupsv1 "github.com/containerd/cgroups/v3/cgroup1/stats"
	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2/stats"
	"github.com/containerd/errdefs"
	typeurl "github.com/containerd/typeurl/v2"

	"afterglow-judge-sandbox/internal/model"
)

const (
	defaultSocketPath = "/run/containerd/containerd.sock"
	defaultNamespace  = "afterglow"
	cgroupV2CheckPath = "/sys/fs/cgroup/cgroup.controllers"

	// Wall time is allowed to be this multiple of CPU time limit.
	// Accounts for I/O waits, scheduling latency, container overhead, etc.
	wallTimeMultiplier = 3

	// Max tasks (threads + processes) in the container.
	// 128 is plenty for JVM (~20 threads) while still blocking fork bombs.
	pidsLimit = 128

	// Safety cap for input file size to prevent host OOM from malicious inputs.
	maxInputSize = 256 * 1024 * 1024 // 256 MB

	// Treat usage >= 99.5% of the limit as hitting memory limit.
	memoryHitThresholdPermille = 995
)

// pickCPU randomly selects a CPU core for the container.  Each sandbox
// is pinned to exactly one core (no multi-threading advantage), while
// randomization spreads concurrent sandboxes across available cores.
func pickCPU() string {
	return strconv.Itoa(rand.IntN(runtime.NumCPU()))
}

// RunProfile describes how a specific language's program should be
// executed inside a container.  All language differences are captured here
// so the container lifecycle code stays language-agnostic.
type RunProfile struct {
	ImageRef    string                              // container image to pull
	SandboxFile string                              // filename inside /sandbox (e.g. "program", "solution.py")
	FileMode    os.FileMode                         // permissions for the copied file
	BuildArgs   func(containerPath string) []string // build the process argv
}

func NativeRunProfile() RunProfile {
	return RunProfile{
		ImageRef:    "gcr.io/distroless/cc-debian12:latest",
		SandboxFile: "program",
		FileMode:    0755,
		BuildArgs:   func(p string) []string { return []string{p} },
	}
}

func PythonRunProfile() RunProfile {
	return RunProfile{
		ImageRef:    "gcr.io/distroless/python3-debian12:latest",
		SandboxFile: "solution.py",
		FileMode:    0644,
		BuildArgs:   func(p string) []string { return []string{"python3", p} },
	}
}

func JavaRunProfile() RunProfile {
	return RunProfile{
		ImageRef:    "gcr.io/distroless/java21-debian12:latest",
		SandboxFile: "solution.jar",
		FileMode:    0644,
		BuildArgs:   func(p string) []string { return []string{"java", "-jar", p} },
	}
}

type ContainerdRunner struct {
	socketPath string
	namespace  string
	profile    RunProfile

	checkCgroupV2   func() error
	checkContainerd func(ctx context.Context, socketPath string) error
}

func NewContainerdRunner(socketPath string, profile RunProfile) *ContainerdRunner {
	if socketPath == "" {
		socketPath = defaultSocketPath
	}
	return &ContainerdRunner{
		socketPath:      socketPath,
		namespace:       defaultNamespace,
		profile:         profile,
		checkCgroupV2:   ensureCgroupV2Enabled,
		checkContainerd: ensureContainerdAvailable,
	}
}

func ensureCgroupV2Enabled() error {
	_, err := os.Stat(cgroupV2CheckPath)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("cgroup v2 is required: missing /sys/fs/cgroup/cgroup.controllers")
	}
	return fmt.Errorf("check cgroup v2 mount: %w", err)
}

func ensureContainerdAvailable(ctx context.Context, socketPath string) error {
	client, err := containerd.New(socketPath)
	if err != nil {
		return fmt.Errorf("connect to containerd socket %q: %w", socketPath, err)
	}
	defer func() { _ = client.Close() }()

	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if _, err := client.Version(checkCtx); err != nil {
		return fmt.Errorf("ping containerd on %q: %w", socketPath, err)
	}
	return nil
}

func (r *ContainerdRunner) PreflightCheck(ctx context.Context) error {
	if err := r.checkCgroupV2(); err != nil {
		return err
	}
	if err := r.checkContainerd(ctx, r.socketPath); err != nil {
		return err
	}
	return nil
}

// ---------- container security ----------

// sandboxSecurityOpts hardens the container for running untrusted code.
//
// The default OCI spec (from WithImageConfig) already creates isolated Linux
// namespaces — including a network namespace with no interfaces — so the
// container has no network access without any extra configuration.
//
// The options below further restrict what the process can do:
//   - read-only rootfs: the process cannot modify the container image
//   - writable /tmp (tmpfs): JVM and Python need temp space; size is bounded
//     by the cgroup memory limit so it doesn't need a separate cap
//   - single-core pinning: eliminates any multi-threading speed advantage
//   - empty capability sets: no root-like powers at all
//   - no_new_privileges: blocks setuid/setgid escalation
//   - PID limit: caps the number of threads+processes to prevent fork bombs
func sandboxSecurityOpts() oci.SpecOpts {
	return oci.Compose(
		oci.WithRootFSReadonly(),
		oci.WithMounts([]specs.Mount{{
			Destination: "/tmp",
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "nodev"},
		}}),
		oci.WithCPUs(pickCPU()),
		oci.WithCapabilities([]string{}),
		oci.WithNoNewPrivileges,
		oci.WithPidsLimit(pidsLimit),
	)
}

// ---------- cgroup metrics ----------

type cgroupMetrics struct {
	cpuNanos        uint64
	peakMemBytes    uint64
	memoryLimitHit  bool
	oomKillDetected bool
}

func collectMetrics(ctx context.Context, task containerd.Task) cgroupMetrics {
	metric, err := task.Metrics(ctx)
	if err != nil {
		return cgroupMetrics{}
	}
	return parseCgroupMetrics(metric.Data)
}

func parseCgroupMetrics(data typeurl.Any) cgroupMetrics {
	var m cgroupMetrics

	var v2 cgroupsv2.Metrics
	if err := typeurl.UnmarshalTo(data, &v2); err == nil {
		if v2.CPU != nil {
			m.cpuNanos = v2.CPU.UsageUsec * 1000
		}
		if v2.Memory != nil {
			m.peakMemBytes = max(v2.Memory.MaxUsage, v2.Memory.Usage)
		}
		if v2.MemoryEvents != nil {
			if v2.MemoryEvents.OomKill > 0 {
				m.oomKillDetected = true
			}
			if v2.MemoryEvents.Max > 0 || v2.MemoryEvents.Oom > 0 {
				m.memoryLimitHit = true
			}
		}
		return m
	}

	var v1 cgroupsv1.Metrics
	if err := typeurl.UnmarshalTo(data, &v1); err != nil {
		return m
	}

	if v1.CPU != nil && v1.CPU.Usage != nil {
		m.cpuNanos = v1.CPU.Usage.Total
	}

	if v1.Memory != nil && v1.Memory.Usage != nil {
		m.peakMemBytes = max(v1.Memory.Usage.Max, v1.Memory.Usage.Usage)
		if v1.Memory.Usage.Failcnt > 0 {
			m.memoryLimitHit = true
		}
	}

	if v1.MemoryOomControl != nil {
		if v1.MemoryOomControl.OomKill > 0 {
			m.oomKillDetected = true
		}
		if v1.MemoryOomControl.UnderOom > 0 {
			m.memoryLimitHit = true
		}
	}
	return m
}

// ---------- output limiter ----------

// outputLimiter holds a shared byte budget for all associated limitedWriters.
// When the combined output (stdout + stderr) exceeds the budget, the channel
// is closed to signal OLE to the main event loop.
type outputLimiter struct {
	ch    chan struct{}
	once  sync.Once
	mu    sync.Mutex
	limit int64
	used  int64
}

func newOutputLimiter(maxBytes int64) *outputLimiter {
	return &outputLimiter{ch: make(chan struct{}), limit: maxBytes}
}

func (l *outputLimiter) signal() {
	l.once.Do(func() { close(l.ch) })
}

// reserve atomically claims up to requested bytes from the shared pool
// and returns the number of bytes actually granted (may be less, or 0).
func (l *outputLimiter) reserve(requested int64) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	remaining := l.limit - l.used
	if remaining <= 0 {
		return 0
	}
	granted := min(requested, remaining)
	l.used += granted
	return granted
}

// limitedWriter buffers output while drawing bytes from the shared
// outputLimiter pool.  When the pool is exhausted, further writes are
// silently discarded (so the pipe never stalls) and OLE is signalled.
type limitedWriter struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	overflowed bool
	limiter    *outputLimiter
}

func newLimitedWriter(limiter *outputLimiter) *limitedWriter {
	return &limitedWriter{limiter: limiter}
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n := len(p)
	if w.overflowed {
		return n, nil
	}
	allowed := w.limiter.reserve(int64(n))
	if allowed > 0 {
		w.buf.Write(p[:allowed])
	}
	if allowed < int64(n) {
		w.overflowed = true
		w.limiter.signal()
	}
	return n, nil
}

func (w *limitedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (w *limitedWriter) isOverflowed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.overflowed
}

// ---------- Execute ----------

func (r *ContainerdRunner) Execute(ctx context.Context, req model.ExecuteRequest) (model.ExecuteResult, error) {
	client, err := containerd.New(r.socketPath)
	if err != nil {
		return infraErr("connect to containerd: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx = namespaces.WithNamespace(ctx, r.namespace)

	image, err := r.ensureImage(ctx, client)
	if err != nil {
		return infraErr("ensure image: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "sandbox-*")
	if err != nil {
		return infraErr("create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := copyFile(req.ExecutablePath, filepath.Join(tmpDir, r.profile.SandboxFile), r.profile.FileMode); err != nil {
		return infraErr("copy program file: %v", err)
	}

	id := fmt.Sprintf("sandbox-%d", time.Now().UnixNano())
	containerPath := "/sandbox/" + r.profile.SandboxFile
	args := r.profile.BuildArgs(containerPath)

	memoryLimitBytes := int64(req.MemoryLimit) * 1024 * 1024
	outputLimitBytes := memoryLimitBytes

	container, err := client.NewContainer(ctx, id,
		containerd.WithImage(image),
		containerd.WithNewSnapshot(id+"-snap", image),
		containerd.WithNewSpec(
			oci.WithImageConfig(image),
			oci.WithProcessArgs(args...),
			oci.WithMounts([]specs.Mount{{
				Destination: "/sandbox",
				Type:        "bind",
				Source:      tmpDir,
				Options:     []string{"rbind", "ro"},
			}}),
			oci.WithMemoryLimit(uint64(memoryLimitBytes)),
			oci.WithMemorySwap(memoryLimitBytes),
			sandboxSecurityOpts(),
		),
	)
	if err != nil {
		return infraErr("create container: %v", err)
	}
	defer func() { _ = container.Delete(ctx, containerd.WithSnapshotCleanup) }()

	inputInfo, err := os.Stat(req.InputPath)
	if err != nil {
		return infraErr("stat input file: %v", err)
	}
	if inputInfo.Size() > maxInputSize {
		return infraErr("input file too large: %d bytes (max %d)", inputInfo.Size(), maxInputSize)
	}
	inputData, err := os.ReadFile(req.InputPath)
	if err != nil {
		return infraErr("read input file: %v", err)
	}

	oleLimiter := newOutputLimiter(outputLimitBytes)
	stdoutLW := newLimitedWriter(oleLimiter)
	stderrLW := newLimitedWriter(oleLimiter)

	task, err := container.NewTask(ctx, cio.NewCreator(
		cio.WithStreams(bytes.NewReader(inputData), stdoutLW, stderrLW),
	))
	if err != nil {
		return infraErr("create task: %v", err)
	}
	defer func() { _, _ = task.Delete(ctx) }()

	exitCh, err := task.Wait(ctx)
	if err != nil {
		return infraErr("setup wait: %v", err)
	}

	startTime := time.Now()
	if err := task.Start(ctx); err != nil {
		return infraErr("start task: %v", err)
	}

	_ = task.CloseIO(ctx, containerd.WithStdinCloser)

	cpuLimitMs := req.TimeLimit
	wallLimitMs := cpuLimitMs * wallTimeMultiplier
	wallDeadline := time.NewTimer(time.Duration(wallLimitMs) * time.Millisecond)
	defer wallDeadline.Stop()

	var reason string
	select {
	case status := <-exitCh:
		wallElapsed := time.Since(startTime)
		code, _, err := status.Result()
		if err != nil {
			return infraErr("task result: %v", err)
		}
		metrics := collectMetrics(ctx, task)
		return buildVerdict(code, wallElapsed, metrics, cpuLimitMs, req.MemoryLimit, outputLimitBytes, stdoutLW, stderrLW), nil

	case <-oleLimiter.ch:
		reason = "output limit exceeded"

	case <-wallDeadline.C:
		reason = "wall time limit exceeded"
	}

	// The process is still running — collect stats, then kill.
	metrics := collectMetrics(ctx, task)
	_ = task.Kill(ctx, syscall.SIGKILL)
	<-exitCh

	return buildForcedStopVerdict(reason, wallLimitMs, cpuLimitMs, req.MemoryLimit, outputLimitBytes, metrics, stdoutLW, stderrLW), nil
}

// ---------- verdict ----------

func memoryLimitReached(metrics cgroupMetrics, memoryLimitMB int) bool {
	if metrics.memoryLimitHit {
		return true
	}
	if memoryLimitMB <= 0 {
		return false
	}

	limitBytes := uint64(memoryLimitMB) * 1024 * 1024
	if metrics.peakMemBytes >= limitBytes {
		return true
	}
	if limitBytes == 0 {
		return false
	}
	return metrics.peakMemBytes*1000 >= limitBytes*memoryHitThresholdPermille
}

func runtimeOOMDetected(stderr string) bool {
	message := strings.ToLower(stderr)
	return strings.Contains(message, "outofmemory") || strings.Contains(message, "cannot allocate memory")
}

func buildForcedStopVerdict(
	reason string,
	wallLimitMs int,
	cpuLimitMs int,
	memoryLimitMB int,
	outputLimitBytes int64,
	metrics cgroupMetrics,
	stdoutLW *limitedWriter,
	stderrLW *limitedWriter,
) model.ExecuteResult {
	cpuMs := clampInt(metrics.cpuNanos/1e6, uint64(cpuLimitMs))
	peakMemMB := int(metrics.peakMemBytes / 1024 / 1024)

	if stdoutLW.isOverflowed() || stderrLW.isOverflowed() {
		return model.ExecuteResult{
			Verdict:    model.VerdictOLE,
			TimeUsed:   cpuMs,
			MemoryUsed: peakMemMB,
			ExtraInfo:  fmt.Sprintf("output limit exceeded (%d bytes max)", outputLimitBytes),
		}
	}
	if metrics.oomKillDetected || memoryLimitReached(metrics, memoryLimitMB) {
		return model.ExecuteResult{
			Verdict:    model.VerdictMLE,
			TimeUsed:   cpuMs,
			MemoryUsed: peakMemMB,
			ExtraInfo:  fmt.Sprintf("memory limit exceeded (peak %dMB, limit %dMB)", peakMemMB, memoryLimitMB),
		}
	}
	return model.ExecuteResult{
		Verdict:    model.VerdictTLE,
		TimeUsed:   cpuMs,
		MemoryUsed: peakMemMB,
		ExtraInfo:  fmt.Sprintf("%s (%dms wall, cpu limit %dms)", reason, wallLimitMs, cpuLimitMs),
	}
}

func buildVerdict(
	exitCode uint32,
	wallElapsed time.Duration,
	metrics cgroupMetrics,
	cpuLimitMs int,
	memoryLimitMB int,
	outputLimitBytes int64,
	stdoutLW, stderrLW *limitedWriter,
) model.ExecuteResult {
	cpuMs := int(metrics.cpuNanos / 1e6)
	peakMemMB := int(metrics.peakMemBytes / 1024 / 1024)

	res := model.ExecuteResult{
		Stdout:     stdoutLW.String(),
		TimeUsed:   cpuMs,
		MemoryUsed: peakMemMB,
		ExitCode:   int(exitCode),
	}

	if cpuMs == 0 {
		res.TimeUsed = int(wallElapsed.Milliseconds())
	}

	// Detect MLE: kernel OOM kill, SIGKILL(137), or peak memory saturating
	// the cgroup limit.  The last case catches runtimes (JVM, Python) that
	// handle OOM internally and exit before the kernel kills them.
	memoryHitLimit := memoryLimitReached(metrics, memoryLimitMB)
	runtimeOOM := runtimeOOMDetected(stderrLW.String())

	// Priority: OLE > MLE > TLE > OK > RE
	switch {
	case stdoutLW.isOverflowed() || stderrLW.isOverflowed():
		res.Verdict = model.VerdictOLE
		res.ExtraInfo = fmt.Sprintf("output limit exceeded (%d bytes max)", outputLimitBytes)

	case metrics.oomKillDetected || exitCode == 137 || runtimeOOM || (exitCode != 0 && memoryHitLimit):
		res.Verdict = model.VerdictMLE
		res.ExtraInfo = fmt.Sprintf("memory limit exceeded (peak %dMB, limit %dMB)", peakMemMB, memoryLimitMB)

	case cpuMs > cpuLimitMs:
		res.Verdict = model.VerdictTLE
		res.ExtraInfo = fmt.Sprintf("CPU time exceeded: %dms > %dms", cpuMs, cpuLimitMs)

	case exitCode == 0:
		res.Verdict = model.VerdictOK

	default:
		res.Verdict = model.VerdictRE
		res.ExtraInfo = stderrLW.String()
	}
	return res
}

// ---------- helpers ----------

func (r *ContainerdRunner) ensureImage(ctx context.Context, client *containerd.Client) (containerd.Image, error) {
	image, err := client.GetImage(ctx, r.imageRef())
	if err == nil {
		return image, nil
	}
	if !errdefs.IsNotFound(err) {
		return nil, fmt.Errorf("get image %s: %w", r.imageRef(), err)
	}
	return client.Pull(ctx, r.imageRef(), containerd.WithPullUnpack)
}

func (r *ContainerdRunner) imageRef() string { return r.profile.ImageRef }

func infraErr(format string, args ...any) (model.ExecuteResult, error) {
	msg := fmt.Sprintf(format, args...)
	return model.ExecuteResult{
		Verdict:   model.VerdictUKE,
		ExitCode:  -1,
		ExtraInfo: msg,
	}, errors.New(msg)
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func clampInt(v, limit uint64) int {
	return int(min(v, limit))
}
