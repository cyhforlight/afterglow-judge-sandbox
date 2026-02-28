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

	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2/stats"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	typeurl "github.com/containerd/typeurl/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"afterglow-judge-sandbox/internal/model"
)

const (
	defaultSocketPath = "/run/containerd/containerd.sock"
	defaultNamespace  = "afterglow"
	cgroupV2CheckPath = "/sys/fs/cgroup/cgroup.controllers"
	bytesPerMiB       = int64(1024 * 1024)

	// Wall time is allowed to be this multiple of CPU time limit.
	// Accounts for I/O waits, scheduling latency, container overhead, etc.
	wallTimeMultiplier = 3

	// Max tasks (threads + processes) in the container.
	// 128 is plenty for JVM (~20 threads) while still blocking fork bombs.
	pidsLimit = 128

	// Safety cap for input file size to prevent host OOM from malicious inputs.
	maxInputSize = 256 * bytesPerMiB // 256 MB

	// Judge output is intentionally capped to a fixed, explicit budget.
	// It is independent from the process memory limit.
	defaultOutputLimitBytes = 16 * bytesPerMiB // 16 MB

	// Treat usage >= 99.5% of the limit as hitting memory limit.
	memoryHitThresholdPermille = 995

	maxInt64Value    = int64(1<<63 - 1)
	maxMemoryLimitMB = maxInt64Value / bytesPerMiB
	maxTimeLimitMs   = maxInt64Value / int64(time.Millisecond) / wallTimeMultiplier
)

// RunProfile describes how a specific language's program should be
// executed inside a container. All language differences are captured here
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

func defaultRunProfiles() map[model.Language]RunProfile {
	native := NativeRunProfile()
	return map[model.Language]RunProfile{
		model.LanguageC:      native,
		model.LanguageCPP:    native,
		model.LanguagePython: PythonRunProfile(),
		model.LanguageJava:   JavaRunProfile(),
	}
}

type ContainerdRunner struct {
	socketPath string
	namespace  string
	profiles   map[model.Language]RunProfile

	checkCgroupV2   func() error
	checkContainerd func(ctx context.Context, socketPath string) error
}

func NewContainerdRunner(socketPath string) *ContainerdRunner {
	return NewContainerdRunnerWithProfiles(socketPath, defaultRunProfiles())
}

func NewContainerdRunnerWithProfiles(socketPath string, profiles map[model.Language]RunProfile) *ContainerdRunner {
	if socketPath == "" {
		socketPath = defaultSocketPath
	}

	clonedProfiles := make(map[model.Language]RunProfile, len(profiles))
	for language, profile := range profiles {
		clonedProfiles[language] = profile
	}

	return &ContainerdRunner{
		socketPath:      socketPath,
		namespace:       defaultNamespace,
		profiles:        clonedProfiles,
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

func (r *ContainerdRunner) profileForLanguage(language model.Language) (RunProfile, error) {
	profile, ok := r.profiles[language]
	if ok {
		return profile, nil
	}
	return RunProfile{}, fmt.Errorf("no run profile registered for language %q", language)
}

func (r *ContainerdRunner) Execute(ctx context.Context, req model.ExecuteRequest) model.ExecuteResult {
	result, err := r.execute(ctx, req)
	if err != nil {
		return buildInfraFailureResult(err)
	}
	return result
}

func (r *ContainerdRunner) ensureImage(ctx context.Context, client *containerd.Client, imageRef string) (containerd.Image, error) {
	image, err := client.GetImage(ctx, imageRef)
	if err == nil {
		return image, nil
	}
	if !errdefs.IsNotFound(err) {
		return nil, fmt.Errorf("get image %q: %w", imageRef, err)
	}
	image, err = client.Pull(ctx, imageRef, containerd.WithPullUnpack)
	if err != nil {
		return nil, fmt.Errorf("pull image %q: %w", imageRef, err)
	}
	return image, nil
}

type executionPlan struct {
	profile          RunProfile
	limits           executionLimits
	outputLimitBytes int64
}

type runningExecution struct {
	execCtx          context.Context
	task             containerd.Task
	exitCh           <-chan containerd.ExitStatus
	stdoutLW         *limitedWriter
	stderrLW         *limitedWriter
	oleLimiter       *outputLimiter
	limits           executionLimits
	outputLimitBytes int64
}

func (r *ContainerdRunner) execute(ctx context.Context, req model.ExecuteRequest) (model.ExecuteResult, error) {
	plan, err := r.prepareExecutionPlan(req)
	if err != nil {
		return model.ExecuteResult{}, err
	}

	run, cleanup, err := r.setupExecution(ctx, req, plan)
	if err != nil {
		return model.ExecuteResult{}, err
	}
	defer cleanup()

	return r.watchExecution(run)
}

func (r *ContainerdRunner) prepareExecutionPlan(req model.ExecuteRequest) (executionPlan, error) {
	var plan executionPlan

	profile, err := r.profileForLanguage(req.Language)
	if err != nil {
		return plan, err
	}
	limits, err := validateExecuteRequest(req)
	if err != nil {
		return plan, fmt.Errorf("invalid execute request: %w", err)
	}

	plan.profile = profile
	plan.limits = limits
	plan.outputLimitBytes = defaultOutputLimitBytes
	return plan, nil
}

func (r *ContainerdRunner) setupExecution(
	ctx context.Context,
	req model.ExecuteRequest,
	plan executionPlan,
) (runningExecution, func(), error) {
	var run runningExecution
	cleanup := func() {}

	client, err := containerd.New(r.socketPath)
	if err != nil {
		return run, cleanup, fmt.Errorf("connect to containerd: %w", err)
	}

	execCtx := namespaces.WithNamespace(ctx, r.namespace)
	image, err := r.ensureImage(execCtx, client, plan.profile.ImageRef)
	if err != nil {
		_ = client.Close()
		return run, cleanup, fmt.Errorf("ensure image %q: %w", plan.profile.ImageRef, err)
	}

	tmpDir, err := os.MkdirTemp("", "sandbox-*")
	if err != nil {
		_ = client.Close()
		return run, cleanup, fmt.Errorf("create temp dir: %w", err)
	}
	programPath := filepath.Join(tmpDir, plan.profile.SandboxFile)
	if err := copyFile(req.ExecutablePath, programPath, plan.profile.FileMode); err != nil {
		_ = os.RemoveAll(tmpDir)
		_ = client.Close()
		return run, cleanup, fmt.Errorf("copy program file: %w", err)
	}

	inputFile, err := openInputFile(req.InputPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		_ = client.Close()
		return run, cleanup, err
	}

	containerID := fmt.Sprintf("sandbox-%d", time.Now().UnixNano())
	containerPath := "/sandbox/" + plan.profile.SandboxFile
	args := plan.profile.BuildArgs(containerPath)

	container, err := client.NewContainer(execCtx, containerID,
		containerd.WithImage(image),
		containerd.WithNewSnapshot(containerID+"-snap", image),
		containerd.WithNewSpec(
			oci.WithImageConfig(image),
			oci.WithProcessArgs(args...),
			oci.WithMounts([]specs.Mount{{
				Destination: "/sandbox",
				Type:        "bind",
				Source:      tmpDir,
				Options:     []string{"rbind", "ro"},
			}}),
			oci.WithMemoryLimit(uint64(plan.limits.memoryLimitBytes)),
			oci.WithMemorySwap(plan.limits.memoryLimitBytes),
			sandboxSecurityOpts(),
		),
	)
	if err != nil {
		_ = inputFile.Close()
		_ = os.RemoveAll(tmpDir)
		_ = client.Close()
		return run, cleanup, fmt.Errorf("create container: %w", err)
	}

	oleLimiter := newOutputLimiter(plan.outputLimitBytes)
	stdoutLW := newLimitedWriter(oleLimiter)
	stderrLW := newLimitedWriter(oleLimiter)

	task, err := container.NewTask(execCtx, cio.NewCreator(
		cio.WithStreams(inputFile, stdoutLW, stderrLW),
	))
	if err != nil {
		_ = container.Delete(execCtx, containerd.WithSnapshotCleanup)
		_ = inputFile.Close()
		_ = os.RemoveAll(tmpDir)
		_ = client.Close()
		return run, cleanup, fmt.Errorf("create task: %w", err)
	}

	exitCh, err := task.Wait(execCtx)
	if err != nil {
		_, _ = task.Delete(execCtx)
		_ = container.Delete(execCtx, containerd.WithSnapshotCleanup)
		_ = inputFile.Close()
		_ = os.RemoveAll(tmpDir)
		_ = client.Close()
		return run, cleanup, fmt.Errorf("setup wait: %w", err)
	}

	cleanup = func() {
		_, _ = task.Delete(execCtx)
		_ = container.Delete(execCtx, containerd.WithSnapshotCleanup)
		_ = inputFile.Close()
		_ = os.RemoveAll(tmpDir)
		_ = client.Close()
	}

	run = runningExecution{
		execCtx:          execCtx,
		task:             task,
		exitCh:           exitCh,
		stdoutLW:         stdoutLW,
		stderrLW:         stderrLW,
		oleLimiter:       oleLimiter,
		limits:           plan.limits,
		outputLimitBytes: plan.outputLimitBytes,
	}
	return run, cleanup, nil
}

func (r *ContainerdRunner) watchExecution(run runningExecution) (model.ExecuteResult, error) {
	startTime := time.Now()
	if err := run.task.Start(run.execCtx); err != nil {
		return model.ExecuteResult{}, fmt.Errorf("start task: %w", err)
	}
	_ = run.task.CloseIO(run.execCtx, containerd.WithStdinCloser)

	wallDeadline := time.NewTimer(time.Duration(run.limits.wallLimitMs) * time.Millisecond)
	defer wallDeadline.Stop()

	var forcedStopReason string
	select {
	case status := <-run.exitCh:
		wallElapsed := time.Since(startTime)
		code, _, err := status.Result()
		if err != nil {
			return model.ExecuteResult{}, fmt.Errorf("read task exit result: %w", err)
		}
		metrics := collectMetrics(run.execCtx, run.task)
		return buildVerdict(
			code,
			wallElapsed,
			metrics,
			run.limits.cpuLimitMs,
			run.limits.memoryLimitMB,
			run.outputLimitBytes,
			run.stdoutLW,
			run.stderrLW,
		), nil

	case <-run.oleLimiter.ch:
		forcedStopReason = "output limit exceeded"

	case <-wallDeadline.C:
		forcedStopReason = "wall time limit exceeded"
	}

	// The process is still running — collect stats, then kill.
	metrics := collectMetrics(run.execCtx, run.task)
	_ = run.task.Kill(run.execCtx, syscall.SIGKILL)
	<-run.exitCh

	return buildForcedStopVerdict(
		forcedStopReason,
		run.limits.wallLimitMs,
		run.limits.cpuLimitMs,
		run.limits.memoryLimitMB,
		run.outputLimitBytes,
		metrics,
		run.stdoutLW,
		run.stderrLW,
	), nil
}

// pickCPU randomly selects a CPU core for the container. Each sandbox
// is pinned to exactly one core (no multi-threading advantage), while
// randomization spreads concurrent sandboxes across available cores.
func pickCPU() string {
	cpuCount := runtime.NumCPU()
	if cpuCount <= 1 {
		return "0"
	}
	return strconv.Itoa(rand.IntN(cpuCount))
}

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

type executionLimits struct {
	cpuLimitMs       int
	wallLimitMs      int
	memoryLimitMB    int
	memoryLimitBytes int64
}

func validateExecuteRequest(req model.ExecuteRequest) (executionLimits, error) {
	var limits executionLimits

	if req.ExecutablePath == "" {
		return limits, errors.New("missing executable path")
	}
	if req.InputPath == "" {
		return limits, errors.New("missing input path")
	}
	if req.TimeLimit <= 0 {
		return limits, errors.New("time limit must be > 0")
	}
	if req.MemoryLimit <= 0 {
		return limits, errors.New("memory limit must be > 0")
	}
	if int64(req.TimeLimit) > maxTimeLimitMs {
		return limits, fmt.Errorf("time limit too large: %dms", req.TimeLimit)
	}
	if int64(req.MemoryLimit) > maxMemoryLimitMB {
		return limits, fmt.Errorf("memory limit too large: %dMB", req.MemoryLimit)
	}

	limits.cpuLimitMs = req.TimeLimit
	limits.wallLimitMs = req.TimeLimit * wallTimeMultiplier
	limits.memoryLimitMB = req.MemoryLimit
	limits.memoryLimitBytes = int64(req.MemoryLimit) * bytesPerMiB
	return limits, nil
}

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
	if err := typeurl.UnmarshalTo(data, &v2); err != nil {
		return m
	}

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
// outputLimiter pool. When the pool is exhausted, further writes are
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
		_, _ = w.buf.Write(p[:allowed])
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

func outputOverflowed(stdoutLW, stderrLW *limitedWriter) bool {
	return stdoutLW.isOverflowed() || stderrLW.isOverflowed()
}

func memoryLimitReached(metrics cgroupMetrics, memoryLimitMB int) bool {
	if metrics.memoryLimitHit {
		return true
	}
	if memoryLimitMB <= 0 {
		return false
	}

	limitBytes := uint64(memoryLimitMB) * uint64(bytesPerMiB)
	if limitBytes == 0 {
		return false
	}

	if metrics.peakMemBytes >= limitBytes {
		return true
	}
	return metrics.peakMemBytes*1000 >= limitBytes*memoryHitThresholdPermille
}

func runtimeOOMDetected(stderr string) bool {
	message := strings.ToLower(stderr)
	return strings.Contains(message, "outofmemory") ||
		strings.Contains(message, "out of memory") ||
		strings.Contains(message, "cannot allocate memory")
}

func outputLimitExceededText(outputLimitBytes int64) string {
	return fmt.Sprintf("output limit exceeded (%d bytes max)", outputLimitBytes)
}

func memoryLimitExceededText(peakMemMB, memoryLimitMB int) string {
	return fmt.Sprintf("memory limit exceeded (peak %dMB, limit %dMB)", peakMemMB, memoryLimitMB)
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
	peakMemMB := int(metrics.peakMemBytes / uint64(bytesPerMiB))

	if outputOverflowed(stdoutLW, stderrLW) {
		return model.ExecuteResult{
			Verdict:    model.VerdictOLE,
			TimeUsed:   cpuMs,
			MemoryUsed: peakMemMB,
			ExtraInfo:  outputLimitExceededText(outputLimitBytes),
		}
	}
	if metrics.oomKillDetected || memoryLimitReached(metrics, memoryLimitMB) {
		return model.ExecuteResult{
			Verdict:    model.VerdictMLE,
			TimeUsed:   cpuMs,
			MemoryUsed: peakMemMB,
			ExtraInfo:  memoryLimitExceededText(peakMemMB, memoryLimitMB),
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
	peakMemMB := int(metrics.peakMemBytes / uint64(bytesPerMiB))

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
	// the cgroup limit. The last case catches runtimes (JVM, Python) that
	// handle OOM internally and exit before the kernel kills them.
	memoryHitLimit := memoryLimitReached(metrics, memoryLimitMB)
	stderrText := stderrLW.String()
	runtimeOOM := runtimeOOMDetected(stderrText)

	// Priority: OLE > MLE > TLE > OK > RE
	switch {
	case outputOverflowed(stdoutLW, stderrLW):
		res.Verdict = model.VerdictOLE
		res.ExtraInfo = outputLimitExceededText(outputLimitBytes)

	case metrics.oomKillDetected || exitCode == 137 || runtimeOOM || (exitCode != 0 && memoryHitLimit):
		res.Verdict = model.VerdictMLE
		res.ExtraInfo = memoryLimitExceededText(peakMemMB, memoryLimitMB)

	case cpuMs > cpuLimitMs:
		res.Verdict = model.VerdictTLE
		res.ExtraInfo = fmt.Sprintf("CPU time exceeded: %dms > %dms", cpuMs, cpuLimitMs)

	case exitCode == 0:
		res.Verdict = model.VerdictOK

	default:
		res.Verdict = model.VerdictRE
		res.ExtraInfo = stderrText
	}
	return res
}

func openInputFile(path string) (*os.File, error) {
	inputFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}

	inputInfo, err := inputFile.Stat()
	if err != nil {
		_ = inputFile.Close()
		return nil, fmt.Errorf("stat input file: %w", err)
	}
	if inputInfo.IsDir() {
		_ = inputFile.Close()
		return nil, fmt.Errorf("input path points to a directory: %q", path)
	}
	if inputInfo.Size() > maxInputSize {
		_ = inputFile.Close()
		return nil, fmt.Errorf("input file too large: %d bytes (max %d)", inputInfo.Size(), maxInputSize)
	}
	return inputFile, nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open destination file %q: %w", dst, err)
	}

	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy file content: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close destination file %q: %w", dst, err)
	}
	return nil
}

func buildInfraFailureResult(err error) model.ExecuteResult {
	return model.ExecuteResult{
		Verdict:   model.VerdictUKE,
		ExitCode:  -1,
		ExtraInfo: err.Error(),
	}
}

func clampInt(v, limit uint64) int {
	return int(min(v, limit))
}
