package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2/stats"
	typeurl "github.com/containerd/typeurl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"afterglow-judge-sandbox/internal/model"
)

// ============================================================
// limitedWriter
// ============================================================

func TestLimitedWriter_NormalWrite(t *testing.T) {
	lim := newOutputLimiter(100)
	w := newLimitedWriter(lim)

	n, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", w.String())
	assert.False(t, w.isOverflowed())
}

func TestLimitedWriter_ExactBoundary(t *testing.T) {
	lim := newOutputLimiter(5)
	w := newLimitedWriter(lim)

	_, _ = w.Write([]byte("12345"))
	assert.False(t, w.isOverflowed(), "exact boundary should not overflow")
	assert.Equal(t, "12345", w.String())
}

func TestLimitedWriter_OverflowTruncates(t *testing.T) {
	lim := newOutputLimiter(5)
	w := newLimitedWriter(lim)

	n, err := w.Write([]byte("hello world"))
	require.NoError(t, err)
	assert.Equal(t, 11, n, "Write should report full length consumed")
	assert.Equal(t, "hello", w.String(), "should be truncated")
	assert.True(t, w.isOverflowed())
}

func TestLimitedWriter_OverflowSignalsLimiter(t *testing.T) {
	lim := newOutputLimiter(3)
	w := newLimitedWriter(lim)

	_, _ = w.Write([]byte("abcdef"))

	select {
	case <-lim.ch:
	default:
		t.Fatal("limiter channel should be closed after overflow")
	}
}

func TestLimitedWriter_SubsequentWritesAfterOverflow(t *testing.T) {
	lim := newOutputLimiter(3)
	w := newLimitedWriter(lim)

	_, _ = w.Write([]byte("abcdef"))
	_, _ = w.Write([]byte("more data"))
	_, _ = w.Write([]byte("even more"))

	assert.Equal(t, "abc", w.String())
}

func TestLimitedWriter_MultipleWritesTriggerOverflow(t *testing.T) {
	lim := newOutputLimiter(10)
	w := newLimitedWriter(lim)

	_, _ = w.Write([]byte("12345"))
	assert.False(t, w.isOverflowed(), "should not overflow yet")

	_, _ = w.Write([]byte("678"))
	assert.False(t, w.isOverflowed(), "still within limit (8 <= 10)")

	_, _ = w.Write([]byte("90AB"))
	assert.True(t, w.isOverflowed(), "should overflow (12 > 10)")
	assert.Equal(t, "1234567890", w.String())
}

func TestLimitedWriter_ConcurrentWrites(t *testing.T) {
	lim := newOutputLimiter(1000)
	w := newLimitedWriter(lim)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = w.Write([]byte("0123456789"))
		}()
	}
	wg.Wait()

	assert.False(t, w.isOverflowed(), "1000 bytes into 1000-byte limit should not overflow")
	assert.Len(t, w.String(), 1000)
}

// ============================================================
// shared output budget (stdout + stderr draw from the same pool)
// ============================================================

func TestSharedOutputBudget_SplitAcrossWriters(t *testing.T) {
	lim := newOutputLimiter(10)
	stdout := newLimitedWriter(lim)
	stderr := newLimitedWriter(lim)

	_, _ = stdout.Write([]byte("12345"))
	_, _ = stderr.Write([]byte("67890"))

	assert.False(t, stdout.isOverflowed(), "exactly at limit should not overflow")
	assert.False(t, stderr.isOverflowed(), "exactly at limit should not overflow")

	_, _ = stderr.Write([]byte("X"))
	assert.True(t, stderr.isOverflowed(), "should overflow after exceeding shared budget")

	select {
	case <-lim.ch:
	default:
		t.Fatal("limiter channel should be closed")
	}
}

func TestSharedOutputBudget_FirstWriterExhaustsBudget(t *testing.T) {
	lim := newOutputLimiter(8)
	stdout := newLimitedWriter(lim)
	stderr := newLimitedWriter(lim)

	_, _ = stdout.Write([]byte("12345678"))

	_, _ = stderr.Write([]byte("a"))
	assert.True(t, stderr.isOverflowed(), "stderr should overflow when budget already exhausted")
	assert.Empty(t, stderr.String(), "stderr buf should be empty")
}

// ============================================================
// outputLimiter
// ============================================================

func TestOutputLimiter_SignalIsIdempotent(t *testing.T) {
	lim := newOutputLimiter(100)
	lim.signal()
	lim.signal()
	lim.signal()

	select {
	case <-lim.ch:
	default:
		t.Fatal("channel should be closed")
	}
}

// ============================================================
// buildVerdict
// ============================================================

func makeLimitedWriters(limit int64) (*limitedWriter, *limitedWriter) {
	lim := newOutputLimiter(limit)
	return newLimitedWriter(lim), newLimitedWriter(lim)
}

func TestBuildVerdict_OK(t *testing.T) {
	stdout, stderr := makeLimitedWriters(1024)
	_, _ = stdout.Write([]byte("42\n"))

	res := buildVerdict(0, 50*time.Millisecond, cgroupMetrics{
		cpuNanos:     30_000_000,
		peakMemBytes: 4 * 1024 * 1024,
	}, 1000, 256, 1024, stdout, stderr)

	assert.Equal(t, model.VerdictOK, res.Verdict)
	assert.Equal(t, "42\n", res.Stdout)
	assert.Equal(t, 30, res.TimeUsed)
	assert.Equal(t, 4, res.MemoryUsed)
}

func TestBuildVerdict_RE(t *testing.T) {
	stdout, stderr := makeLimitedWriters(1024)
	_, _ = stderr.Write([]byte("segfault"))

	res := buildVerdict(139, 10*time.Millisecond, cgroupMetrics{
		cpuNanos:     5_000_000,
		peakMemBytes: 2 * 1024 * 1024,
	}, 1000, 256, 1024, stdout, stderr)

	assert.Equal(t, model.VerdictRE, res.Verdict)
	assert.Equal(t, 139, res.ExitCode)
	assert.Contains(t, res.ExtraInfo, "segfault")
}

func TestBuildVerdict_MLE_OOMKill(t *testing.T) {
	stdout, stderr := makeLimitedWriters(1024)

	res := buildVerdict(137, 500*time.Millisecond, cgroupMetrics{
		cpuNanos:        400_000_000,
		peakMemBytes:    64 * 1024 * 1024,
		oomKillDetected: true,
	}, 2000, 64, 1024, stdout, stderr)

	assert.Equal(t, model.VerdictMLE, res.Verdict)
}

func TestBuildVerdict_MLE_RuntimeOOM(t *testing.T) {
	stdout, stderr := makeLimitedWriters(1024)
	_, _ = stderr.Write([]byte("OutOfMemoryError"))

	res := buildVerdict(1, 2*time.Second, cgroupMetrics{
		cpuNanos:     1_500_000_000,
		peakMemBytes: 256 * 1024 * 1024,
	}, 5000, 256, 1024, stdout, stderr)

	assert.Equal(t, model.VerdictMLE, res.Verdict, "runtime OOM with peak at limit")
}

func TestBuildVerdict_MLE_NotTriggeredOnNormalExit(t *testing.T) {
	stdout, stderr := makeLimitedWriters(1024)
	_, _ = stdout.Write([]byte("ok\n"))

	res := buildVerdict(0, 100*time.Millisecond, cgroupMetrics{
		cpuNanos:     50_000_000,
		peakMemBytes: 256 * 1024 * 1024,
	}, 2000, 256, 1024, stdout, stderr)

	assert.Equal(t, model.VerdictOK, res.Verdict, "exit 0 even if memory at limit")
}

func TestBuildVerdict_TLE(t *testing.T) {
	stdout, stderr := makeLimitedWriters(1024)

	res := buildVerdict(0, 3*time.Second, cgroupMetrics{
		cpuNanos:     2_500_000_000,
		peakMemBytes: 10 * 1024 * 1024,
	}, 2000, 256, 1024, stdout, stderr)

	assert.Equal(t, model.VerdictTLE, res.Verdict)
}

func TestBuildVerdict_OLE(t *testing.T) {
	stdout, stderr := makeLimitedWriters(10)
	_, _ = stdout.Write([]byte("this is way too much output"))

	res := buildVerdict(0, 100*time.Millisecond, cgroupMetrics{
		cpuNanos:     30_000_000,
		peakMemBytes: 4 * 1024 * 1024,
	}, 2000, 256, 10, stdout, stderr)

	assert.Equal(t, model.VerdictOLE, res.Verdict)
}

func TestBuildVerdict_Priority_OLE_Over_MLE(t *testing.T) {
	stdout, stderr := makeLimitedWriters(5)
	_, _ = stdout.Write([]byte("too much"))

	res := buildVerdict(137, 500*time.Millisecond, cgroupMetrics{
		cpuNanos:        400_000_000,
		peakMemBytes:    64 * 1024 * 1024,
		oomKillDetected: true,
	}, 2000, 64, 5, stdout, stderr)

	assert.Equal(t, model.VerdictOLE, res.Verdict, "OLE should take priority over MLE")
}

func TestBuildVerdict_FallbackToWallTime(t *testing.T) {
	stdout, stderr := makeLimitedWriters(1024)

	res := buildVerdict(0, 42*time.Millisecond, cgroupMetrics{
		cpuNanos:     0,
		peakMemBytes: 2 * 1024 * 1024,
	}, 2000, 256, 1024, stdout, stderr)

	assert.Equal(t, 42, res.TimeUsed, "should fall back to wall time")
}

// ============================================================
// buildForcedStopVerdict
// ============================================================

func TestBuildForcedStopVerdict_MLEWhenMemoryLimitHit(t *testing.T) {
	stdout, stderr := makeLimitedWriters(1024)
	res := buildForcedStopVerdict(
		"wall time limit exceeded",
		9000,
		3000,
		128,
		1024,
		cgroupMetrics{
			cpuNanos:       2_000_000_000,
			peakMemBytes:   134_213_632, // ~128MB minus a few pages.
			memoryLimitHit: true,
		},
		stdout,
		stderr,
	)

	assert.Equal(t, model.VerdictMLE, res.Verdict)
	assert.GreaterOrEqual(t, res.MemoryUsed, 127)
}

func TestBuildForcedStopVerdict_TLEWhenMemoryNotHit(t *testing.T) {
	stdout, stderr := makeLimitedWriters(1024)
	res := buildForcedStopVerdict(
		"wall time limit exceeded",
		9000,
		3000,
		256,
		1024,
		cgroupMetrics{
			cpuNanos:     2_000_000_000,
			peakMemBytes: 32 * 1024 * 1024,
		},
		stdout,
		stderr,
	)

	assert.Equal(t, model.VerdictTLE, res.Verdict)
}

func TestMemoryLimitReached(t *testing.T) {
	tests := []struct {
		name     string
		metrics  cgroupMetrics
		limitMB  int
		expected bool
	}{
		{
			name: "memory events reported limit hit",
			metrics: cgroupMetrics{
				memoryLimitHit: true,
			},
			limitMB:  128,
			expected: true,
		},
		{
			name: "usage above threshold",
			metrics: cgroupMetrics{
				peakMemBytes: 134_213_632,
			},
			limitMB:  128,
			expected: true,
		},
		{
			name: "usage clearly below threshold",
			metrics: cgroupMetrics{
				peakMemBytes: 64 * 1024 * 1024,
			},
			limitMB:  128,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, memoryLimitReached(tt.metrics, tt.limitMB))
		})
	}
}

func TestRuntimeOOMDetected(t *testing.T) {
	tests := []struct {
		name     string
		stderr   string
		expected bool
	}{
		{
			name:     "java out of memory",
			stderr:   "java.lang.OutOfMemoryError: Java heap space",
			expected: true,
		},
		{
			name:     "glibc allocation failure",
			stderr:   "Cannot allocate memory",
			expected: true,
		},
		{
			name:     "normal runtime error",
			stderr:   "segmentation fault",
			expected: false,
		},
		{
			name:     "plain out of memory text",
			stderr:   "fatal: out of memory while allocating",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, runtimeOOMDetected(tt.stderr))
		})
	}
}

// ============================================================
// request validation + input checks
// ============================================================

func TestValidateExecuteRequest(t *testing.T) {
	validReq := model.ExecuteRequest{
		ExecutablePath: "/tmp/program",
		InputPath:      "/tmp/input.txt",
		TimeLimit:      1000,
		MemoryLimit:    256,
	}

	limits, err := validateExecuteRequest(validReq)
	require.NoError(t, err)
	assert.Equal(t, validReq.TimeLimit, limits.cpuLimitMs)
	assert.Equal(t, validReq.TimeLimit*wallTimeMultiplier, limits.wallLimitMs)
	assert.Equal(t, validReq.MemoryLimit, limits.memoryLimitMB)
	assert.Equal(t, int64(validReq.MemoryLimit)*bytesPerMiB, limits.memoryLimitBytes)

	tests := []struct {
		name    string
		req     model.ExecuteRequest
		wantErr string
	}{
		{
			name: "missing executable path",
			req: model.ExecuteRequest{
				InputPath:   "/tmp/input.txt",
				TimeLimit:   1000,
				MemoryLimit: 256,
			},
			wantErr: "missing executable path",
		},
		{
			name: "missing input path",
			req: model.ExecuteRequest{
				ExecutablePath: "/tmp/program",
				TimeLimit:      1000,
				MemoryLimit:    256,
			},
			wantErr: "missing input path",
		},
		{
			name: "non-positive time limit",
			req: model.ExecuteRequest{
				ExecutablePath: "/tmp/program",
				InputPath:      "/tmp/input.txt",
				TimeLimit:      0,
				MemoryLimit:    256,
			},
			wantErr: "time limit must be > 0",
		},
		{
			name: "non-positive memory limit",
			req: model.ExecuteRequest{
				ExecutablePath: "/tmp/program",
				InputPath:      "/tmp/input.txt",
				TimeLimit:      1000,
				MemoryLimit:    0,
			},
			wantErr: "memory limit must be > 0",
		},
	}

	maxIntValue := int(^uint(0) >> 1)
	if int64(maxIntValue) > maxTimeLimitMs {
		tests = append(tests, struct {
			name    string
			req     model.ExecuteRequest
			wantErr string
		}{
			name: "time limit too large",
			req: model.ExecuteRequest{
				ExecutablePath: "/tmp/program",
				InputPath:      "/tmp/input.txt",
				TimeLimit:      maxIntValue,
				MemoryLimit:    256,
			},
			wantErr: "time limit too large",
		})
	}
	if int64(maxIntValue) > maxMemoryLimitMB {
		tests = append(tests, struct {
			name    string
			req     model.ExecuteRequest
			wantErr string
		}{
			name: "memory limit too large",
			req: model.ExecuteRequest{
				ExecutablePath: "/tmp/program",
				InputPath:      "/tmp/input.txt",
				TimeLimit:      1000,
				MemoryLimit:    maxIntValue,
			},
			wantErr: "memory limit too large",
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateExecuteRequest(tt.req)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestOpenInputFile(t *testing.T) {
	tempDir := t.TempDir()

	okPath := filepath.Join(tempDir, "ok.in")
	require.NoError(t, os.WriteFile(okPath, []byte("42\n"), 0o644))

	okFile, err := openInputFile(okPath)
	require.NoError(t, err)
	require.NoError(t, okFile.Close())

	_, err = openInputFile(tempDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directory")

	tooLargePath := filepath.Join(tempDir, "large.in")
	tooLargeFile, err := os.Create(tooLargePath)
	require.NoError(t, err)
	require.NoError(t, tooLargeFile.Truncate(maxInputSize+1))
	require.NoError(t, tooLargeFile.Close())

	_, err = openInputFile(tooLargePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

// ============================================================
// parseCgroupMetrics
// ============================================================

func TestParseCgroupMetrics_V2(t *testing.T) {
	metricAny, err := typeurl.MarshalAny(&cgroupsv2.Metrics{
		CPU: &cgroupsv2.CPUStat{
			UsageUsec: 1234,
		},
		Memory: &cgroupsv2.MemoryStat{
			Usage:    100,
			MaxUsage: 200,
		},
		MemoryEvents: &cgroupsv2.MemoryEvents{
			Max:     2,
			OomKill: 1,
		},
	})
	require.NoError(t, err)

	got := parseCgroupMetrics(metricAny)
	assert.Equal(t, uint64(1_234_000), got.cpuNanos)
	assert.Equal(t, uint64(200), got.peakMemBytes)
	assert.True(t, got.memoryLimitHit)
	assert.True(t, got.oomKillDetected)
}

func TestParseCgroupMetrics_NonMetricsPayload(t *testing.T) {
	metricAny, err := typeurl.MarshalAny(&cgroupsv2.CPUStat{
		UsageUsec: 5678,
	})
	require.NoError(t, err)

	got := parseCgroupMetrics(metricAny)
	assert.Equal(t, cgroupMetrics{}, got)
}

// ============================================================
// RunProfile
// ============================================================

func TestRunProfiles(t *testing.T) {
	tests := []struct {
		name       string
		profile    RunProfile
		wantFile   string
		wantArgSub string
	}{
		{"native", NativeRunProfile(), "program", "/sandbox/program"},
		{"python", PythonRunProfile(), "solution.py", "python3"},
		{"java", JavaRunProfile(), "solution.jar", "java"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantFile, tt.profile.SandboxFile)
			assert.NotEmpty(t, tt.profile.ImageRef)

			args := tt.profile.BuildArgs("/sandbox/" + tt.profile.SandboxFile)
			require.NotEmpty(t, args, "BuildArgs returned empty")
			assert.True(t,
				slices.ContainsFunc(args, func(a string) bool {
					return strings.Contains(a, tt.wantArgSub)
				}),
				"args %v should contain %q", args, tt.wantArgSub,
			)
		})
	}
}

// ============================================================
// ContainerdRunner: routing + preflight
// ============================================================

func TestContainerdRunner_PrepareExecutionPlan(t *testing.T) {
	runner := NewContainerdRunnerWithProfiles("unix:///run/containerd/containerd.sock", defaultRunProfiles())
	req := model.ExecuteRequest{
		ExecutablePath: "/tmp/program",
		InputPath:      "/tmp/input.txt",
		Language:       model.LanguageCPP,
		TimeLimit:      1000,
		MemoryLimit:    512,
	}

	plan, err := runner.prepareExecutionPlan(req)
	require.NoError(t, err)
	assert.Equal(t, req.TimeLimit, plan.limits.cpuLimitMs)
	assert.Equal(t, req.TimeLimit*wallTimeMultiplier, plan.limits.wallLimitMs)
	assert.Equal(t, int64(req.MemoryLimit)*bytesPerMiB, plan.limits.memoryLimitBytes)
	assert.Equal(t, defaultOutputLimitBytes, plan.outputLimitBytes)
	assert.NotEqual(t, plan.limits.memoryLimitBytes, plan.outputLimitBytes)
}

func TestContainerdRunner_Execute_UnknownLanguage(t *testing.T) {
	runner := NewContainerdRunnerWithProfiles("unix:///run/containerd/containerd.sock", map[model.Language]RunProfile{})
	result := runner.Execute(context.Background(), model.ExecuteRequest{
		Language: model.LanguageUnknown,
	})
	assert.Equal(t, model.VerdictUKE, result.Verdict)
	assert.Equal(t, -1, result.ExitCode)
	assert.Contains(t, result.ExtraInfo, "no run profile registered")
}

func TestContainerdRunner_PreflightCheck(t *testing.T) {
	tests := []struct {
		name                    string
		cgroupErr               error
		containerdErr           error
		wantErr                 string
		wantContainerdCheckCall bool
	}{
		{
			name:                    "cgroup check failed",
			cgroupErr:               errors.New("no cgroup v2"),
			wantErr:                 "no cgroup v2",
			wantContainerdCheckCall: false,
		},
		{
			name:                    "containerd check failed",
			containerdErr:           errors.New("socket denied"),
			wantErr:                 "socket denied",
			wantContainerdCheckCall: true,
		},
		{
			name:                    "all checks passed",
			wantErr:                 "",
			wantContainerdCheckCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := NewContainerdRunner("unix:///run/containerd/containerd.sock")
			runner.checkCgroupV2 = func() error {
				return tt.cgroupErr
			}

			containerdCheckCalled := false
			runner.checkContainerd = func(_ context.Context, _ string) error {
				containerdCheckCalled = true
				return tt.containerdErr
			}

			err := runner.PreflightCheck(context.Background())
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
			assert.Equal(t, tt.wantContainerdCheckCall, containerdCheckCalled)
		})
	}
}
