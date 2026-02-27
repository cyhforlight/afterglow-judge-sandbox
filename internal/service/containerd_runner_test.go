package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cgroupsv1 "github.com/containerd/cgroups/v3/cgroup1/stats"
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

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, memoryLimitReached(testCase.metrics, testCase.limitMB))
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
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, runtimeOOMDetected(testCase.stderr))
		})
	}
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

func TestParseCgroupMetrics_V1Fallback(t *testing.T) {
	metricAny, err := typeurl.MarshalAny(&cgroupsv1.Metrics{
		CPU: &cgroupsv1.CPUStat{
			Usage: &cgroupsv1.CPUUsage{
				Total: 5678,
			},
		},
		Memory: &cgroupsv1.MemoryStat{
			Usage: &cgroupsv1.MemoryEntry{
				Usage:   100,
				Max:     300,
				Failcnt: 5,
			},
		},
		MemoryOomControl: &cgroupsv1.MemoryOomControl{
			OomKill: 1,
		},
	})
	require.NoError(t, err)

	got := parseCgroupMetrics(metricAny)
	assert.Equal(t, uint64(5678), got.cpuNanos)
	assert.Equal(t, uint64(300), got.peakMemBytes)
	assert.True(t, got.memoryLimitHit)
	assert.True(t, got.oomKillDetected)
}

// ============================================================
// clampInt
// ============================================================

func TestClampInt(t *testing.T) {
	tests := []struct {
		name     string
		v, limit uint64
		want     int
	}{
		{"below limit", 500, 1000, 500},
		{"at limit", 1000, 1000, 1000},
		{"above limit", 2000, 1000, 1000},
		{"zero", 0, 1000, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, clampInt(tt.v, tt.limit))
		})
	}
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
// DispatchRunner
// ============================================================

func TestDispatchRunner_UnknownLanguage(t *testing.T) {
	d := &DispatchRunner{runners: map[model.Language]Runner{}}
	_, err := d.Execute(context.Background(), model.ExecuteRequest{Language: model.LanguageUnknown})
	assert.Error(t, err)
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

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			runner := NewContainerdRunner("unix:///run/containerd/containerd.sock", NativeRunProfile())
			runner.checkCgroupV2 = func() error {
				return testCase.cgroupErr
			}

			containerdCheckCalled := false
			runner.checkContainerd = func(_ context.Context, _ string) error {
				containerdCheckCalled = true
				return testCase.containerdErr
			}

			err := runner.PreflightCheck(context.Background())
			if testCase.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.wantErr)
			}
			assert.Equal(t, testCase.wantContainerdCheckCall, containerdCheckCalled)
		})
	}
}

type preflightStubRunner struct {
	executeErr   error
	preflightErr error
	called       bool
}

func (r *preflightStubRunner) Execute(_ context.Context, _ model.ExecuteRequest) (model.ExecuteResult, error) {
	return model.ExecuteResult{}, r.executeErr
}

func (r *preflightStubRunner) PreflightCheck(_ context.Context) error {
	r.called = true
	return r.preflightErr
}

func TestDispatchRunner_PreflightCheck(t *testing.T) {
	tests := []struct {
		name         string
		preflightErr error
		wantErr      string
	}{
		{
			name:         "propagate preflight error",
			preflightErr: errors.New("containerd denied"),
			wantErr:      "containerd denied",
		},
		{
			name:         "preflight passed",
			preflightErr: nil,
			wantErr:      "",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			stub := &preflightStubRunner{
				preflightErr: testCase.preflightErr,
			}
			dispatch := &DispatchRunner{
				runners: map[model.Language]Runner{
					model.LanguageCPP: stub,
				},
			}

			err := dispatch.PreflightCheck(context.Background())
			if testCase.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.wantErr)
			}
			assert.True(t, stub.called)
		})
	}
}
