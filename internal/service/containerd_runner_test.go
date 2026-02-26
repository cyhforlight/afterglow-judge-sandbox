package service

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"afterglow-judge-sandbox/internal/model"
)

// ============================================================
// limitedWriter
// ============================================================

func TestLimitedWriter_NormalWrite(t *testing.T) {
	lim := newOutputLimiter(100)
	w := newLimitedWriter(lim)

	n, err := w.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write: n=%d, err=%v", n, err)
	}
	if w.String() != "hello" {
		t.Fatalf("got %q, want %q", w.String(), "hello")
	}
	if w.isOverflowed() {
		t.Fatal("should not overflow")
	}
}

func TestLimitedWriter_ExactBoundary(t *testing.T) {
	lim := newOutputLimiter(5)
	w := newLimitedWriter(lim)

	w.Write([]byte("12345"))
	if w.isOverflowed() {
		t.Fatal("exact boundary should not overflow")
	}
	if w.String() != "12345" {
		t.Fatalf("got %q", w.String())
	}
}

func TestLimitedWriter_OverflowTruncates(t *testing.T) {
	lim := newOutputLimiter(5)
	w := newLimitedWriter(lim)

	n, err := w.Write([]byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 11 {
		t.Fatalf("Write should report full length consumed: got %d", n)
	}
	if w.String() != "hello" {
		t.Fatalf("got %q, want %q (truncated)", w.String(), "hello")
	}
	if !w.isOverflowed() {
		t.Fatal("should be overflowed")
	}
}

func TestLimitedWriter_OverflowSignalsLimiter(t *testing.T) {
	lim := newOutputLimiter(3)
	w := newLimitedWriter(lim)

	w.Write([]byte("abcdef"))

	select {
	case <-lim.ch:
	default:
		t.Fatal("limiter channel should be closed after overflow")
	}
}

func TestLimitedWriter_SubsequentWritesAfterOverflow(t *testing.T) {
	lim := newOutputLimiter(3)
	w := newLimitedWriter(lim)

	w.Write([]byte("abcdef"))
	w.Write([]byte("more data"))
	w.Write([]byte("even more"))

	if w.String() != "abc" {
		t.Fatalf("got %q, want %q", w.String(), "abc")
	}
}

func TestLimitedWriter_MultipleWritesTriggerOverflow(t *testing.T) {
	lim := newOutputLimiter(10)
	w := newLimitedWriter(lim)

	w.Write([]byte("12345"))
	if w.isOverflowed() {
		t.Fatal("should not overflow yet")
	}
	w.Write([]byte("678"))
	if w.isOverflowed() {
		t.Fatal("still within limit (8 <= 10)")
	}
	w.Write([]byte("90AB"))
	if !w.isOverflowed() {
		t.Fatal("should overflow (12 > 10)")
	}
	if w.String() != "1234567890" {
		t.Fatalf("got %q", w.String())
	}
}

func TestLimitedWriter_ConcurrentWrites(t *testing.T) {
	lim := newOutputLimiter(1000)
	w := newLimitedWriter(lim)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.Write([]byte("0123456789"))
		}()
	}
	wg.Wait()

	if w.isOverflowed() {
		t.Fatal("1000 bytes of writes into 1000-byte limit should not overflow")
	}
	if len(w.String()) != 1000 {
		t.Fatalf("expected 1000 bytes, got %d", len(w.String()))
	}
}

// ============================================================
// shared output budget (stdout + stderr draw from the same pool)
// ============================================================

func TestSharedOutputBudget_SplitAcrossWriters(t *testing.T) {
	lim := newOutputLimiter(10)
	stdout := newLimitedWriter(lim)
	stderr := newLimitedWriter(lim)

	stdout.Write([]byte("12345")) // 5 bytes
	stderr.Write([]byte("67890")) // 5 bytes, total 10 = exactly at limit

	if stdout.isOverflowed() || stderr.isOverflowed() {
		t.Fatal("exactly at limit should not overflow")
	}

	stderr.Write([]byte("X")) // 1 more byte pushes over
	if !stderr.isOverflowed() {
		t.Fatal("should overflow after exceeding shared budget")
	}
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

	stdout.Write([]byte("12345678")) // exactly 8, exhausts pool

	// stderr's first write gets 0 bytes → overflow
	stderr.Write([]byte("a"))
	if !stderr.isOverflowed() {
		t.Fatal("stderr should overflow when budget already exhausted")
	}
	if stderr.String() != "" {
		t.Fatalf("stderr buf should be empty, got %q", stderr.String())
	}
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

func makeLimitedWriters(limit int64) (*outputLimiter, *limitedWriter, *limitedWriter) {
	lim := newOutputLimiter(limit)
	return lim, newLimitedWriter(lim), newLimitedWriter(lim)
}

func TestBuildVerdict_OK(t *testing.T) {
	_, stdout, stderr := makeLimitedWriters(1024)
	stdout.Write([]byte("42\n"))

	res := buildVerdict(0, 50*time.Millisecond, cgroupMetrics{
		cpuNanos:     30_000_000,
		peakMemBytes: 4 * 1024 * 1024,
	}, 1000, 256, 1024, stdout, stderr)

	if res.Verdict != model.VerdictOK {
		t.Fatalf("verdict: got %v, want OK", res.Verdict)
	}
	if res.Stdout != "42\n" {
		t.Fatalf("stdout: got %q", res.Stdout)
	}
	if res.TimeUsed != 30 {
		t.Fatalf("timeUsed: got %d, want 30", res.TimeUsed)
	}
	if res.MemoryUsed != 4 {
		t.Fatalf("memoryUsed: got %d, want 4", res.MemoryUsed)
	}
}

func TestBuildVerdict_RE(t *testing.T) {
	_, stdout, stderr := makeLimitedWriters(1024)
	stderr.Write([]byte("segfault"))

	res := buildVerdict(139, 10*time.Millisecond, cgroupMetrics{
		cpuNanos:     5_000_000,
		peakMemBytes: 2 * 1024 * 1024,
	}, 1000, 256, 1024, stdout, stderr)

	if res.Verdict != model.VerdictRE {
		t.Fatalf("verdict: got %v, want RE", res.Verdict)
	}
	if res.ExitCode != 139 {
		t.Fatalf("exitCode: got %d, want 139", res.ExitCode)
	}
	if !strings.Contains(res.ExtraInfo, "segfault") {
		t.Fatalf("extraInfo should contain stderr: got %q", res.ExtraInfo)
	}
}

func TestBuildVerdict_MLE_OOMKill(t *testing.T) {
	_, stdout, stderr := makeLimitedWriters(1024)

	res := buildVerdict(137, 500*time.Millisecond, cgroupMetrics{
		cpuNanos:        400_000_000,
		peakMemBytes:    64 * 1024 * 1024,
		oomKillDetected: true,
	}, 2000, 64, 1024, stdout, stderr)

	if res.Verdict != model.VerdictMLE {
		t.Fatalf("verdict: got %v, want MLE", res.Verdict)
	}
}

func TestBuildVerdict_MLE_RuntimeOOM(t *testing.T) {
	_, stdout, stderr := makeLimitedWriters(1024)
	stderr.Write([]byte("OutOfMemoryError"))

	res := buildVerdict(1, 2*time.Second, cgroupMetrics{
		cpuNanos:     1_500_000_000,
		peakMemBytes: 256 * 1024 * 1024,
	}, 5000, 256, 1024, stdout, stderr)

	if res.Verdict != model.VerdictMLE {
		t.Fatalf("verdict: got %v, want MLE (runtime OOM with peak at limit)", res.Verdict)
	}
}

func TestBuildVerdict_MLE_NotTriggeredOnNormalExit(t *testing.T) {
	_, stdout, stderr := makeLimitedWriters(1024)
	stdout.Write([]byte("ok\n"))

	res := buildVerdict(0, 100*time.Millisecond, cgroupMetrics{
		cpuNanos:     50_000_000,
		peakMemBytes: 256 * 1024 * 1024,
	}, 2000, 256, 1024, stdout, stderr)

	if res.Verdict != model.VerdictOK {
		t.Fatalf("verdict: got %v, want OK (exit 0 even if memory at limit)", res.Verdict)
	}
}

func TestBuildVerdict_TLE(t *testing.T) {
	_, stdout, stderr := makeLimitedWriters(1024)

	res := buildVerdict(0, 3*time.Second, cgroupMetrics{
		cpuNanos:     2_500_000_000,
		peakMemBytes: 10 * 1024 * 1024,
	}, 2000, 256, 1024, stdout, stderr)

	if res.Verdict != model.VerdictTLE {
		t.Fatalf("verdict: got %v, want TLE", res.Verdict)
	}
}

func TestBuildVerdict_OLE(t *testing.T) {
	_, stdout, stderr := makeLimitedWriters(10)
	stdout.Write([]byte("this is way too much output"))

	res := buildVerdict(0, 100*time.Millisecond, cgroupMetrics{
		cpuNanos:     30_000_000,
		peakMemBytes: 4 * 1024 * 1024,
	}, 2000, 256, 10, stdout, stderr)

	if res.Verdict != model.VerdictOLE {
		t.Fatalf("verdict: got %v, want OLE", res.Verdict)
	}
}

func TestBuildVerdict_Priority_OLE_Over_MLE(t *testing.T) {
	_, stdout, stderr := makeLimitedWriters(5)
	stdout.Write([]byte("too much"))

	res := buildVerdict(137, 500*time.Millisecond, cgroupMetrics{
		cpuNanos:        400_000_000,
		peakMemBytes:    64 * 1024 * 1024,
		oomKillDetected: true,
	}, 2000, 64, 5, stdout, stderr)

	if res.Verdict != model.VerdictOLE {
		t.Fatalf("verdict: got %v, want OLE (priority over MLE)", res.Verdict)
	}
}

func TestBuildVerdict_FallbackToWallTime(t *testing.T) {
	_, stdout, stderr := makeLimitedWriters(1024)

	res := buildVerdict(0, 42*time.Millisecond, cgroupMetrics{
		cpuNanos:     0,
		peakMemBytes: 2 * 1024 * 1024,
	}, 2000, 256, 1024, stdout, stderr)

	if res.TimeUsed != 42 {
		t.Fatalf("timeUsed: got %d, want 42 (wall time fallback)", res.TimeUsed)
	}
}

// ============================================================
// clampInt
// ============================================================

func TestClampInt(t *testing.T) {
	if clampInt(500, 1000) != 500 {
		t.Fatal("below max")
	}
	if clampInt(1000, 1000) != 1000 {
		t.Fatal("at max")
	}
	if clampInt(2000, 1000) != 1000 {
		t.Fatal("above max")
	}
	if clampInt(0, 1000) != 0 {
		t.Fatal("zero")
	}
}

// ============================================================
// RunProfile
// ============================================================

func TestRunProfiles(t *testing.T) {
	tests := []struct {
		name        string
		profile     RunProfile
		wantFile    string
		wantArgSub  string
	}{
		{"native", NativeRunProfile(), "program", "/sandbox/program"},
		{"python", PythonRunProfile(), "solution.py", "python3"},
		{"java", JavaRunProfile(), "solution.jar", "java"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.profile.SandboxFile != tt.wantFile {
				t.Fatalf("SandboxFile: got %q, want %q", tt.profile.SandboxFile, tt.wantFile)
			}
			if tt.profile.ImageRef == "" {
				t.Fatal("ImageRef is empty")
			}
			args := tt.profile.BuildArgs("/sandbox/" + tt.profile.SandboxFile)
			if len(args) == 0 {
				t.Fatal("BuildArgs returned empty")
			}
			found := false
			for _, a := range args {
				if strings.Contains(a, tt.wantArgSub) {
					found = true
				}
			}
			if !found {
				t.Fatalf("args %v should contain %q", args, tt.wantArgSub)
			}
		})
	}
}

// ============================================================
// DispatchRunner
// ============================================================

func TestDispatchRunner_UnknownLanguage(t *testing.T) {
	d := &DispatchRunner{runners: map[model.Language]Runner{}}
	_, err := d.Execute(context.Background(), model.ExecuteRequest{Language: model.LanguageUnknown})
	if err == nil {
		t.Fatal("expected error for unknown language")
	}
}
