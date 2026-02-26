package app

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/service"
)

type fakeRunner struct {
	gotReq model.ExecuteRequest
	result model.ExecuteResult
	err    error
}

func (f *fakeRunner) Execute(_ context.Context, req model.ExecuteRequest) (model.ExecuteResult, error) {
	f.gotReq = req
	return f.result, f.err
}

var _ service.Runner = (*fakeRunner)(nil)

func TestRun_Success(t *testing.T) {
	fixed := model.ExecuteResult{
		Verdict:    model.VerdictOK,
		Stdout:     "42\n",
		TimeUsed:   7,
		MemoryUsed: 16,
		ExitCode:   0,
		ExtraInfo:  "fixed test result",
	}
	runner := &fakeRunner{result: fixed}

	var out bytes.Buffer
	var errOut bytes.Buffer
	application := New(runner, &out, &errOut)

	exitCode := application.Run(context.Background(), []string{
		"--exec", "/tmp/a.out",
		"--input", "/tmp/input.txt",
		"--lang", "C++",
		"--time-limit", "1000",
		"--memory-limit", "256",
	})
	if exitCode != 0 {
		t.Fatalf("unexpected exit code: got %d, want 0 (stderr=%s)", exitCode, errOut.String())
	}

	if runner.gotReq.ExecutablePath != "/tmp/a.out" {
		t.Fatalf("unexpected executable path: %s", runner.gotReq.ExecutablePath)
	}
	if runner.gotReq.InputPath != "/tmp/input.txt" {
		t.Fatalf("unexpected input path: %s", runner.gotReq.InputPath)
	}
	if runner.gotReq.Language != model.LanguageCPP {
		t.Fatalf("unexpected language: %v", runner.gotReq.Language)
	}

	var fields map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &fields); err != nil {
		t.Fatalf("failed to decode output json: %v (output=%q)", err, out.String())
	}
	if got := fields["verdict"]; got != fixed.Verdict.String() {
		t.Fatalf("verdict: got %q, want %q", got, fixed.Verdict.String())
	}
	if got := fields["stdout"]; got != fixed.Stdout {
		t.Fatalf("stdout: got %q, want %q", got, fixed.Stdout)
	}
}

func TestRun_InvalidArgs(t *testing.T) {
	runner := &fakeRunner{}

	var out bytes.Buffer
	var errOut bytes.Buffer
	application := New(runner, &out, &errOut)

	exitCode := application.Run(context.Background(), []string{
		"--exec", "/tmp/a.out",
		"--lang", "Java",
		"--time-limit", "1000",
		"--memory-limit", "256",
	})
	if exitCode != 2 {
		t.Fatalf("unexpected exit code: got %d, want 2", exitCode)
	}
}

func TestRun_Help(t *testing.T) {
	runner := &fakeRunner{}

	var out bytes.Buffer
	var errOut bytes.Buffer
	application := New(runner, &out, &errOut)

	exitCode := application.Run(context.Background(), []string{"--help"})
	if exitCode != 0 {
		t.Fatalf("unexpected exit code: got %d, want 0", exitCode)
	}
	if out.Len() == 0 {
		t.Fatal("expected usage output on stdout, got empty")
	}
	if errOut.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", errOut.String())
	}
}
