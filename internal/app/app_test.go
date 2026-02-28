package app

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/service"
)

type fakeRunner struct {
	gotReq model.ExecuteRequest
	result model.ExecuteResult

	preflightErr    error
	preflightCalled bool

	executeCalled bool
}

func (f *fakeRunner) PreflightCheck(_ context.Context) error {
	f.preflightCalled = true
	return f.preflightErr
}

func (f *fakeRunner) Execute(_ context.Context, req model.ExecuteRequest) model.ExecuteResult {
	f.executeCalled = true
	f.gotReq = req
	return f.result
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
	require.Equal(t, 0, exitCode, "stderr=%s", errOut.String())
	assert.True(t, runner.preflightCalled)

	assert.Equal(t, "/tmp/a.out", runner.gotReq.ExecutablePath)
	assert.Equal(t, "/tmp/input.txt", runner.gotReq.InputPath)
	assert.Equal(t, model.LanguageCPP, runner.gotReq.Language)

	var fields map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Bytes(), &fields), "output=%q", out.String())
	assert.Equal(t, fixed.Verdict.String(), fields["verdict"])
	assert.Equal(t, fixed.Stdout, fields["stdout"])
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
	assert.Equal(t, 2, exitCode)
	assert.False(t, runner.preflightCalled)
}

func TestRun_Help(t *testing.T) {
	runner := &fakeRunner{}

	var out bytes.Buffer
	var errOut bytes.Buffer
	application := New(runner, &out, &errOut)

	exitCode := application.Run(context.Background(), []string{"--help"})
	assert.Equal(t, 0, exitCode)
	assert.False(t, runner.preflightCalled)
	assert.NotEmpty(t, out.String(), "expected usage output on stdout")
	assert.Empty(t, errOut.String(), "unexpected stderr output")
}

func TestRun_PreflightCheck(t *testing.T) {
	tests := []struct {
		name            string
		preflightErr    error
		wantExitCode    int
		wantErrContains string
		wantExecuteCall bool
	}{
		{
			name:            "preflight failed",
			preflightErr:    assert.AnError,
			wantExitCode:    1,
			wantErrContains: "environment check failed",
			wantExecuteCall: false,
		},
		{
			name:            "preflight passed",
			preflightErr:    nil,
			wantExitCode:    0,
			wantErrContains: "",
			wantExecuteCall: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			runner := &fakeRunner{
				result:       model.ExecuteResult{Verdict: model.VerdictOK},
				preflightErr: testCase.preflightErr,
			}

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

			assert.Equal(t, testCase.wantExitCode, exitCode)
			assert.True(t, runner.preflightCalled)
			assert.Equal(t, testCase.wantExecuteCall, runner.executeCalled)
			if testCase.wantErrContains != "" {
				assert.Contains(t, errOut.String(), testCase.wantErrContains)
				return
			}
			assert.Empty(t, errOut.String())
		})
	}
}

func TestRun_InfraFailureVerdictUKE(t *testing.T) {
	runner := &fakeRunner{
		result: model.ExecuteResult{
			Verdict:   model.VerdictUKE,
			ExitCode:  -1,
			ExtraInfo: "connect to containerd: permission denied",
		},
	}

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

	assert.Equal(t, 1, exitCode)
	assert.True(t, runner.preflightCalled)
	assert.True(t, runner.executeCalled)
	assert.Empty(t, errOut.String())

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Equal(t, model.VerdictUKE.String(), got["verdict"])
	assert.Equal(t, float64(-1), got["exitCode"])
}
