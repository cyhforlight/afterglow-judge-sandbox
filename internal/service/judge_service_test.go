package service

import (
	"context"
	"errors"
	"testing"

	"afterglow-judge-sandbox/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCompiler struct {
	output CompileOutput
	err    error
}

func (c *fakeCompiler) Compile(_ context.Context, _ CompileRequest) (CompileOutput, error) {
	return c.output, c.err
}

type fakeRunner struct {
	preflightErr error
	result       model.ExecuteResult
	results      []model.ExecuteResult
	calls        int
}

func (r *fakeRunner) PreflightCheck(_ context.Context) error {
	return r.preflightErr
}

func (r *fakeRunner) Execute(_ context.Context, _ model.ExecuteRequest) model.ExecuteResult {
	if len(r.results) == 0 {
		return r.result
	}
	idx := r.calls
	if idx >= len(r.results) {
		idx = len(r.results) - 1
	}
	r.calls++
	return r.results[idx]
}

func TestJudgeEngine_CompileError(t *testing.T) {
	engine := NewJudgeEngine(&fakeRunner{}, &fakeCompiler{output: CompileOutput{
		Result: model.CompileResult{Succeeded: false, Log: "compile failed"},
	}})

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "int main(){",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case1", InputText: "", ExpectedOutput: ""},
		},
	})

	assert.Equal(t, model.VerdictCE, result.Verdict)
	assert.False(t, result.Compile.Succeeded)
	assert.Equal(t, "compile failed", result.Compile.Log)
	assert.Empty(t, result.Cases)
	assert.Equal(t, 1, result.TotalCount)
}

func TestJudgeEngine_WrongAnswerAfterOK(t *testing.T) {
	engine := NewJudgeEngine(&fakeRunner{result: model.ExecuteResult{Verdict: model.VerdictOK, Stdout: "41\n"}}, &fakeCompiler{output: CompileOutput{
		Result:          model.CompileResult{Succeeded: true},
		ArtifactPath:    "/tmp/program",
		RuntimeLanguage: model.LanguageCPP,
	}})

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case1", InputText: "", ExpectedOutput: "42\n"},
		},
	})

	require.Len(t, result.Cases, 1)
	assert.Equal(t, model.VerdictWA, result.Cases[0].Verdict)
	assert.Equal(t, model.VerdictWA, result.Verdict)
	assert.Equal(t, 0, result.PassedCount)
}

func TestJudgeEngine_TrimTrailingSpaceCompare(t *testing.T) {
	engine := NewJudgeEngine(&fakeRunner{result: model.ExecuteResult{Verdict: model.VerdictOK, Stdout: "42\n\n"}}, &fakeCompiler{output: CompileOutput{
		Result:          model.CompileResult{Succeeded: true},
		ArtifactPath:    "/tmp/program",
		RuntimeLanguage: model.LanguageCPP,
	}})

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case1", InputText: "", ExpectedOutput: "42"},
		},
	})

	require.Len(t, result.Cases, 1)
	assert.Equal(t, model.VerdictOK, result.Cases[0].Verdict)
	assert.Equal(t, model.VerdictOK, result.Verdict)
	assert.Equal(t, 1, result.PassedCount)
}

func TestJudgeEngine_AggregateRuntimePriority(t *testing.T) {
	runner := &fakeRunner{results: []model.ExecuteResult{
		{Verdict: model.VerdictRE},
		{Verdict: model.VerdictTLE},
		{Verdict: model.VerdictMLE},
		{Verdict: model.VerdictOLE},
	}}
	engine := NewJudgeEngine(runner, &fakeCompiler{output: CompileOutput{
		Result:          model.CompileResult{Succeeded: true},
		ArtifactPath:    "/tmp/program",
		RuntimeLanguage: model.LanguageCPP,
	}})

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "1"},
			{Name: "2"},
			{Name: "3"},
			{Name: "4"},
		},
	})

	assert.Equal(t, model.VerdictOLE, result.Verdict)
}

func TestJudgeEngine_CompilerInfraError(t *testing.T) {
	engine := NewJudgeEngine(&fakeRunner{}, &fakeCompiler{err: errors.New("boom")})

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case1"},
		},
	})

	assert.Equal(t, model.VerdictUKE, result.Verdict)
	assert.False(t, result.Compile.Succeeded)
	assert.Contains(t, result.Compile.Log, "compile infrastructure error")
}
