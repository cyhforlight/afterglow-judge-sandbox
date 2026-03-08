package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"afterglow-judge-sandbox/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCompiler struct {
	output UserCodeCompileOutput
	err    error
}

func (c *fakeCompiler) Compile(_ context.Context, _ UserCodeCompileRequest) (UserCodeCompileOutput, error) {
	return c.output, c.err
}

type fakeRunner struct {
	preflightErr error
	executeErr   error
	result       model.ExecuteResult
	results      []model.ExecuteResult
	calls        int
}

func (r *fakeRunner) PreflightCheck(_ context.Context) error {
	return r.preflightErr
}

func (r *fakeRunner) Execute(_ context.Context, _ model.ExecuteRequest) (model.ExecuteResult, error) {
	if r.executeErr != nil {
		return model.ExecuteResult{}, r.executeErr
	}
	if len(r.results) == 0 {
		return r.result, nil
	}

	idx := r.calls
	if idx >= len(r.results) {
		idx = len(r.results) - 1
	}
	r.calls++
	return r.results[idx], nil
}

type fakeCheckerCompiler struct {
	output CheckerCompileOutput
	err    error
	calls  int
}

func (c *fakeCheckerCompiler) Compile(_ context.Context, _ CheckerCompileRequest) (CheckerCompileOutput, error) {
	c.calls++
	return c.output, c.err
}

type fakeCheckerRunner struct {
	result  CheckerRunResult
	results []CheckerRunResult
	err     error
	calls   int
}

func (r *fakeCheckerRunner) Run(_ context.Context, _ CheckerRunRequest) (CheckerRunResult, error) {
	r.calls++
	if r.err != nil {
		return CheckerRunResult{}, r.err
	}
	if len(r.results) == 0 {
		return r.result, nil
	}

	idx := r.calls - 1
	if idx >= len(r.results) {
		idx = len(r.results) - 1
	}
	return r.results[idx], nil
}

type fakeResourceStore struct {
	files map[string][]byte
	err   error
}

func (s *fakeResourceStore) Get(_ context.Context, key string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}

	content, ok := s.files[key]
	if !ok {
		return nil, fmt.Errorf("resource not found: %s", key)
	}

	return append([]byte(nil), content...), nil
}

func testCompiledArtifact() *model.CompiledArtifact {
	return &model.CompiledArtifact{
		Name: "program",
		Data: []byte("binary"),
		Mode: 0o755,
	}
}

func testCheckerArtifact() *model.CompiledArtifact {
	return &model.CompiledArtifact{
		Name: checkerArtifactFileName,
		Data: []byte("checker"),
		Mode: 0o755,
	}
}

func newTestJudgeEngine(
	runner *fakeRunner,
	compiler *fakeCompiler,
	checkerCompiler *fakeCheckerCompiler,
	checkerRunner *fakeCheckerRunner,
	resources *fakeResourceStore,
) *JudgeEngine {
	if runner == nil {
		runner = &fakeRunner{}
	}
	if compiler == nil {
		compiler = &fakeCompiler{}
	}
	if checkerCompiler == nil {
		checkerCompiler = &fakeCheckerCompiler{output: CheckerCompileOutput{
			Result:   model.CompileResult{Succeeded: true},
			Artifact: testCheckerArtifact(),
		}}
	}
	if checkerRunner == nil {
		checkerRunner = &fakeCheckerRunner{}
	}
	if resources == nil {
		resources = &fakeResourceStore{files: map[string][]byte{
			defaultCheckerSourceKey: []byte("checker source"),
			testlibHeaderKey:        []byte("header"),
		}}
	}

	return NewJudgeEngine(runner, compiler, checkerCompiler, checkerRunner, resources)
}

func successfulCompileOutput(language model.Language) UserCodeCompileOutput {
	return UserCodeCompileOutput{
		Result:          model.CompileResult{Succeeded: true},
		Artifact:        testCompiledArtifact(),
		RuntimeLanguage: language,
	}
}

func TestJudgeEngine_CompileError(t *testing.T) {
	checkerCompiler := &fakeCheckerCompiler{output: CheckerCompileOutput{
		Result:   model.CompileResult{Succeeded: true},
		Artifact: testCheckerArtifact(),
	}}
	engine := newTestJudgeEngine(nil, &fakeCompiler{output: UserCodeCompileOutput{
		Result: model.CompileResult{Succeeded: false, Log: "compile failed"},
	}}, checkerCompiler, nil, nil)

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
	assert.Equal(t, 0, checkerCompiler.calls)
	assert.Equal(t, 1, result.TotalCount)
}

func TestJudgeEngine_WrongAnswerAfterOK(t *testing.T) {
	checkerRunner := &fakeCheckerRunner{result: CheckerRunResult{
		Verdict: model.VerdictWA,
		Message: "1st lines differ - expected: '42', found: '41'",
	}}
	engine := newTestJudgeEngine(
		&fakeRunner{result: model.ExecuteResult{Verdict: model.VerdictOK, Stdout: "41\n"}},
		&fakeCompiler{output: successfulCompileOutput(model.LanguageCPP)},
		nil,
		checkerRunner,
		nil,
	)

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
	assert.Equal(t, "1st lines differ - expected: '42', found: '41'", result.Cases[0].ExtraInfo)
	assert.Equal(t, model.VerdictWA, result.Verdict)
	assert.Equal(t, 0, result.PassedCount)
	assert.Equal(t, 1, checkerRunner.calls)
}

func TestJudgeEngine_CheckerInfrastructureErrorMarksOnlyCurrentCase(t *testing.T) {
	runner := &fakeRunner{results: []model.ExecuteResult{
		{Verdict: model.VerdictOK, Stdout: "2\n", ExitCode: 0},
		{Verdict: model.VerdictOK, Stdout: "4\n", ExitCode: 0},
		{Verdict: model.VerdictOK, Stdout: "6\n", ExitCode: 0},
	}}
	checkerRunner := &fakeCheckerRunner{results: []CheckerRunResult{
		{Verdict: model.VerdictOK},
		{Verdict: model.VerdictUKE, Message: "checker timed out"},
		{Verdict: model.VerdictOK},
	}}
	engine := newTestJudgeEngine(
		runner,
		&fakeCompiler{output: successfulCompileOutput(model.LanguageCPP)},
		nil,
		checkerRunner,
		nil,
	)

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case-1", ExpectedOutput: "2\n"},
			{Name: "case-2", ExpectedOutput: "4\n"},
			{Name: "case-3", ExpectedOutput: "6\n"},
		},
	})

	require.Len(t, result.Cases, 3)
	assert.Equal(t, model.VerdictOK, result.Cases[0].Verdict)
	assert.Equal(t, model.VerdictUKE, result.Cases[1].Verdict)
	assert.Equal(t, "checker timed out", result.Cases[1].ExtraInfo)
	assert.Equal(t, model.VerdictOK, result.Cases[2].Verdict)
	assert.Equal(t, model.VerdictUKE, result.Verdict)
	assert.Equal(t, 2, result.PassedCount)
	assert.Equal(t, 3, checkerRunner.calls)
}

func TestJudgeEngine_AggregateRuntimePriority(t *testing.T) {
	runner := &fakeRunner{results: []model.ExecuteResult{
		{Verdict: model.VerdictRE},
		{Verdict: model.VerdictTLE},
		{Verdict: model.VerdictMLE},
		{Verdict: model.VerdictOLE},
	}}
	checkerRunner := &fakeCheckerRunner{}
	engine := newTestJudgeEngine(
		runner,
		&fakeCompiler{output: successfulCompileOutput(model.LanguageCPP)},
		nil,
		checkerRunner,
		nil,
	)

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
	assert.Equal(t, 0, checkerRunner.calls)
}

func TestJudgeEngine_CompilerInfraError(t *testing.T) {
	engine := newTestJudgeEngine(nil, &fakeCompiler{err: errors.New("boom")}, nil, nil, nil)

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

func TestJudgeEngine_MultipleTestCases_MixedResults(t *testing.T) {
	runner := &fakeRunner{results: []model.ExecuteResult{
		{Verdict: model.VerdictOK, Stdout: "2\n", ExitCode: 0},
		{Verdict: model.VerdictOK, Stdout: "4\n", ExitCode: 0},
		{Verdict: model.VerdictTLE, Stdout: "", ExitCode: 124},
	}}
	checkerRunner := &fakeCheckerRunner{results: []CheckerRunResult{
		{Verdict: model.VerdictOK},
		{Verdict: model.VerdictWA, Message: "2nd lines differ"},
	}}
	engine := newTestJudgeEngine(
		runner,
		&fakeCompiler{output: successfulCompileOutput(model.LanguageCPP)},
		nil,
		checkerRunner,
		nil,
	)

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case-1", InputText: "1\n", ExpectedOutput: "2\n"},
			{Name: "case-2", InputText: "2\n", ExpectedOutput: "8\n"},
			{Name: "case-3", InputText: "3\n", ExpectedOutput: "6\n"},
		},
	})

	require.Len(t, result.Cases, 3)
	assert.Equal(t, model.VerdictOK, result.Cases[0].Verdict)
	assert.Equal(t, model.VerdictWA, result.Cases[1].Verdict)
	assert.Equal(t, "2nd lines differ", result.Cases[1].ExtraInfo)
	assert.Equal(t, model.VerdictTLE, result.Cases[2].Verdict)
	assert.Equal(t, model.VerdictTLE, result.Verdict)
	assert.Equal(t, 1, result.PassedCount)
}

func TestJudgeEngine_AllTestCasesPass(t *testing.T) {
	runner := &fakeRunner{results: []model.ExecuteResult{
		{Verdict: model.VerdictOK, Stdout: "2\n", ExitCode: 0},
		{Verdict: model.VerdictOK, Stdout: "4\n", ExitCode: 0},
		{Verdict: model.VerdictOK, Stdout: "6\n", ExitCode: 0},
	}}
	checkerRunner := &fakeCheckerRunner{results: []CheckerRunResult{
		{Verdict: model.VerdictOK},
		{Verdict: model.VerdictOK},
		{Verdict: model.VerdictOK},
	}}
	engine := newTestJudgeEngine(
		runner,
		&fakeCompiler{output: successfulCompileOutput(model.LanguageCPP)},
		nil,
		checkerRunner,
		nil,
	)

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case-1", InputText: "1\n", ExpectedOutput: "2\n"},
			{Name: "case-2", InputText: "2\n", ExpectedOutput: "4\n"},
			{Name: "case-3", InputText: "3\n", ExpectedOutput: "6\n"},
		},
	})

	assert.Equal(t, model.VerdictOK, result.Verdict)
	assert.Equal(t, 3, result.PassedCount)
	assert.Equal(t, 3, result.TotalCount)
}

func TestJudgeEngine_EmptyTestCases(t *testing.T) {
	engine := newTestJudgeEngine(nil, nil, nil, nil, nil)

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases:   []model.JudgeTestCase{},
	})

	assert.Equal(t, model.VerdictUKE, result.Verdict)
	assert.False(t, result.Compile.Succeeded)
	assert.Contains(t, result.Compile.Log, "at least one testcase is required")
}

func TestJudgeEngine_SingleTestCase(t *testing.T) {
	runner := &fakeRunner{result: model.ExecuteResult{
		Verdict: model.VerdictOK, Stdout: "42\n", ExitCode: 0,
	}}
	checkerRunner := &fakeCheckerRunner{result: CheckerRunResult{Verdict: model.VerdictOK}}
	engine := newTestJudgeEngine(
		runner,
		&fakeCompiler{output: successfulCompileOutput(model.LanguagePython)},
		nil,
		checkerRunner,
		nil,
	)

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "print(42)",
		Language:    model.LanguagePython,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "only-case", InputText: "", ExpectedOutput: "42\n"},
		},
	})

	require.Len(t, result.Cases, 1)
	assert.Equal(t, model.VerdictOK, result.Cases[0].Verdict)
	assert.Equal(t, model.VerdictOK, result.Verdict)
	assert.Equal(t, 1, result.PassedCount)
}

func TestJudgeEngine_InvalidRequest(t *testing.T) {
	engine := newTestJudgeEngine(nil, nil, nil, nil, nil)

	tests := []struct {
		name   string
		req    model.JudgeRequest
		errMsg string
	}{
		{
			name: "empty source code",
			req: model.JudgeRequest{
				SourceCode:  "",
				Language:    model.LanguagePython,
				TimeLimit:   1000,
				MemoryLimit: 128,
				TestCases:   []model.JudgeTestCase{{Name: "case1"}},
			},
			errMsg: "source code is required",
		},
		{
			name: "unknown language",
			req: model.JudgeRequest{
				SourceCode:  "code",
				Language:    model.LanguageUnknown,
				TimeLimit:   1000,
				MemoryLimit: 128,
				TestCases:   []model.JudgeTestCase{{Name: "case1"}},
			},
			errMsg: "language is required",
		},
		{
			name: "zero time limit",
			req: model.JudgeRequest{
				SourceCode:  "code",
				Language:    model.LanguagePython,
				TimeLimit:   0,
				MemoryLimit: 128,
				TestCases:   []model.JudgeTestCase{{Name: "case1"}},
			},
			errMsg: "time limit must be positive",
		},
		{
			name: "negative memory limit",
			req: model.JudgeRequest{
				SourceCode:  "code",
				Language:    model.LanguagePython,
				TimeLimit:   1000,
				MemoryLimit: -1,
				TestCases:   []model.JudgeTestCase{{Name: "case1"}},
			},
			errMsg: "memory limit must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Judge(context.Background(), tt.req)
			assert.Equal(t, model.VerdictUKE, result.Verdict)
			assert.False(t, result.Compile.Succeeded)
			assert.Contains(t, result.Compile.Log, tt.errMsg)
		})
	}
}

func TestJudgeEngine_CheckerCompileFailureReturnsUnknownError(t *testing.T) {
	engine := newTestJudgeEngine(
		&fakeRunner{},
		&fakeCompiler{output: successfulCompileOutput(model.LanguageCPP)},
		&fakeCheckerCompiler{output: CheckerCompileOutput{
			Result: model.CompileResult{Succeeded: false, Log: "fatal error: testlib.h missing"},
		}},
		nil,
		nil,
	)

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case-1"},
			{Name: "case-2"},
		},
	})

	assert.Equal(t, model.VerdictUKE, result.Verdict)
	assert.True(t, result.Compile.Succeeded)
	require.Len(t, result.Cases, 2)
	assert.Equal(t, model.VerdictUKE, result.Cases[0].Verdict)
	assert.Contains(t, result.Cases[0].ExtraInfo, "checker compilation failed")
}

func TestJudgeEngine_MissingCheckerResourceReturnsUnknownError(t *testing.T) {
	engine := newTestJudgeEngine(
		&fakeRunner{},
		&fakeCompiler{output: successfulCompileOutput(model.LanguageCPP)},
		nil,
		nil,
		&fakeResourceStore{files: map[string][]byte{
			defaultCheckerSourceKey: []byte("checker source"),
		}},
	)

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case-1"},
		},
	})

	assert.Equal(t, model.VerdictUKE, result.Verdict)
	assert.True(t, result.Compile.Succeeded)
	require.Len(t, result.Cases, 1)
	assert.Contains(t, result.Cases[0].ExtraInfo, testlibHeaderKey)
}

func TestJudgeEngine_UserRuntimeErrorSkipsChecker(t *testing.T) {
	checkerRunner := &fakeCheckerRunner{}
	engine := newTestJudgeEngine(
		&fakeRunner{result: model.ExecuteResult{Verdict: model.VerdictTLE}},
		&fakeCompiler{output: successfulCompileOutput(model.LanguageCPP)},
		nil,
		checkerRunner,
		nil,
	)

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case-1"},
		},
	})

	require.Len(t, result.Cases, 1)
	assert.Equal(t, model.VerdictTLE, result.Cases[0].Verdict)
	assert.Equal(t, 0, checkerRunner.calls)
}

func TestJudgeEngine_CheckerRunnerErrorMarksCaseUnknownError(t *testing.T) {
	checkerRunner := &fakeCheckerRunner{err: errors.New("sandbox boom")}
	engine := newTestJudgeEngine(
		&fakeRunner{result: model.ExecuteResult{Verdict: model.VerdictOK, Stdout: "42\n"}},
		&fakeCompiler{output: successfulCompileOutput(model.LanguageCPP)},
		nil,
		checkerRunner,
		nil,
	)

	result := engine.Judge(context.Background(), model.JudgeRequest{
		SourceCode:  "code",
		Language:    model.LanguageCPP,
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases: []model.JudgeTestCase{
			{Name: "case-1", ExpectedOutput: "42\n"},
			{Name: "case-2", ExpectedOutput: "42\n"},
		},
	})

	require.Len(t, result.Cases, 2)
	assert.Equal(t, model.VerdictUKE, result.Cases[0].Verdict)
	assert.Contains(t, result.Cases[0].ExtraInfo, "checker infrastructure error")
	assert.Equal(t, model.VerdictUKE, result.Verdict)
	assert.Equal(t, 2, checkerRunner.calls)
}
