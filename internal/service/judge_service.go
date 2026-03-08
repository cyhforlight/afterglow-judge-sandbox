package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"afterglow-judge-sandbox/internal/model"
)

// JudgeService handles full judge orchestration.
type JudgeService interface {
	PreflightCheck(ctx context.Context) error
	Judge(ctx context.Context, req model.JudgeRequest) model.JudgeResult
}

// JudgeEngine implements JudgeService.
type JudgeEngine struct {
	runner          UserCodeRunner
	compiler        UserCodeCompiler
	checkerCompiler CheckerCompiler
	checkerRunner   CheckerRunner
	resources       ResourceStore
	log             *slog.Logger
}

// NewJudgeEngine creates a judge engine.
func NewJudgeEngine(
	runner UserCodeRunner,
	compiler UserCodeCompiler,
	checkerCompiler CheckerCompiler,
	checkerRunner CheckerRunner,
	resources ResourceStore,
) *JudgeEngine {
	return &JudgeEngine{
		runner:          runner,
		compiler:        compiler,
		checkerCompiler: checkerCompiler,
		checkerRunner:   checkerRunner,
		resources:       resources,
		log:             slog.Default(),
	}
}

// PreflightCheck verifies backend runtime readiness.
func (s *JudgeEngine) PreflightCheck(ctx context.Context) error {
	return s.runner.PreflightCheck(ctx)
}

// Judge compiles source code and evaluates all test cases.
func (s *JudgeEngine) Judge(ctx context.Context, req model.JudgeRequest) model.JudgeResult {
	if err := validateJudgeRequest(req); err != nil {
		return model.JudgeResult{
			Verdict: model.VerdictUKE,
			Compile: model.CompileResult{
				Succeeded: false,
				Log:       err.Error(),
			},
			TotalCount: len(req.TestCases),
		}
	}

	compileOut, err := s.compiler.Compile(ctx, UserCodeCompileRequest{
		Language:   req.Language,
		SourceCode: req.SourceCode,
	})
	if err != nil {
		s.log.ErrorContext(ctx, "compile step failed", "error", err)
		return model.JudgeResult{
			Verdict: model.VerdictUKE,
			Compile: model.CompileResult{
				Succeeded: false,
				Log:       fmt.Sprintf("compile infrastructure error: %v", err),
			},
			TotalCount: len(req.TestCases),
		}
	}

	if !compileOut.Result.Succeeded {
		return model.JudgeResult{
			Verdict:    model.VerdictCE,
			Compile:    compileOut.Result,
			TotalCount: len(req.TestCases),
			Cases:      make([]model.JudgeCaseResult, 0, len(req.TestCases)),
		}
	}

	checkerOut, err := s.compileDefaultChecker(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "checker setup failed", "error", err)
		return s.unknownJudgeResult(req.TestCases, compileOut.Result, fmt.Sprintf("checker setup failed: %v", err))
	}
	if !checkerOut.Result.Succeeded {
		message := strings.TrimSpace(checkerOut.Result.Log)
		if message == "" {
			message = "checker compilation failed"
		}
		s.log.ErrorContext(ctx, "checker compilation failed", "log", message)
		return s.unknownJudgeResult(req.TestCases, compileOut.Result, fmt.Sprintf("checker compilation failed: %s", message))
	}
	if checkerOut.Artifact == nil {
		s.log.ErrorContext(ctx, "checker compilation succeeded without artifact")
		return s.unknownJudgeResult(req.TestCases, compileOut.Result, "checker compilation succeeded without artifact")
	}

	caseResults := make([]model.JudgeCaseResult, 0, len(req.TestCases))
	passedCount := 0

	for _, testCase := range req.TestCases {
		caseResult := s.runSingleCase(ctx, req, compileOut, *checkerOut.Artifact, testCase)
		if caseResult.Verdict == model.VerdictOK {
			passedCount++
		}
		caseResults = append(caseResults, caseResult)
	}

	return model.JudgeResult{
		Verdict:     aggregateJudgeVerdict(caseResults),
		Compile:     compileOut.Result,
		Cases:       caseResults,
		PassedCount: passedCount,
		TotalCount:  len(req.TestCases),
	}
}

func validateJudgeRequest(req model.JudgeRequest) error {
	if strings.TrimSpace(req.SourceCode) == "" {
		return errors.New("source code is required")
	}
	if req.Language == model.LanguageUnknown {
		return errors.New("language is required")
	}
	if req.TimeLimit <= 0 {
		return errors.New("time limit must be positive")
	}
	if req.MemoryLimit <= 0 {
		return errors.New("memory limit must be positive")
	}
	if len(req.TestCases) == 0 {
		return errors.New("at least one testcase is required")
	}
	return nil
}

func (s *JudgeEngine) compileDefaultChecker(ctx context.Context) (CheckerCompileOutput, error) {
	if s.resources == nil {
		return CheckerCompileOutput{}, errors.New("resource store is required")
	}
	if s.checkerCompiler == nil {
		return CheckerCompileOutput{}, errors.New("checker compiler is required")
	}

	checkerSource, err := s.resources.Get(ctx, defaultCheckerSourceKey)
	if err != nil {
		return CheckerCompileOutput{}, fmt.Errorf("load %q: %w", defaultCheckerSourceKey, err)
	}

	testlibHeader, err := s.resources.Get(ctx, testlibHeaderKey)
	if err != nil {
		return CheckerCompileOutput{}, fmt.Errorf("load %q: %w", testlibHeaderKey, err)
	}

	return s.checkerCompiler.Compile(ctx, CheckerCompileRequest{
		SourceCode: checkerSource,
		SupportFiles: []CompileFile{{
			Name:    testlibHeaderKey,
			Content: testlibHeader,
			Mode:    0o644,
		}},
	})
}

func (s *JudgeEngine) runSingleCase(
	ctx context.Context,
	req model.JudgeRequest,
	compileOut UserCodeCompileOutput,
	checkerArtifact model.CompiledArtifact,
	testCase model.JudgeTestCase,
) model.JudgeCaseResult {
	if compileOut.Artifact == nil {
		return model.JudgeCaseResult{
			Name:      testCase.Name,
			Verdict:   model.VerdictUKE,
			ExtraInfo: "compiled artifact is missing",
		}
	}

	runResult, err := s.runner.Execute(ctx, model.ExecuteRequest{
		Program:     *compileOut.Artifact,
		Input:       testCase.InputText,
		Language:    compileOut.RuntimeLanguage,
		TimeLimit:   req.TimeLimit,
		MemoryLimit: req.MemoryLimit,
	})
	if err != nil {
		s.log.ErrorContext(ctx, "program execution failed", "testCase", testCase.Name, "error", err)
		return model.JudgeCaseResult{
			Name:      testCase.Name,
			Verdict:   model.VerdictUKE,
			ExtraInfo: fmt.Sprintf("infrastructure error: %v", err),
		}
	}

	finalVerdict := runResult.Verdict
	extraInfo := runResult.ExtraInfo
	if runResult.Verdict == model.VerdictOK {
		if s.checkerRunner == nil {
			finalVerdict = model.VerdictUKE
			extraInfo = "checker runner is required"
		}

		if finalVerdict == model.VerdictOK {
			checkerResult, err := s.checkerRunner.Run(ctx, CheckerRunRequest{
				Checker:        checkerArtifact,
				InputText:      testCase.InputText,
				ActualOutput:   runResult.Stdout,
				ExpectedOutput: testCase.ExpectedOutput,
			})
			if err != nil {
				s.log.ErrorContext(ctx, "checker execution failed", "testCase", testCase.Name, "error", err)
				finalVerdict = model.VerdictUKE
				extraInfo = fmt.Sprintf("checker infrastructure error: %v", err)
			} else {
				finalVerdict = checkerResult.Verdict
				extraInfo = checkerMessageOrDefault(checkerResult)
			}
		}
	}

	return model.JudgeCaseResult{
		Name:       testCase.Name,
		Verdict:    finalVerdict,
		Stdout:     runResult.Stdout,
		TimeUsed:   runResult.TimeUsed,
		MemoryUsed: runResult.MemoryUsed,
		ExitCode:   runResult.ExitCode,
		ExtraInfo:  extraInfo,
	}
}

func (s *JudgeEngine) unknownJudgeResult(
	testCases []model.JudgeTestCase,
	compileResult model.CompileResult,
	message string,
) model.JudgeResult {
	caseResults := make([]model.JudgeCaseResult, 0, len(testCases))
	for _, testCase := range testCases {
		caseResults = append(caseResults, model.JudgeCaseResult{
			Name:      testCase.Name,
			Verdict:   model.VerdictUKE,
			ExtraInfo: message,
		})
	}

	return model.JudgeResult{
		Verdict:    model.VerdictUKE,
		Compile:    compileResult,
		Cases:      caseResults,
		TotalCount: len(testCases),
	}
}

func checkerMessageOrDefault(result CheckerRunResult) string {
	if result.Message != "" {
		return result.Message
	}
	if result.Verdict == model.VerdictWA {
		return "checker reported wrong answer"
	}
	if result.Verdict == model.VerdictUKE {
		return "checker reported infrastructure failure"
	}
	return ""
}

func aggregateJudgeVerdict(cases []model.JudgeCaseResult) model.Verdict {
	if len(cases) == 0 {
		return model.VerdictUKE
	}

	highestRuntime := model.VerdictUnknown
	hasWA := false

	for _, caseResult := range cases {
		if isRuntimeVerdict(caseResult.Verdict) {
			if runtimeSeverity(caseResult.Verdict) > runtimeSeverity(highestRuntime) {
				highestRuntime = caseResult.Verdict
			}
			continue
		}

		if caseResult.Verdict == model.VerdictWA {
			hasWA = true
		}
	}

	if highestRuntime != model.VerdictUnknown {
		return highestRuntime
	}
	if hasWA {
		return model.VerdictWA
	}
	return model.VerdictOK
}

func isRuntimeVerdict(verdict model.Verdict) bool {
	switch verdict {
	case model.VerdictOLE, model.VerdictMLE, model.VerdictTLE, model.VerdictRE, model.VerdictUKE:
		return true
	default:
		return false
	}
}

func runtimeSeverity(verdict model.Verdict) int {
	switch verdict {
	case model.VerdictOLE:
		return 5
	case model.VerdictMLE:
		return 4
	case model.VerdictTLE:
		return 3
	case model.VerdictRE:
		return 2
	case model.VerdictUKE:
		return 1
	default:
		return 0
	}
}
