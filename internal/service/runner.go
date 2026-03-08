// Package service implements the core execution logic.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/sandbox"
	"afterglow-judge-sandbox/internal/workspace"
)

// Runner executes a program inside a sandboxed container.
type Runner interface {
	PreflightCheck(ctx context.Context) error
	Execute(ctx context.Context, req model.ExecuteRequest) (model.ExecuteResult, error)
}

// runner executes code in isolated containers.
type runner struct {
	sandbox  sandbox.Sandbox
	profiles map[model.Language]RunConfig
	log      *slog.Logger
}

// NewRunner creates a runner with default language profiles.
func NewRunner(sb sandbox.Sandbox) Runner {
	profiles := make(map[model.Language]RunConfig)

	profiles[model.LanguageC] = cProfile().Run
	profiles[model.LanguageCPP] = cppProfile().Run
	profiles[model.LanguageJava] = javaProfile().Run
	profiles[model.LanguagePython] = pythonProfile().Run

	return &runner{
		sandbox:  sb,
		profiles: profiles,
		log:      slog.Default(),
	}
}

// PreflightCheck verifies that cgroup v2 and containerd are available.
func (r *runner) PreflightCheck(ctx context.Context) error {
	return r.sandbox.PreflightCheck(ctx)
}

// Execute runs the given request and returns the execution result.
func (r *runner) Execute(ctx context.Context, req model.ExecuteRequest) (model.ExecuteResult, error) {
	result, err := r.execute(ctx, req)
	if err != nil {
		r.log.ErrorContext(ctx, "execution failed", "error", err)
		return model.ExecuteResult{}, err
	}
	r.log.InfoContext(ctx, "execution complete",
		"verdict", result.Verdict.String(),
		"timeUsed", result.TimeUsed,
		"memoryUsed", result.MemoryUsed,
	)
	return result, nil
}

func (r *runner) execute(ctx context.Context, req model.ExecuteRequest) (model.ExecuteResult, error) {
	profile, ok := r.profiles[req.Language]
	if !ok {
		return model.ExecuteResult{}, fmt.Errorf("no run profile for language %q", req.Language)
	}
	if len(req.Program.Data) == 0 {
		return model.ExecuteResult{}, errors.New("program data is required")
	}

	ws, err := workspace.New()
	if err != nil {
		return model.ExecuteResult{}, fmt.Errorf("create workspace: %w", err)
	}
	defer func() { _ = ws.Cleanup() }()

	programMode := req.Program.Mode
	if programMode == 0 {
		programMode = profile.FileMode
	}
	if err := ws.WriteFile(profile.ArtifactName, req.Program.Data, programMode); err != nil {
		return model.ExecuteResult{}, fmt.Errorf("write program file: %w", err)
	}

	containerPath := "/sandbox/" + profile.ArtifactName
	args := profile.RuntimeCommand(containerPath)
	cwd := "/sandbox"

	sandboxReq := sandbox.ExecuteRequest{
		ImageRef: profile.ImageRef,
		Command:  args,
		MountDir: &sandbox.Mount{
			HostPath:      ws.Dir(),
			ContainerPath: "/sandbox",
			ReadOnly:      true,
		},
		Cwd:   &cwd,
		Stdin: strings.NewReader(req.Input),
		Limits: sandbox.ResourceLimits{
			CPUTimeMs:   req.TimeLimit,
			WallTimeMs:  req.TimeLimit * sandbox.WallTimeMultiplier,
			MemoryMB:    req.MemoryLimit,
			OutputBytes: sandbox.DefaultExecutionOutputLimitBytes,
		},
	}

	result, err := r.sandbox.Execute(ctx, sandboxReq)
	if err != nil {
		return model.ExecuteResult{}, fmt.Errorf("sandbox execute: %w", err)
	}

	return convertSandboxResult(result), nil
}

func convertSandboxResult(sr sandbox.ExecuteResult) model.ExecuteResult {
	return model.ExecuteResult{
		Verdict:    convertVerdict(sr.Verdict),
		Stdout:     sr.Stdout,
		TimeUsed:   sr.CPUTimeMs,
		MemoryUsed: sr.MemoryMB,
		ExitCode:   sr.ExitCode,
		ExtraInfo:  sr.ExtraInfo,
	}
}

func convertVerdict(v sandbox.Verdict) model.Verdict {
	switch v {
	case sandbox.VerdictOK:
		return model.VerdictOK
	case sandbox.VerdictTLE:
		return model.VerdictTLE
	case sandbox.VerdictMLE:
		return model.VerdictMLE
	case sandbox.VerdictOLE:
		return model.VerdictOLE
	case sandbox.VerdictRE:
		return model.VerdictRE
	default:
		return model.VerdictUKE
	}
}
