package service

import (
	"context"
	"errors"
	"fmt"

	"afterglow-judge-sandbox/internal/model"
)

// Runner executes a program inside a sandboxed container and returns the result.
type Runner interface {
	Execute(ctx context.Context, req model.ExecuteRequest) (model.ExecuteResult, error)
}

// DispatchRunner routes execution to a language-specific ContainerdRunner.
type DispatchRunner struct {
	runners map[model.Language]Runner
}

func NewDispatchRunner(socketPath string) *DispatchRunner {
	native := NewContainerdRunner(socketPath, NativeRunProfile())
	python := NewContainerdRunner(socketPath, PythonRunProfile())
	java := NewContainerdRunner(socketPath, JavaRunProfile())

	return &DispatchRunner{
		runners: map[model.Language]Runner{
			model.LanguageC:      native,
			model.LanguageCPP:    native,
			model.LanguagePython: python,
			model.LanguageJava:   java,
		},
	}
}

func (d *DispatchRunner) Execute(ctx context.Context, req model.ExecuteRequest) (model.ExecuteResult, error) {
	r, ok := d.runners[req.Language]
	if !ok {
		msg := fmt.Sprintf("no runner registered for language %q", req.Language)
		return model.ExecuteResult{
			Verdict:   model.VerdictUKE,
			ExitCode:  -1,
			ExtraInfo: msg,
		}, errors.New(msg)
	}
	return r.Execute(ctx, req)
}
