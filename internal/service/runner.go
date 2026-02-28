package service

import (
	"context"

	"afterglow-judge-sandbox/internal/model"
)

// Runner executes a program inside a sandboxed container.
type Runner interface {
	PreflightCheck(ctx context.Context) error
	Execute(ctx context.Context, req model.ExecuteRequest) model.ExecuteResult
}
