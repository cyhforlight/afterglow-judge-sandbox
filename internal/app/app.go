package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"afterglow-judge-sandbox/internal/cli"
	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/service"
)

type App struct {
	runner service.Runner
	out    io.Writer
	errOut io.Writer
}

func New(runner service.Runner, out, errOut io.Writer) *App {
	return &App{
		runner: runner,
		out:    out,
		errOut: errOut,
	}
}

func (a *App) Run(ctx context.Context, args []string) int {
	req, err := cli.ParseArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(a.out, cli.Usage())
			return 0
		}
		_, _ = fmt.Fprintf(a.errOut, "invalid arguments: %v\n\n%s\n", err, cli.Usage())
		return 2
	}

	if err := a.runner.PreflightCheck(ctx); err != nil {
		_, _ = fmt.Fprintf(a.errOut, "environment check failed: %v\n", err)
		return 1
	}

	result := a.runner.Execute(ctx, req)

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(a.errOut, "failed to encode result: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(a.out, string(encoded))
	if result.Verdict == model.VerdictUKE {
		return 1
	}
	return 0
}
