package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"afterglow-judge-sandbox/internal/cli"
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
			fmt.Fprintln(a.out, cli.Usage())
			return 0
		}
		fmt.Fprintf(a.errOut, "invalid arguments: %v\n\n%s\n", err, cli.Usage())
		return 2
	}

	result, err := a.runner.Execute(ctx, req)
	if err != nil {
		fmt.Fprintf(a.errOut, "runner error: %v\n", err)
		return 1
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(a.errOut, "failed to encode result: %v\n", err)
		return 1
	}
	fmt.Fprintln(a.out, string(encoded))
	return 0
}
