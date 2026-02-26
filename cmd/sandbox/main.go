package main

import (
	"context"
	"os"

	"afterglow-judge-sandbox/internal/app"
	"afterglow-judge-sandbox/internal/service"
)

func main() {
	runner := service.NewDispatchRunner(os.Getenv("CONTAINERD_SOCKET"))
	application := app.New(runner, os.Stdout, os.Stderr)
	os.Exit(application.Run(context.Background(), os.Args[1:]))
}
