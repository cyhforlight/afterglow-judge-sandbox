// Package main provides the HTTP server entry point for afterglow-judge-sandbox.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"afterglow-judge-sandbox/internal/concurrency"
	"afterglow-judge-sandbox/internal/config"
	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/service"
	"afterglow-judge-sandbox/internal/storage"
	"afterglow-judge-sandbox/internal/transport/httptransport"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Setup logger
	logger := setupLogger(cfg.LogLevel)

	logger.Info("starting sandbox server",
		"addr", cfg.Addr(),
		"max_concurrent", cfg.MaxConcurrentExecutions,
	)

	// Initialize components
	runner, stor, err := initializeComponents(cfg)
	if err != nil {
		logger.Error("initialization failed", "error", err)
		os.Exit(1)
	}

	// Create HTTP server
	server := httptransport.NewServer(cfg, runner, stor, logger)

	// Run server with graceful shutdown
	if err := runServer(server, cfg, logger); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped gracefully")
}

// setupLogger creates a configured logger.
func setupLogger(logLevel string) *slog.Logger {
	level := slog.LevelInfo
	if logLevel == "debug" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
}

// initializeComponents creates storage, limiter, and runner.
func initializeComponents(cfg *config.Config) (service.Runner, storage.Storage, error) {
	// Create storage
	stor, err := storage.NewLocalStorage("")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create execution limiter
	limiter := concurrency.NewExecutionLimiter(int64(cfg.MaxConcurrentExecutions))

	// Create base runner
	baseRunner := service.NewContainerdRunner(cfg.ContainerdSocket)

	// Wrap runner with limiter
	runner := &limitedRunner{
		runner:  baseRunner,
		limiter: limiter,
	}

	// Preflight check
	ctx := context.Background()
	if err := runner.PreflightCheck(ctx); err != nil {
		return nil, nil, fmt.Errorf("preflight check failed: %w", err)
	}

	return runner, stor, nil
}

// runServer starts the server and handles graceful shutdown.
func runServer(server *httptransport.Server, cfg *config.Config, logger *slog.Logger) error {
	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	errChan := make(chan error, 1)
	go func() {
		if err := server.Start(serverCtx); err != nil {
			errChan <- err
		}
	}()

	// Wait for signal or error
	select {
	case sig := <-sigChan:
		logger.Info("received signal", "signal", sig)
		serverCancel()

		// Graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()

		return server.Stop(shutdownCtx)

	case err := <-errChan:
		return err
	}
}

// limitedRunner wraps a runner with concurrency limiting.
type limitedRunner struct {
	runner  service.Runner
	limiter *concurrency.ExecutionLimiter
}

func (r *limitedRunner) PreflightCheck(ctx context.Context) error {
	return r.runner.PreflightCheck(ctx)
}

func (r *limitedRunner) Execute(ctx context.Context, req model.ExecuteRequest) model.ExecuteResult {
	var result model.ExecuteResult

	err := r.limiter.WithLimit(ctx, func() error {
		result = r.runner.Execute(ctx, req)
		return nil
	})

	if err != nil {
		// Context cancelled or timeout
		return model.ExecuteResult{
			Verdict:   model.VerdictUKE,
			ExtraInfo: err.Error(),
		}
	}

	return result
}
