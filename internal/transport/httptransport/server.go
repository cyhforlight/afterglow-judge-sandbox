package httptransport

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"afterglow-judge-sandbox/internal/config"
	"afterglow-judge-sandbox/internal/service"
	"afterglow-judge-sandbox/internal/storage"
)

// Server implements the HTTP transport layer.
type Server struct {
	httpServer *http.Server
	handler    *Handler
	logger     *slog.Logger
	addr       string
}

// NewServer creates a new HTTP server.
func NewServer(
	cfg *config.Config,
	runner service.Runner,
	storage storage.Storage,
	logger *slog.Logger,
) *Server {
	handler := NewHandler(runner, storage, logger, cfg.MaxInputSizeMB)

	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("POST /v1/execute", handler.HandleExecute)
	mux.HandleFunc("GET /health", handler.HandleHealth)

	// Build middleware chain
	var finalHandler http.Handler = mux

	// Apply middleware (from innermost to outermost)
	finalHandler = CORSMiddleware(cfg.AllowedOrigins)(finalHandler)

	if cfg.EnableAuth {
		finalHandler = AuthMiddleware(cfg.APIKeys)(finalHandler)
	}

	finalHandler = TimeoutMiddleware(cfg.ReadTimeout)(finalHandler)
	finalHandler = LoggingMiddleware(logger)(finalHandler)
	finalHandler = RecoveryMiddleware(logger)(finalHandler)

	httpServer := &http.Server{
		Addr:         cfg.Addr(),
		Handler:      finalHandler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return &Server{
		httpServer: httpServer,
		handler:    handler,
		logger:     logger,
		addr:       cfg.Addr(),
	}
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("starting HTTP server", "addr", s.addr)

	errChan := make(chan error, 1)

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		return s.Stop(context.Background())
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	}
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("stopping HTTP server")

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	s.logger.Info("HTTP server stopped")
	return nil
}

// Addr returns the server's listening address.
func (s *Server) Addr() string {
	return s.addr
}
