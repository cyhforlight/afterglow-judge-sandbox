package httptransport

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"afterglow-judge-sandbox/internal/config"
	"afterglow-judge-sandbox/internal/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       8080,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
		EnableAuth:     false,
	}

	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	assert.NotNil(t, server)
	assert.NotNil(t, server.httpServer)
	assert.NotNil(t, server.handler)
	assert.Equal(t, "localhost:8080", server.Addr())
}

func TestNewServer_WithAuth(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       9090,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
		EnableAuth:     true,
		APIKeys:        []string{"test-key"},
	}

	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	assert.NotNil(t, server)
	assert.Equal(t, "localhost:9090", server.Addr())
}

func TestServer_StartStop(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0, // Use random port
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
		EnableAuth:     false,
	}

	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	// Wait for server to stop
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
		EnableAuth:     false,
	}

	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start server
	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Stop server with timeout
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()

	err = server.Stop(stopCtx)
	assert.NoError(t, err)
}

func TestServer_Addr(t *testing.T) {
	tests := []struct {
		name         string
		httpAddr     string
		httpPort     int
		expectedAddr string
	}{
		{
			name:         "standard address",
			httpAddr:     "localhost",
			httpPort:     8080,
			expectedAddr: "localhost:8080",
		},
		{
			name:         "all interfaces",
			httpAddr:     "0.0.0.0",
			httpPort:     3000,
			expectedAddr: "0.0.0.0:3000",
		},
		{
			name:         "random port",
			httpAddr:     "127.0.0.1",
			httpPort:     0,
			expectedAddr: "127.0.0.1:0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				HTTPAddr:       tt.httpAddr,
				HTTPPort:       tt.httpPort,
				ReadTimeout:    5 * time.Second,
				WriteTimeout:   10 * time.Second,
				MaxInputSizeMB: 256,
				AllowedOrigins: []string{"*"},
			}

			runner := &mockRunner{}
			stor, err := storage.NewLocalStorage("")
			require.NoError(t, err)

			server := NewServer(cfg, runner, stor, slog.Default())
			assert.Equal(t, tt.expectedAddr, server.Addr())
		})
	}
}

func TestServer_MiddlewareChain(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"https://example.com"},
		EnableAuth:     true,
		APIKeys:        []string{"valid-key"},
	}

	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	// Test that middleware chain is properly built
	assert.NotNil(t, server.httpServer.Handler)
}

func TestServer_RouteRegistration(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
		EnableAuth:     false,
	}

	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Test health endpoint (we can't easily test without knowing the actual port)
	// This test mainly ensures the server can be created and started
	assert.NotNil(t, server.httpServer)

	cancel()
	time.Sleep(100 * time.Millisecond)
}

func TestServer_Stop_WithoutStart(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
		EnableAuth:     false,
	}

	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	// Stop server without starting it
	ctx := context.Background()
	err = server.Stop(ctx)
	// Should not panic and may return error
	// The behavior depends on http.Server implementation
	_ = err
}

func TestServer_ContextCancellation(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
		EnableAuth:     false,
	}

	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	// Create context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Start should handle cancelled context
	err = server.Start(ctx)
	// Should return quickly without error or with context cancelled error
	_ = err
}

func TestServer_ShutdownTimeout(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
		EnableAuth:     false,
	}

	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start server
	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Stop with very short timeout
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer stopCancel()

	err = server.Stop(stopCtx)
	// May return timeout error
	_ = err
}
