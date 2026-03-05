package httptransport

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"afterglow-judge-sandbox/internal/config"

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
	}

	server := NewServer(cfg, &mockJudgeService{}, slog.Default())

	assert.NotNil(t, server)
	assert.NotNil(t, server.httpServer)
	assert.NotNil(t, server.handler)
	assert.Equal(t, "localhost:8080", server.Addr())
}

func TestServer_StartStop(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
	}

	server := NewServer(cfg, &mockJudgeService{}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errChan:
		if err != nil && strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("listening sockets are not permitted in this sandbox")
		}
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
	}

	server := NewServer(cfg, &mockJudgeService{}, slog.Default())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = server.Start(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()

	err := server.Stop(stopCtx)
	assert.NoError(t, err)
}

func TestServer_Addr(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "127.0.0.1",
		HTTPPort:       3000,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
	}

	server := NewServer(cfg, &mockJudgeService{}, slog.Default())
	assert.Equal(t, "127.0.0.1:3000", server.Addr())
}
