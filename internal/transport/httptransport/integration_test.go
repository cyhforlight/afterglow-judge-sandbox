package httptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"afterglow-judge-sandbox/internal/config"
	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_HTTPServer_FullLifecycle tests complete server lifecycle.
func TestIntegration_HTTPServer_FullLifecycle(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
		EnableAuth:     false,
	}

	runner := &mockRunner{
		result: model.ExecuteResult{
			Verdict: model.VerdictOK,
		},
	}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)
	logger := slog.Default()

	server := NewServer(cfg, runner, stor, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Server should be running
	assert.NotNil(t, server.httpServer)

	// Cancel to trigger shutdown
	cancel()

	// Wait for shutdown
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

// TestIntegration_ExecuteEndpoint_Success tests full execute flow.
func TestIntegration_ExecuteEndpoint_Success(t *testing.T) {
	runner := &mockRunner{
		result: model.ExecuteResult{
			Verdict:    model.VerdictOK,
			Stdout:     "Hello, World!\n",
			TimeUsed:   100,
			MemoryUsed: 10,
			ExitCode:   0,
		},
	}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	// Create test request
	reqBody := ExecuteRequestDTO{
		ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\necho 'Hello, World!'")),
		InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
		Language:         "C++",
		TimeLimit:        1000,
		MemoryLimit:      256,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleExecute(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp ExecuteResponseDTO
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "OK", resp.Verdict)
	assert.Equal(t, "Hello, World!\n", resp.Stdout)
	assert.Equal(t, 100, resp.TimeUsed)
	assert.Equal(t, 10, resp.MemoryUsed)
}

// TestIntegration_ExecuteEndpoint_AllVerdicts tests all verdict types.
func TestIntegration_ExecuteEndpoint_AllVerdicts(t *testing.T) {
	tests := []struct {
		name           string
		verdict        model.Verdict
		expectedString string
	}{
		{"OK", model.VerdictOK, "OK"},
		{"TLE", model.VerdictTLE, "TimeLimitExceeded"},
		{"MLE", model.VerdictMLE, "MemoryLimitExceeded"},
		{"OLE", model.VerdictOLE, "OutputLimitExceeded"},
		{"RE", model.VerdictRE, "RuntimeError"},
		{"UKE", model.VerdictUKE, "UnknownError"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &mockRunner{
				result: model.ExecuteResult{
					Verdict: tt.verdict,
				},
			}
			stor, err := storage.NewLocalStorage("")
			require.NoError(t, err)

			handler := NewHandler(runner, stor, slog.Default(), 256)

			reqBody := ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        1000,
				MemoryLimit:      256,
			}

			body, err := json.Marshal(reqBody)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleExecute(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var resp ExecuteResponseDTO
			err = json.NewDecoder(w.Body).Decode(&resp)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedString, resp.Verdict)
		})
	}
}

// TestIntegration_HealthEndpoint tests health check endpoint.
func TestIntegration_HealthEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		preflightErr error
		expectedCode int
	}{
		{
			name:         "healthy",
			preflightErr: nil,
			expectedCode: http.StatusOK,
		},
		{
			name:         "unhealthy",
			preflightErr: assert.AnError,
			expectedCode: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &mockRunner{
				preflightErr: tt.preflightErr,
			}
			stor, err := storage.NewLocalStorage("")
			require.NoError(t, err)

			handler := NewHandler(runner, stor, slog.Default(), 256)

			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			w := httptest.NewRecorder()

			handler.HandleHealth(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)
		})
	}
}

// TestIntegration_MiddlewareChain_LoggingAndRecovery tests middleware integration.
func TestIntegration_MiddlewareChain_LoggingAndRecovery(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	// Handler that panics
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic")
	})

	// Apply middleware chain
	wrapped := RecoveryMiddleware(logger)(handler)
	wrapped = LoggingMiddleware(logger)(wrapped)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Should recover from panic
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Should log both the request and the panic
	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "http request")
	assert.Contains(t, logOutput, "panic recovered")
}

// TestIntegration_AuthMiddleware_ValidToken tests auth middleware integration.
func TestIntegration_AuthMiddleware_ValidToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrapped := AuthMiddleware([]string{"valid-key"})(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-key")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

// TestIntegration_AuthMiddleware_InvalidToken tests auth rejection.
func TestIntegration_AuthMiddleware_InvalidToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrapped := AuthMiddleware([]string{"valid-key"})(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-key")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid API key")
}

// TestIntegration_CORSMiddleware_AllowedOrigin tests CORS integration.
func TestIntegration_CORSMiddleware_AllowedOrigin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := CORSMiddleware([]string{"https://example.com"})(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

// TestIntegration_CORSMiddleware_PreflightRequest tests CORS preflight.
func TestIntegration_CORSMiddleware_PreflightRequest(t *testing.T) {
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not be called for OPTIONS")
	})

	wrapped := CORSMiddleware([]string{"*"})(handler)

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
}

// TestIntegration_TimeoutMiddleware_RequestTimeout tests timeout handling.
func TestIntegration_TimeoutMiddleware_RequestTimeout(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if context has timeout
		deadline, ok := r.Context().Deadline()
		assert.True(t, ok, "context should have deadline")
		assert.WithinDuration(t, time.Now().Add(100*time.Millisecond), deadline, 50*time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	wrapped := TimeoutMiddleware(100 * time.Millisecond)(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestIntegration_InvalidJSON tests invalid JSON handling.
func TestIntegration_InvalidJSON(t *testing.T) {
	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleExecute(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp ErrorResponseDTO
	err = json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "INVALID_REQUEST", errResp.Code)
}

// TestIntegration_MissingFields tests validation.
func TestIntegration_MissingFields(t *testing.T) {
	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: "", // Missing
		InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
		Language:         "C++",
		TimeLimit:        1000,
		MemoryLimit:      256,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleExecute(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestIntegration_RequestBodyTooLarge tests body size limit.
func TestIntegration_RequestBodyTooLarge(t *testing.T) {
	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	// Very small max size
	handler := NewHandler(runner, stor, slog.Default(), 0)
	handler.maxSize = 10

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("very long executable content that exceeds limit")),
		InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
		Language:         "C++",
		TimeLimit:        1000,
		MemoryLimit:      256,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleExecute(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestIntegration_ServerPanic_Recovery tests panic recovery in real server.
func TestIntegration_ServerPanic_Recovery(t *testing.T) {
	// Create a runner that panics
	runner := &panicRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	// Wrap with recovery middleware
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	wrapped := RecoveryMiddleware(logger)(http.HandlerFunc(handler.HandleExecute))

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
		InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
		Language:         "C++",
		TimeLimit:        1000,
		MemoryLimit:      256,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Should recover from panic
	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, logBuf.String(), "panic recovered")
}

// TestIntegration_ConcurrentRequests tests concurrent request handling.
func TestIntegration_ConcurrentRequests(t *testing.T) {
	runner := &mockRunner{
		result: model.ExecuteResult{
			Verdict: model.VerdictOK,
		},
	}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	const numRequests = 10
	results := make(chan int, numRequests)

	for range numRequests {
		go func() {
			reqBody := ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        1000,
				MemoryLimit:      256,
			}

			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleExecute(w, req)
			results <- w.Code
		}()
	}

	// Collect results
	for range numRequests {
		code := <-results
		assert.Equal(t, http.StatusOK, code)
	}
}

// panicRunner is a mock runner that panics.
type panicRunner struct{}

func (p *panicRunner) PreflightCheck(_ context.Context) error {
	return nil
}

func (p *panicRunner) Execute(_ context.Context, _ model.ExecuteRequest) model.ExecuteResult {
	panic("intentional panic for testing")
}
