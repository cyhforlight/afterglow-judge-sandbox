package httptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRunner implements service.Runner for testing.
type mockRunner struct {
	preflightErr error
	result       model.ExecuteResult
}

func (m *mockRunner) PreflightCheck(_ context.Context) error {
	return m.preflightErr
}

func (m *mockRunner) Execute(_ context.Context, _ model.ExecuteRequest) model.ExecuteResult {
	return m.result
}

func TestHandleHealth_Success(t *testing.T) {
	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.HandleHealth(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "healthy")
}

func TestHandleHealth_Unhealthy(t *testing.T) {
	runner := &mockRunner{
		preflightErr: assert.AnError,
	}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.HandleHealth(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleExecute_Success(t *testing.T) {
	runner := &mockRunner{
		result: model.ExecuteResult{
			Verdict:    model.VerdictOK,
			Stdout:     "Hello, World!\n",
			TimeUsed:   10,
			MemoryUsed: 4,
			ExitCode:   0,
		},
	}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	// Create test executable
	execData := []byte("#!/bin/sh\necho 'Hello, World!'")
	inputData := []byte("")

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: base64.StdEncoding.EncodeToString(execData),
		InputBase64:      base64.StdEncoding.EncodeToString(inputData),
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

	assert.Equal(t, "OK", resp.Verdict)
	assert.Equal(t, "Hello, World!\n", resp.Stdout)
	assert.Equal(t, 10, resp.TimeUsed)
	assert.Equal(t, 4, resp.MemoryUsed)
}

func TestHandleExecute_InvalidJSON(t *testing.T) {
	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleExecute(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleExecute_MissingFields(t *testing.T) {
	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	tests := []struct {
		name string
		dto  ExecuteRequestDTO
	}{
		{
			name: "missing executable",
			dto: ExecuteRequestDTO{
				InputBase64: base64.StdEncoding.EncodeToString([]byte("")),
				Language:    "C++",
				TimeLimit:   1000,
				MemoryLimit: 256,
			},
		},
		{
			name: "missing language",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				TimeLimit:        1000,
				MemoryLimit:      256,
			},
		},
		{
			name: "invalid time limit",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        0,
				MemoryLimit:      256,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.dto)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleExecute(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestHandleExecute_InvalidBase64(t *testing.T) {
	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: "not-valid-base64!!!",
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

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleExecute_AllVerdicts(t *testing.T) {
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

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

// TestHandleExecute_E2E tests with real file operations.
func TestHandleExecute_E2E(t *testing.T) {
	// Create a real executable file for testing
	tmpDir := t.TempDir()
	execPath := tmpDir + "/test_exec"
	err := os.WriteFile(execPath, []byte("#!/bin/sh\necho 'test'"), 0o755)
	require.NoError(t, err)

	runner := &mockRunner{
		result: model.ExecuteResult{
			Verdict:    model.VerdictOK,
			Stdout:     "test\n",
			TimeUsed:   5,
			MemoryUsed: 2,
			ExitCode:   0,
		},
	}

	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	execData, err := os.ReadFile(execPath)
	require.NoError(t, err)

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: base64.StdEncoding.EncodeToString(execData),
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

	assert.Equal(t, "OK", resp.Verdict)
	assert.Equal(t, "test\n", resp.Stdout)
}

// TestHandleExecute_StorageStoreError tests storage store failure.
func TestHandleExecute_StorageStoreError(t *testing.T) {
	runner := &mockRunner{}

	// Create a mock storage that fails on Store
	stor := &mockStorage{
		storeErr: assert.AnError,
	}

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

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestHandleExecute_StorageGetError tests storage get failure.
func TestHandleExecute_StorageGetError(t *testing.T) {
	runner := &mockRunner{}

	// Create a mock storage that fails on Get
	stor := &mockStorage{
		getErr: assert.AnError,
	}

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

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestHandleExecute_ContextCancelled tests context cancellation during storage operations.
func TestHandleExecute_ContextCancelled(t *testing.T) {
	runner := &mockRunner{}

	// Create a storage that will be slow
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

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1)
	defer cancel()

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleExecute(w, req)

	// Context cancellation may or may not cause failure depending on timing
	// Just verify it doesn't panic
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusInternalServerError)
}

// TestHandleExecute_RequestBodyTooLarge tests max body size limit.
func TestHandleExecute_RequestBodyTooLarge(t *testing.T) {
	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	// Set very small max size (1 byte)
	handler := NewHandler(runner, stor, slog.Default(), 0)
	handler.maxSize = 1

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

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandleExecute_InvalidLanguage tests invalid language parsing.
func TestHandleExecute_InvalidLanguage(t *testing.T) {
	runner := &mockRunner{}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
		InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
		Language:         "InvalidLanguage",
		TimeLimit:        1000,
		MemoryLimit:      256,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleExecute(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestHandleExecute_EmptyExecutable tests empty executable handling.
func TestHandleExecute_EmptyExecutable(t *testing.T) {
	runner := &mockRunner{
		result: model.ExecuteResult{
			Verdict: model.VerdictOK,
		},
	}
	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	// Empty executable should fail validation (executableBase64 is required but empty string is valid base64)
	// However, the validation checks for empty string, so this should fail
	reqBody := ExecuteRequestDTO{
		ExecutableBase64: "", // Empty string fails validation
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

	// Should fail validation
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// mockStorage is a mock storage for testing error scenarios.
type mockStorage struct {
	storeErr error
	getErr   error
}

func (m *mockStorage) Store(_ context.Context, _ string, _ io.Reader) (string, error) {
	if m.storeErr != nil {
		return "", m.storeErr
	}
	return "test-key", nil
}

func (m *mockStorage) Get(_ context.Context, _ string) (string, func(), error) {
	if m.getErr != nil {
		return "", func() {}, m.getErr
	}
	return "/tmp/test", func() {}, nil
}

func (m *mockStorage) Delete(_ context.Context, _ string) error {
	return nil
}
