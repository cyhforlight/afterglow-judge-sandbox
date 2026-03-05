package httptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"afterglow-judge-sandbox/internal/service"
	"afterglow-judge-sandbox/internal/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compileCppStatic compiles C++ code to a fully static binary.
// Uses -static for complete static linking (no dynamic dependencies).
func compileCppStatic(t *testing.T, code string) []byte {
	t.Helper()

	// Check if g++ is available
	if _, err := exec.LookPath("g++"); err != nil {
		t.Skip("g++ not available, skipping C++ test")
	}

	// Create temp directory for compilation
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "program.cpp")
	binFile := filepath.Join(tmpDir, "program")

	// Write source code
	err := os.WriteFile(srcFile, []byte(code), 0644)
	require.NoError(t, err)

	// Compile with full static linking
	// -static: fully static binary (no dynamic dependencies)
	// -O2: optimization level 2
	cmd := exec.Command("g++",
		"-o", binFile,
		"-static",
		"-O2",
		srcFile,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to compile C++ code: %v\nStderr: %s", err, stderr.String())
	}

	// Read compiled binary
	binary, err := os.ReadFile(binFile)
	require.NoError(t, err)

	return binary
}

// TestE2E_HTTP_CPP_OK tests C++ program execution via HTTP.
func TestE2E_HTTP_CPP_OK(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("E2E tests require root privileges")
	}

	ctx := context.Background()
	runner := service.NewContainerdRunner("/run/containerd/containerd.sock")

	if err := runner.PreflightCheck(ctx); err != nil {
		t.Skipf("Containerd not available: %v", err)
	}

	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	// Compile C++ code to static binary
	cppCode := `#include <iostream>
int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}`

	executable := compileCppStatic(t, cppCode)

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: base64.StdEncoding.EncodeToString(executable),
		InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
		Language:         "C++",
		TimeLimit:        5000,
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
	assert.Contains(t, resp.Stdout, "Hello, World!")
	assert.Equal(t, 0, resp.ExitCode)
}

// TestE2E_HTTP_CPP_TLE tests time limit exceeded via HTTP.
func TestE2E_HTTP_CPP_TLE(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("E2E tests require root privileges")
	}

	ctx := context.Background()
	runner := service.NewContainerdRunner("/run/containerd/containerd.sock")

	if err := runner.PreflightCheck(ctx); err != nil {
		t.Skipf("Containerd not available: %v", err)
	}

	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	cppCode := `#include <iostream>
int main() {
    while(true) {}
    return 0;
}`

	executable := compileCppStatic(t, cppCode)

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: base64.StdEncoding.EncodeToString(executable),
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

	assert.Equal(t, "TimeLimitExceeded", resp.Verdict)
}

// TestE2E_HTTP_Python_OK tests Python program execution via HTTP.
func TestE2E_HTTP_Python_OK(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("E2E tests require root privileges")
	}

	ctx := context.Background()
	runner := service.NewContainerdRunner("/run/containerd/containerd.sock")

	if err := runner.PreflightCheck(ctx); err != nil {
		t.Skipf("Containerd not available: %v", err)
	}

	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	pythonCode := `print("Hello from Python!")`

	reqBody := ExecuteRequestDTO{
		ExecutableBase64: base64.StdEncoding.EncodeToString([]byte(pythonCode)),
		InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
		Language:         "Python",
		TimeLimit:        5000,
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
	assert.Contains(t, resp.Stdout, "Hello from Python!")
}

// TestE2E_HTTP_ConcurrentExecutions tests concurrent HTTP requests.
func TestE2E_HTTP_ConcurrentExecutions(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("E2E tests require root privileges")
	}

	ctx := context.Background()
	runner := service.NewContainerdRunner("/run/containerd/containerd.sock")

	if err := runner.PreflightCheck(ctx); err != nil {
		t.Skipf("Containerd not available: %v", err)
	}

	stor, err := storage.NewLocalStorage("")
	require.NoError(t, err)

	handler := NewHandler(runner, stor, slog.Default(), 256)

	cppCode := `#include <iostream>
int main() {
    std::cout << "OK" << std::endl;
    return 0;
}`

	executable := compileCppStatic(t, cppCode)

	const numRequests = 3
	results := make(chan string, numRequests)

	for range numRequests {
		go func() {
			reqBody := ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString(executable),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        5000,
				MemoryLimit:      256,
			}

			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleExecute(w, req)

			var resp ExecuteResponseDTO
			_ = json.NewDecoder(w.Body).Decode(&resp)
			results <- resp.Verdict
		}()
	}

	for range numRequests {
		select {
		case verdict := <-results:
			assert.Equal(t, "OK", verdict)
		case <-time.After(30 * time.Second):
			t.Fatal("timeout waiting for concurrent execution")
		}
	}
}
