package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"afterglow-judge-sandbox/internal/config"
	"afterglow-judge-sandbox/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_HTTPServer_FullLifecycle(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr:       "localhost",
		HTTPPort:       0,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxInputSizeMB: 256,
		AllowedOrigins: []string{"*"},
	}

	judge := &mockJudgeService{}
	server := NewServer(cfg, judge, slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	assert.NotNil(t, server.httpServer)

	cancel()
	select {
	case err := <-errChan:
		if err != nil && strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("listening sockets are not permitted in this sandbox")
		}
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestIntegration_ExecuteEndpoint_Success(t *testing.T) {
	judge := &mockJudgeService{result: model.JudgeResult{
		Verdict: model.VerdictOK,
		Compile: model.CompileResult{Succeeded: true, Log: ""},
		Cases: []model.JudgeCaseResult{
			{Name: "case-1", Verdict: model.VerdictOK, Stdout: "42\n"},
		},
		PassedCount: 1,
		TotalCount:  1,
	}}

	handler := NewHandler(judge, slog.Default(), 256)
	body := JudgeRequestDTO{
		SourceCode:  "print(42)",
		Language:    "Python",
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases:   []JudgeTestCaseDTO{{Name: "case-1", ExpectedOutputText: "42\n"}},
	}

	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleExecute(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp JudgeResponseDTO
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "OK", resp.Verdict)
	assert.Equal(t, 1, resp.PassedCount)
}

func TestIntegration_ExecuteEndpoint_CompileError(t *testing.T) {
	judge := &mockJudgeService{result: model.JudgeResult{
		Verdict: model.VerdictCE,
		Compile: model.CompileResult{Succeeded: false, Log: "compile failed"},
		Cases:   []model.JudgeCaseResult{},
	}}

	handler := NewHandler(judge, slog.Default(), 256)
	body := JudgeRequestDTO{
		SourceCode:  "bad code",
		Language:    "C++",
		TimeLimit:   1000,
		MemoryLimit: 128,
		TestCases:   []JudgeTestCaseDTO{{Name: "case-1", ExpectedOutputText: "42\n"}},
	}

	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	handler.HandleExecute(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "CompileError")
}

func TestIntegration_HealthEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		preflightErr error
		expectedCode int
	}{
		{name: "healthy", expectedCode: http.StatusOK},
		{name: "unhealthy", preflightErr: assert.AnError, expectedCode: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewHandler(&mockJudgeService{preflightErr: tt.preflightErr}, slog.Default(), 256)
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			w := httptest.NewRecorder()
			handler.HandleHealth(w, req)
			assert.Equal(t, tt.expectedCode, w.Code)
		})
	}
}

func TestIntegration_MiddlewareChain_LoggingAndRecovery(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic")
	})

	wrapped := RecoveryMiddleware(logger)(handler)
	wrapped = LoggingMiddleware(logger)(wrapped)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "http request")
	assert.Contains(t, logOutput, "panic recovered")
}
