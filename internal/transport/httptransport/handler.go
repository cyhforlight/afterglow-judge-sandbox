package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/service"
	"afterglow-judge-sandbox/internal/storage"
)

// Handler handles HTTP requests for code execution.
type Handler struct {
	runner  service.Runner
	storage storage.Storage
	logger  *slog.Logger
	maxSize int64 // max request body size in bytes
}

// NewHandler creates a new HTTP handler.
func NewHandler(runner service.Runner, storage storage.Storage, logger *slog.Logger, maxSizeMB int) *Handler {
	return &Handler{
		runner:  runner,
		storage: storage,
		logger:  logger,
		maxSize: int64(maxSizeMB) * 1024 * 1024,
	}
}

// HandleExecute handles POST /v1/execute requests.
func (h *Handler) HandleExecute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, h.maxSize)

	// Parse request
	var req ExecuteRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	// Execute
	result, err := h.execute(ctx, &req)
	if err != nil {
		h.logger.Error("execution failed", "error", err)
		h.writeError(w, http.StatusInternalServerError, "EXECUTION_FAILED", err.Error())
		return
	}

	// Return result
	h.writeJSON(w, http.StatusOK, ToExecuteResult(result))
}

// HandleHealth handles GET /health requests.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check if runner is healthy
	if err := h.runner.PreflightCheck(ctx); err != nil {
		h.writeError(w, http.StatusServiceUnavailable, "UNHEALTHY", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

// execute performs the actual execution.
func (h *Handler) execute(ctx context.Context, dto *ExecuteRequestDTO) (model.ExecuteResult, error) {
	// Decode files
	execData, err := dto.DecodeExecutable()
	if err != nil {
		return model.ExecuteResult{}, err
	}

	inputData, err := dto.DecodeInput()
	if err != nil {
		return model.ExecuteResult{}, err
	}

	// Parse language
	lang, err := model.ParseLanguage(dto.Language)
	if err != nil {
		return model.ExecuteResult{}, err
	}

	// Store executable
	execKey, err := h.storage.Store(ctx, "executable", bytes.NewReader(execData))
	if err != nil {
		return model.ExecuteResult{}, fmt.Errorf("failed to store executable: %w", err)
	}

	execPath, execCleanup, err := h.storage.Get(ctx, execKey)
	if err != nil {
		return model.ExecuteResult{}, fmt.Errorf("failed to get executable: %w", err)
	}
	defer execCleanup()

	// Store input
	inputKey, err := h.storage.Store(ctx, "input.txt", bytes.NewReader(inputData))
	if err != nil {
		return model.ExecuteResult{}, fmt.Errorf("failed to store input: %w", err)
	}

	inputPath, inputCleanup, err := h.storage.Get(ctx, inputKey)
	if err != nil {
		return model.ExecuteResult{}, fmt.Errorf("failed to get input: %w", err)
	}
	defer inputCleanup()

	// Build execution request
	execReq := model.ExecuteRequest{
		ExecutablePath: execPath,
		InputPath:      inputPath,
		Language:       lang,
		TimeLimit:      dto.TimeLimit,
		MemoryLimit:    dto.MemoryLimit,
	}

	// Execute
	result := h.runner.Execute(ctx, execReq)

	return result, nil
}

// writeJSON writes a JSON response.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// writeError writes an error response.
func (h *Handler) writeError(w http.ResponseWriter, status int, code, details string) {
	h.writeJSON(w, status, ErrorResponseDTO{
		Error:   http.StatusText(status),
		Code:    code,
		Details: details,
	})
}
