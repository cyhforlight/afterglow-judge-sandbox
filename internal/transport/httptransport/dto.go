// Package httptransport provides HTTP transport layer DTOs and conversions.
package httptransport

import (
	"encoding/base64"
	"errors"
	"fmt"

	"afterglow-judge-sandbox/internal/model"
)

// ExecuteRequestDTO represents an HTTP execution request.
type ExecuteRequestDTO struct {
	ExecutableBase64 string `json:"executableBase64"`
	InputBase64      string `json:"inputBase64"`
	Language         string `json:"language"`
	TimeLimit        int    `json:"timeLimit"`   // milliseconds
	MemoryLimit      int    `json:"memoryLimit"` // megabytes
}

// ExecuteResponseDTO represents an HTTP execution response.
type ExecuteResponseDTO struct {
	Verdict    string `json:"verdict"`
	Stdout     string `json:"stdout"`
	TimeUsed   int    `json:"timeUsed"`   // milliseconds
	MemoryUsed int    `json:"memoryUsed"` // megabytes
	ExitCode   int    `json:"exitCode"`
	ExtraInfo  string `json:"extraInfo"`
}

// ErrorResponseDTO represents an HTTP error response.
type ErrorResponseDTO struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Details string `json:"details,omitempty"`
}

// DecodeExecutable decodes the base64 executable content.
func (dto *ExecuteRequestDTO) DecodeExecutable() ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(dto.ExecutableBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid executable base64: %w", err)
	}
	return data, nil
}

// DecodeInput decodes the base64 input content.
func (dto *ExecuteRequestDTO) DecodeInput() ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(dto.InputBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid input base64: %w", err)
	}
	return data, nil
}

// Validate checks if the request is valid.
func (dto *ExecuteRequestDTO) Validate() error {
	if dto.ExecutableBase64 == "" {
		return errors.New("executableBase64 is required")
	}
	if dto.Language == "" {
		return errors.New("language is required")
	}
	if dto.TimeLimit <= 0 {
		return errors.New("timeLimit must be positive")
	}
	if dto.MemoryLimit <= 0 {
		return errors.New("memoryLimit must be positive")
	}
	return nil
}

// ToExecuteResult converts a model.ExecuteResult to DTO.
func ToExecuteResult(result model.ExecuteResult) ExecuteResponseDTO {
	return ExecuteResponseDTO{
		Verdict:    result.Verdict.String(),
		Stdout:     result.Stdout,
		TimeUsed:   result.TimeUsed,
		MemoryUsed: result.MemoryUsed,
		ExitCode:   result.ExitCode,
		ExtraInfo:  result.ExtraInfo,
	}
}
