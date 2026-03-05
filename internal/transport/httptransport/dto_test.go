package httptransport

import (
	"encoding/base64"
	"strings"
	"testing"

	"afterglow-judge-sandbox/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecuteRequestDTO_Validate tests the validation logic.
func TestExecuteRequestDTO_Validate(t *testing.T) {
	tests := []struct {
		name    string
		dto     ExecuteRequestDTO
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        1000,
				MemoryLimit:      256,
			},
			wantErr: false,
		},
		{
			name: "missing executable",
			dto: ExecuteRequestDTO{
				ExecutableBase64: "",
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        1000,
				MemoryLimit:      256,
			},
			wantErr: true,
			errMsg:  "executableBase64 is required",
		},
		{
			name: "missing language",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "",
				TimeLimit:        1000,
				MemoryLimit:      256,
			},
			wantErr: true,
			errMsg:  "language is required",
		},
		{
			name: "zero time limit",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        0,
				MemoryLimit:      256,
			},
			wantErr: true,
			errMsg:  "timeLimit must be positive",
		},
		{
			name: "negative time limit",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        -100,
				MemoryLimit:      256,
			},
			wantErr: true,
			errMsg:  "timeLimit must be positive",
		},
		{
			name: "zero memory limit",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        1000,
				MemoryLimit:      0,
			},
			wantErr: true,
			errMsg:  "memoryLimit must be positive",
		},
		{
			name: "negative memory limit",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      base64.StdEncoding.EncodeToString([]byte("")),
				Language:         "C++",
				TimeLimit:        1000,
				MemoryLimit:      -256,
			},
			wantErr: true,
			errMsg:  "memoryLimit must be positive",
		},
		{
			name: "empty input allowed",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("test")),
				InputBase64:      "",
				Language:         "C++",
				TimeLimit:        1000,
				MemoryLimit:      256,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dto.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestExecuteRequestDTO_DecodeExecutable tests executable decoding.
func TestExecuteRequestDTO_DecodeExecutable(t *testing.T) {
	tests := []struct {
		name    string
		dto     ExecuteRequestDTO
		want    []byte
		wantErr bool
	}{
		{
			name: "valid base64",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\necho 'hello'")),
			},
			want:    []byte("#!/bin/sh\necho 'hello'"),
			wantErr: false,
		},
		{
			name: "invalid base64",
			dto: ExecuteRequestDTO{
				ExecutableBase64: "not-valid-base64!!!",
			},
			wantErr: true,
		},
		{
			name: "empty string",
			dto: ExecuteRequestDTO{
				ExecutableBase64: "",
			},
			want:    []byte{},
			wantErr: false,
		},
		{
			name: "large data",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", 10000))),
			},
			want:    []byte(strings.Repeat("A", 10000)),
			wantErr: false,
		},
		{
			name: "binary data",
			dto: ExecuteRequestDTO{
				ExecutableBase64: base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0xFF}),
			},
			want:    []byte{0x00, 0x01, 0x02, 0xFF},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.dto.DecodeExecutable()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid executable base64")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestExecuteRequestDTO_DecodeInput tests input decoding.
func TestExecuteRequestDTO_DecodeInput(t *testing.T) {
	tests := []struct {
		name    string
		dto     ExecuteRequestDTO
		want    []byte
		wantErr bool
	}{
		{
			name: "valid base64",
			dto: ExecuteRequestDTO{
				InputBase64: base64.StdEncoding.EncodeToString([]byte("test input\n123")),
			},
			want:    []byte("test input\n123"),
			wantErr: false,
		},
		{
			name: "invalid base64",
			dto: ExecuteRequestDTO{
				InputBase64: "invalid!!!base64",
			},
			wantErr: true,
		},
		{
			name: "empty string",
			dto: ExecuteRequestDTO{
				InputBase64: "",
			},
			want:    []byte{},
			wantErr: false,
		},
		{
			name: "large input",
			dto: ExecuteRequestDTO{
				InputBase64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("input line\n", 1000))),
			},
			want:    []byte(strings.Repeat("input line\n", 1000)),
			wantErr: false,
		},
		{
			name: "unicode input",
			dto: ExecuteRequestDTO{
				InputBase64: base64.StdEncoding.EncodeToString([]byte("你好世界\nこんにちは")),
			},
			want:    []byte("你好世界\nこんにちは"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.dto.DecodeInput()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid input base64")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestToExecuteResult tests conversion from model to DTO.
func TestToExecuteResult(t *testing.T) {
	tests := []struct {
		name   string
		result model.ExecuteResult
		want   ExecuteResponseDTO
	}{
		{
			name: "OK verdict",
			result: model.ExecuteResult{
				Verdict:    model.VerdictOK,
				Stdout:     "Hello, World!\n",
				TimeUsed:   100,
				MemoryUsed: 10,
				ExitCode:   0,
				ExtraInfo:  "",
			},
			want: ExecuteResponseDTO{
				Verdict:    "OK",
				Stdout:     "Hello, World!\n",
				TimeUsed:   100,
				MemoryUsed: 10,
				ExitCode:   0,
				ExtraInfo:  "",
			},
		},
		{
			name: "TLE verdict",
			result: model.ExecuteResult{
				Verdict:    model.VerdictTLE,
				Stdout:     "partial output",
				TimeUsed:   1000,
				MemoryUsed: 50,
				ExitCode:   -1,
				ExtraInfo:  "killed by timeout",
			},
			want: ExecuteResponseDTO{
				Verdict:    "TimeLimitExceeded",
				Stdout:     "partial output",
				TimeUsed:   1000,
				MemoryUsed: 50,
				ExitCode:   -1,
				ExtraInfo:  "killed by timeout",
			},
		},
		{
			name: "MLE verdict",
			result: model.ExecuteResult{
				Verdict:    model.VerdictMLE,
				Stdout:     "",
				TimeUsed:   50,
				MemoryUsed: 512,
				ExitCode:   -1,
				ExtraInfo:  "memory limit exceeded",
			},
			want: ExecuteResponseDTO{
				Verdict:    "MemoryLimitExceeded",
				Stdout:     "",
				TimeUsed:   50,
				MemoryUsed: 512,
				ExitCode:   -1,
				ExtraInfo:  "memory limit exceeded",
			},
		},
		{
			name: "OLE verdict",
			result: model.ExecuteResult{
				Verdict:    model.VerdictOLE,
				Stdout:     strings.Repeat("A", 1000),
				TimeUsed:   200,
				MemoryUsed: 20,
				ExitCode:   0,
				ExtraInfo:  "output too large",
			},
			want: ExecuteResponseDTO{
				Verdict:    "OutputLimitExceeded",
				Stdout:     strings.Repeat("A", 1000),
				TimeUsed:   200,
				MemoryUsed: 20,
				ExitCode:   0,
				ExtraInfo:  "output too large",
			},
		},
		{
			name: "RE verdict",
			result: model.ExecuteResult{
				Verdict:    model.VerdictRE,
				Stdout:     "error output",
				TimeUsed:   10,
				MemoryUsed: 5,
				ExitCode:   1,
				ExtraInfo:  "segmentation fault",
			},
			want: ExecuteResponseDTO{
				Verdict:    "RuntimeError",
				Stdout:     "error output",
				TimeUsed:   10,
				MemoryUsed: 5,
				ExitCode:   1,
				ExtraInfo:  "segmentation fault",
			},
		},
		{
			name: "UKE verdict",
			result: model.ExecuteResult{
				Verdict:    model.VerdictUKE,
				Stdout:     "",
				TimeUsed:   0,
				MemoryUsed: 0,
				ExitCode:   -1,
				ExtraInfo:  "unknown error occurred",
			},
			want: ExecuteResponseDTO{
				Verdict:    "UnknownError",
				Stdout:     "",
				TimeUsed:   0,
				MemoryUsed: 0,
				ExitCode:   -1,
				ExtraInfo:  "unknown error occurred",
			},
		},
		{
			name: "empty stdout",
			result: model.ExecuteResult{
				Verdict:    model.VerdictOK,
				Stdout:     "",
				TimeUsed:   5,
				MemoryUsed: 2,
				ExitCode:   0,
				ExtraInfo:  "",
			},
			want: ExecuteResponseDTO{
				Verdict:    "OK",
				Stdout:     "",
				TimeUsed:   5,
				MemoryUsed: 2,
				ExitCode:   0,
				ExtraInfo:  "",
			},
		},
		{
			name: "large stdout",
			result: model.ExecuteResult{
				Verdict:    model.VerdictOK,
				Stdout:     strings.Repeat("output line\n", 100),
				TimeUsed:   150,
				MemoryUsed: 30,
				ExitCode:   0,
				ExtraInfo:  "",
			},
			want: ExecuteResponseDTO{
				Verdict:    "OK",
				Stdout:     strings.Repeat("output line\n", 100),
				TimeUsed:   150,
				MemoryUsed: 30,
				ExitCode:   0,
				ExtraInfo:  "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToExecuteResult(tt.result)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestToExecuteResult_FieldMapping verifies all fields are correctly mapped.
func TestToExecuteResult_FieldMapping(t *testing.T) {
	result := model.ExecuteResult{
		Verdict:    model.VerdictOK,
		Stdout:     "test output",
		TimeUsed:   123,
		MemoryUsed: 456,
		ExitCode:   789,
		ExtraInfo:  "extra information",
	}

	dto := ToExecuteResult(result)

	assert.Equal(t, "OK", dto.Verdict)
	assert.Equal(t, "test output", dto.Stdout)
	assert.Equal(t, 123, dto.TimeUsed)
	assert.Equal(t, 456, dto.MemoryUsed)
	assert.Equal(t, 789, dto.ExitCode)
	assert.Equal(t, "extra information", dto.ExtraInfo)
}
