// Package sandbox provides a unified container execution abstraction for both
// compilation and runtime execution.
package sandbox

import (
	"context"
	"io"
)

// Sandbox executes commands in isolated containers.
type Sandbox interface {
	Execute(ctx context.Context, req ExecuteRequest) (ExecuteResult, error)
	PreflightCheck(ctx context.Context) error
}

// ExecuteRequest contains all parameters needed to run a command in a container.
type ExecuteRequest struct {
	ImageRef      string
	Command       []string
	MountDir      *Mount
	Cwd           *string
	Stdin         io.Reader
	Limits        ResourceLimits
	EnableSeccomp bool // Enable seccomp restrictions (for user code execution)
}

// Mount describes a host path to be mounted into the container.
type Mount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// ResourceLimits defines execution constraints.
type ResourceLimits struct {
	CPUTimeMs   int
	WallTimeMs  int
	MemoryMB    int
	OutputBytes int64
}

// ExecuteResult contains the execution outcome and metrics.
type ExecuteResult struct {
	ExitCode  int
	Stdout    string
	Stderr    string
	CPUTimeMs int
	MemoryMB  int
	Verdict   Verdict
	ExtraInfo string
}

// Verdict represents the execution result classification.
type Verdict int

// Execution verdicts.
const (
	VerdictOK Verdict = iota
	VerdictTLE
	VerdictMLE
	VerdictOLE
	VerdictRE
)

// Resource limit constants for execution.
const (
	// WallTimeMultiplier is the multiplier applied to CPU time limit to get wall time limit.
	// Wall time accounts for I/O waits, scheduling latency, container overhead, etc.
	// A multiplier of 3 means wall time can be up to 3x the CPU time limit.
	WallTimeMultiplier = 3

	// DefaultExecutionOutputLimitBytes is the maximum output size for user program execution.
	// Set to 16MB to prevent memory exhaustion from unbounded output.
	DefaultExecutionOutputLimitBytes = 16 * 1024 * 1024 // 16MB

	// DefaultCompileOutputLimitBytes is the maximum output size for compilation.
	// Set to 1MB as compile logs are typically small.
	DefaultCompileOutputLimitBytes = 1 * 1024 * 1024 // 1MB
)
