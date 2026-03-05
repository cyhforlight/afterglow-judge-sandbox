// Package concurrency provides utilities for controlling concurrent execution.
package concurrency

import (
	"context"
	"fmt"

	"golang.org/x/sync/semaphore"
)

// ExecutionLimiter limits the number of concurrent executions.
type ExecutionLimiter struct {
	sem *semaphore.Weighted
}

// NewExecutionLimiter creates a limiter with the specified max concurrent executions.
func NewExecutionLimiter(maxConcurrent int64) *ExecutionLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	return &ExecutionLimiter{
		sem: semaphore.NewWeighted(maxConcurrent),
	}
}

// WithLimit executes fn with concurrency control.
// Blocks until a slot is available or context is cancelled.
func (l *ExecutionLimiter) WithLimit(ctx context.Context, fn func() error) error {
	if err := l.sem.Acquire(ctx, 1); err != nil {
		return fmt.Errorf("failed to acquire execution slot: %w", err)
	}
	defer l.sem.Release(1)

	return fn()
}
