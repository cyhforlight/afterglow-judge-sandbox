package concurrency

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutionLimiter_WithLimit(t *testing.T) {
	limiter := NewExecutionLimiter(2)
	ctx := context.Background()

	var concurrent atomic.Int32
	var maxConcurrent atomic.Int32

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			err := limiter.WithLimit(ctx, func() error {
				current := concurrent.Add(1)
				defer concurrent.Add(-1)

				// Track max concurrent
				for {
					maxVal := maxConcurrent.Load()
					if current <= maxVal || maxConcurrent.CompareAndSwap(maxVal, current) {
						break
					}
				}

				time.Sleep(50 * time.Millisecond)
				return nil
			})
			assert.NoError(t, err)
		}()
	}

	wg.Wait()

	// Should never exceed limit of 2
	assert.LessOrEqual(t, maxConcurrent.Load(), int32(2))
}

func TestExecutionLimiter_ContextCancellation(t *testing.T) {
	limiter := NewExecutionLimiter(1)

	// Occupy the slot
	ctx1 := context.Background()
	started := make(chan struct{})
	done := make(chan struct{})

	go func() {
		_ = limiter.WithLimit(ctx1, func() error {
			close(started)
			<-done
			return nil
		})
	}()

	<-started

	// Try to acquire with cancelled context
	ctx2, cancel := context.WithCancel(context.Background())
	cancel()

	err := limiter.WithLimit(ctx2, func() error {
		return nil
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")

	close(done)
}

func TestExecutionLimiter_FunctionError(t *testing.T) {
	limiter := NewExecutionLimiter(1)
	ctx := context.Background()

	expectedErr := errors.New("test error")
	err := limiter.WithLimit(ctx, func() error {
		return expectedErr
	})

	assert.Equal(t, expectedErr, err)
}

func TestNewExecutionLimiter_InvalidLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int64
	}{
		{"zero limit", 0},
		{"negative limit", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewExecutionLimiter(tt.limit)
			assert.NotNil(t, limiter)

			// Should still work (defaults to 1)
			ctx := context.Background()
			err := limiter.WithLimit(ctx, func() error {
				return nil
			})
			assert.NoError(t, err)
		})
	}
}
