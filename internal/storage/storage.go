// Package storage provides abstractions for file storage backends.
package storage

import (
	"context"
	"io"
)

// Storage abstracts file storage operations.
// Implementations can use local filesystem, S3, MinIO, etc.
type Storage interface {
	// Store saves file content and returns a storage key.
	Store(ctx context.Context, name string, content io.Reader) (key string, err error)

	// Get retrieves a file by key and returns its local path.
	// The cleanup function must be called when done to release resources.
	Get(ctx context.Context, key string) (path string, cleanup func(), err error)

	// Delete removes a file by key.
	Delete(ctx context.Context, key string) error
}
