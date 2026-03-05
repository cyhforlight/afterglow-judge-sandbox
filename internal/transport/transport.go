// Package transport defines abstractions for different transport layers (HTTP, gRPC, etc.).
package transport

import "context"

// Server represents any transport layer server (HTTP, gRPC, message queue, etc.).
type Server interface {
	// Start begins serving requests. Blocks until the server stops or context is cancelled.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the server.
	Stop(ctx context.Context) error

	// Addr returns the server's listening address.
	Addr() string
}
