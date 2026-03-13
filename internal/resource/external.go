package resource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// External provides read-only access to external files.
type External struct {
	mountPoint string
}

// NewExternal creates a read-only resource store mounted at the specified directory.
func NewExternal(mountPoint string) (*External, error) {
	// Verify mount point exists and is a directory
	info, err := os.Stat(mountPoint)
	if err != nil {
		return nil, fmt.Errorf("mount point not accessible: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("mount point is not a directory: %q", mountPoint)
	}

	return &External{
		mountPoint: mountPoint,
	}, nil
}

// Get retrieves file content by relative path.
// The path is relative to the mount point (e.g., "testdata/input.txt").
func (e *External) Get(_ context.Context, relPath string) ([]byte, error) {
	resolvedPath, err := e.resolveRegularFilePath(relPath)
	if err != nil {
		return nil, err
	}

	// Let the operating system page cache handle repeated reads.
	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	return data, nil
}

// Stat verifies that a relative path resolves to an accessible regular file inside the mount.
func (e *External) Stat(_ context.Context, relPath string) error {
	_, err := e.resolveRegularFilePath(relPath)
	return err
}

func (e *External) resolveRegularFilePath(relPath string) (string, error) {
	// Normalize and validate path (prevent path traversal)
	normalized, err := NormalizeKey(relPath)
	if err != nil {
		return "", err
	}

	// Build full path
	fullPath := filepath.Join(e.mountPoint, normalized)

	// Resolve symlinks to prevent mount escape
	resolvedPath, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return "", fmt.Errorf("resolve symlink: %w", err)
	}

	// Resolve mount point symlinks
	resolvedMount, err := filepath.EvalSymlinks(e.mountPoint)
	if err != nil {
		return "", fmt.Errorf("resolve mount point: %w", err)
	}

	// Verify resolved path is still within mount point
	relResolved, err := filepath.Rel(resolvedMount, resolvedPath)
	if err != nil || relResolved == ".." || strings.HasPrefix(relResolved, "../") {
		return "", fmt.Errorf("symlink escapes mount point: %s", relPath)
	}

	// Validate that the resolved path points to a regular file inside the mount.
	fileInfo, err := os.Stat(resolvedPath)
	if err != nil {
		return "", fmt.Errorf("file not found: %w", err)
	}
	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("external resource must be a regular file: %s", relPath)
	}

	return resolvedPath, nil
}
