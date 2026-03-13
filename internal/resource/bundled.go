// Package resource provides read-only access to bundled and external judge resources.
package resource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	iofs "io/fs"
	"path"
	"path/filepath"
	"strings"

	rootassets "afterglow-judge-engine"
)

// Bundled implements read-only access to project-bundled resources.
// Used for resources like testlib.h and builtin checker sources.
type Bundled struct {
	fsys iofs.FS
}

const bundledSupportDirName = "support"

// NewBundled creates a resource store backed by embedded support resources.
func NewBundled() (*Bundled, error) {
	bundledFS, err := iofs.Sub(rootassets.BundledSupportFiles, bundledSupportDirName)
	if err != nil {
		return nil, fmt.Errorf("open bundled support resources: %w", err)
	}

	return newBundled(bundledFS), nil
}

func newBundled(fsys iofs.FS) *Bundled {
	return &Bundled{fsys: fsys}
}

// Get retrieves bundled resource content by trusted relative key.
func (b *Bundled) Get(_ context.Context, key string) ([]byte, error) {
	data, err := iofs.ReadFile(b.fsys, key)
	if errors.Is(err, iofs.ErrNotExist) {
		return nil, fmt.Errorf("resource not found: %s", key)
	}
	if err != nil {
		return nil, fmt.Errorf("read bundled resource %q: %w", key, err)
	}

	return bytes.Clone(data), nil
}

// Stat verifies that a bundled resource key exists.
func (b *Bundled) Stat(_ context.Context, key string) error {
	if _, err := iofs.Stat(b.fsys, key); errors.Is(err, iofs.ErrNotExist) {
		return fmt.Errorf("resource not found: %s", key)
	} else if err != nil {
		return fmt.Errorf("stat bundled resource %q: %w", key, err)
	}

	return nil
}

// NormalizeKey validates and normalizes a resource key.
func NormalizeKey(key string) (string, error) {
	if strings.TrimSpace(key) == "" {
		return "", errors.New("resource key is required")
	}
	if filepath.IsAbs(key) {
		return "", fmt.Errorf("resource key must be relative: %q", key)
	}

	normalizedKey := path.Clean(filepath.ToSlash(key))
	if normalizedKey == "." {
		return "", errors.New("resource key is required")
	}
	if normalizedKey == ".." || strings.HasPrefix(normalizedKey, "../") {
		return "", fmt.Errorf("resource key escapes base directory: %q", key)
	}

	return normalizedKey, nil
}
