package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalStorage_Store(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		content     string
		expectError bool
	}{
		{
			name:        "store simple file",
			filename:    "test.txt",
			content:     "hello world",
			expectError: false,
		},
		{
			name:        "store with special chars in name",
			filename:    "test-file_123.cpp",
			content:     "#include <iostream>",
			expectError: false,
		},
		{
			name:        "store empty file",
			filename:    "empty.txt",
			content:     "",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			storage, err := NewLocalStorage(tmpDir)
			require.NoError(t, err)

			ctx := context.Background()
			reader := bytes.NewReader([]byte(tt.content))

			key, err := storage.Store(ctx, tt.filename, reader)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, key)

			// Verify file exists
			pattern := filepath.Join(tmpDir, key+"_*")
			matches, err := filepath.Glob(pattern)
			require.NoError(t, err)
			require.Len(t, matches, 1)

			// Verify content
			data, err := os.ReadFile(matches[0])
			require.NoError(t, err)
			assert.Equal(t, tt.content, string(data))
		})
	}
}

func TestLocalStorage_Get(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	require.NoError(t, err)

	ctx := context.Background()
	content := "test content"

	// Store a file first
	key, err := storage.Store(ctx, "test.txt", bytes.NewReader([]byte(content)))
	require.NoError(t, err)

	// Get the file
	path, cleanup, err := storage.Get(ctx, key)
	require.NoError(t, err)
	require.NotEmpty(t, path)
	require.NotNil(t, cleanup)
	defer cleanup()

	// Verify content
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, string(data))

	// Verify cleanup works
	cleanup()
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestLocalStorage_Get_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	require.NoError(t, err)

	ctx := context.Background()
	// Use a valid hex key that doesn't exist
	_, _, err = storage.Get(ctx, "0123456789abcdef0123456789abcdef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLocalStorage_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Store a file
	key, err := storage.Store(ctx, "test.txt", bytes.NewReader([]byte("content")))
	require.NoError(t, err)

	// Delete it
	err = storage.Delete(ctx, key)
	require.NoError(t, err)

	// Verify it's gone
	_, _, err = storage.Get(ctx, key)
	assert.Error(t, err)
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test.txt", "test.txt"},
		{"../../../etc/passwd", "passwd"},
		{"file with spaces.cpp", "filewithspaces.cpp"},
		{"test@#$%file.java", "testfile.java"},
		{"normal-file_123.py", "normal-file_123.py"},
		{".", "."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		expectError bool
	}{
		{"valid hex key", "0123456789abcdef", false},
		{"empty key", "", true},
		{"path traversal", "../key", true},
		{"with slash", "key/path", true},
		{"with backslash", "key\\path", true},
		{"non-hex", "notahexstring", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKey(tt.key)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
