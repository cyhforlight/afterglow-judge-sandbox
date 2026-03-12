// Package workspace manages temporary directories for compilation and execution.
package workspace

import (
	"fmt"
	"os"
	"path/filepath"
)

// File describes a file to be stored in a workspace.
type File struct {
	Name    string
	Content []byte
	Mode    os.FileMode
}

// Workspace manages a temporary directory for compilation or execution.
type Workspace struct {
	dir string
}

// New creates a new temporary workspace directory.
func New() (*Workspace, error) {
	dir, err := os.MkdirTemp("", "sandbox-workspace-*")
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	return &Workspace{dir: dir}, nil
}

// Dir returns the workspace directory path.
func (w *Workspace) Dir() string {
	return w.dir
}

// Path resolves a relative workspace path to an absolute path in the workspace.
func (w *Workspace) Path(name string) string {
	return filepath.Join(w.dir, name)
}

// WriteFile writes a file to the workspace with the given name, content, and permissions.
func (w *Workspace) WriteFile(name string, content []byte, mode os.FileMode) error {
	path := w.Path(name)
	if err := os.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("write file %q: %w", name, err)
	}
	return nil
}

// WriteFiles writes multiple files to the workspace.
func (w *Workspace) WriteFiles(files []File) error {
	for _, file := range files {
		fileMode := file.Mode
		if fileMode == 0 {
			fileMode = 0644
		}
		if err := w.WriteFile(file.Name, file.Content, fileMode); err != nil {
			return err
		}
	}
	return nil
}

// ReadFile reads a file from the workspace.
func (w *Workspace) ReadFile(name string) ([]byte, error) {
	data, err := os.ReadFile(w.Path(name))
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", name, err)
	}
	return data, nil
}

// Stat returns file info for a file in the workspace.
func (w *Workspace) Stat(name string) (os.FileInfo, error) {
	info, err := os.Stat(w.Path(name))
	if err != nil {
		return nil, fmt.Errorf("stat file %q: %w", name, err)
	}
	return info, nil
}

// Cleanup removes the workspace directory and all its contents.
func (w *Workspace) Cleanup() error {
	if err := os.RemoveAll(w.dir); err != nil {
		return fmt.Errorf("cleanup workspace: %w", err)
	}
	return nil
}
