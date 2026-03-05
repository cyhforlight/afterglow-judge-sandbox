package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"afterglow-judge-sandbox/internal/model"
)

// CompileRequest contains source data for compilation.
type CompileRequest struct {
	Language   model.Language
	SourceCode string
}

// CompileOutput is the compiler output consumed by the judge service.
type CompileOutput struct {
	Result          model.CompileResult
	ArtifactPath    string
	RuntimeLanguage model.Language
	Cleanup         func()
}

// Compiler compiles source code to a runnable artifact.
type Compiler interface {
	Compile(ctx context.Context, req CompileRequest) (CompileOutput, error)
}

// HostCompiler compiles user source code on the host machine.
type HostCompiler struct{}

// NewHostCompiler creates a host compiler.
func NewHostCompiler() *HostCompiler {
	return &HostCompiler{}
}

// Compile compiles source code based on language profile.
func (c *HostCompiler) Compile(ctx context.Context, req CompileRequest) (CompileOutput, error) {
	var out CompileOutput

	workDir, err := os.MkdirTemp("", "judge-compile-*")
	if err != nil {
		return out, fmt.Errorf("create compile temp dir: %w", err)
	}

	out.Cleanup = func() { _ = os.RemoveAll(workDir) }

	sourcePath, artifactPath, compileLog, succeeded, err := compileByLanguage(ctx, workDir, req)
	if err != nil {
		var compileErr *compileFailureError
		if errors.As(err, &compileErr) {
			out.Result = model.CompileResult{Succeeded: false, Log: compileErr.log}
			out.RuntimeLanguage = req.Language
			out.ArtifactPath = ""
			return out, nil
		}
		out.Cleanup()
		return out, err
	}

	_ = sourcePath
	out.Result = model.CompileResult{Succeeded: succeeded, Log: compileLog}
	if !succeeded {
		out.ArtifactPath = ""
		out.RuntimeLanguage = req.Language
		return out, nil
	}

	out.ArtifactPath = artifactPath
	out.RuntimeLanguage = req.Language
	return out, nil
}

type compileFailureError struct {
	log string
}

func (e *compileFailureError) Error() string {
	return e.log
}

func compileByLanguage(
	ctx context.Context,
	workDir string,
	req CompileRequest,
) (sourcePath, artifactPath, compileLog string, succeeded bool, err error) {
	switch req.Language {
	case model.LanguagePython:
		sourcePath = filepath.Join(workDir, "solution.py")
		if err = os.WriteFile(sourcePath, []byte(req.SourceCode), 0o644); err != nil {
			return "", "", "", false, fmt.Errorf("write python source: %w", err)
		}
		return sourcePath, sourcePath, "python does not require compile", true, nil

	case model.LanguageC:
		sourcePath = filepath.Join(workDir, "main.c")
		artifactPath = filepath.Join(workDir, "program")
		return compileNative(ctx, req.SourceCode, sourcePath, artifactPath, "gcc", []string{"-O2", "-pipe", "-static", "-s"})

	case model.LanguageCPP:
		sourcePath = filepath.Join(workDir, "main.cpp")
		artifactPath = filepath.Join(workDir, "program")
		return compileNative(ctx, req.SourceCode, sourcePath, artifactPath, "g++", []string{"-O2", "-pipe", "-static", "-s"})

	case model.LanguageJava:
		return compileJava(ctx, workDir, req.SourceCode)

	default:
		return "", "", "", false, &compileFailureError{log: fmt.Sprintf("unsupported language: %q", req.Language.String())}
	}
}

func compileNative(
	ctx context.Context,
	sourceCode string,
	sourcePath string,
	artifactPath string,
	compiler string,
	compileFlags []string,
) (string, string, string, bool, error) {
	if err := os.WriteFile(sourcePath, []byte(sourceCode), 0o644); err != nil {
		return "", "", "", false, fmt.Errorf("write source file: %w", err)
	}

	if !toolAvailable(compiler) {
		return sourcePath, "", "", false, &compileFailureError{log: compiler + " not found in PATH"}
	}

	args := append([]string{}, compileFlags...)
	args = append(args, "-o", artifactPath, sourcePath)

	cmd := exec.CommandContext(ctx, compiler, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if runErr := cmd.Run(); runErr != nil {
		return sourcePath, "", "", false, &compileFailureError{log: output.String()}
	}

	return sourcePath, artifactPath, output.String(), true, nil
}

func compileJava(ctx context.Context, workDir string, sourceCode string) (string, string, string, bool, error) {
	sourcePath := filepath.Join(workDir, "Main.java")
	classDir := filepath.Join(workDir, "classes")
	artifactPath := filepath.Join(workDir, "solution.jar")

	if err := os.WriteFile(sourcePath, []byte(sourceCode), 0o644); err != nil {
		return "", "", "", false, fmt.Errorf("write java source: %w", err)
	}

	if err := os.MkdirAll(classDir, 0o755); err != nil {
		return "", "", "", false, fmt.Errorf("create class dir: %w", err)
	}

	if !toolAvailable("javac") {
		return sourcePath, "", "", false, &compileFailureError{log: "javac not found in PATH"}
	}
	if !toolAvailable("jar") {
		return sourcePath, "", "", false, &compileFailureError{log: "jar not found in PATH"}
	}

	var output bytes.Buffer

	javacCmd := exec.CommandContext(ctx, "javac", "-encoding", "UTF-8", "-d", classDir, sourcePath)
	javacCmd.Stdout = &output
	javacCmd.Stderr = &output
	if runErr := javacCmd.Run(); runErr != nil {
		return sourcePath, "", "", false, &compileFailureError{log: output.String()}
	}

	jarCmd := exec.CommandContext(ctx, "jar", "--create", "--file", artifactPath, "--main-class", "Main", "-C", classDir, ".")
	jarCmd.Stdout = &output
	jarCmd.Stderr = &output
	if runErr := jarCmd.Run(); runErr != nil {
		return sourcePath, "", "", false, &compileFailureError{log: output.String()}
	}

	return sourcePath, artifactPath, output.String(), true, nil
}

func toolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
