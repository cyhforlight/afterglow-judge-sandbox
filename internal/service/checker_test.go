package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/sandbox"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckerCompiler_CompilesSourceAndSupportFiles(t *testing.T) {
	sb := &fakeSandbox{
		t: t,
		executeFunc: func(t *testing.T, req sandbox.ExecuteRequest) sandbox.ExecuteResult {
			t.Helper()

			checkerSource, err := os.ReadFile(filepath.Join(req.MountDir.HostPath, checkerSourceFileName))
			require.NoError(t, err)
			assert.Equal(t, "#include \"testlib.h\"\nint main() { return 0; }\n", string(checkerSource))

			testlibHeader, err := os.ReadFile(filepath.Join(req.MountDir.HostPath, testlibHeaderKey))
			require.NoError(t, err)
			assert.Equal(t, "// header\n", string(testlibHeader))

			artifactPath := filepath.Join(req.MountDir.HostPath, cppProfile().Compile.ArtifactName)
			err = os.WriteFile(artifactPath, []byte("checker-binary"), 0o755)
			require.NoError(t, err)

			return sandbox.ExecuteResult{
				ExitCode: 0,
				Verdict:  sandbox.VerdictOK,
				Stdout:   "build ok",
			}
		},
	}

	compiler := NewCheckerCompiler(NewCompiler(sb, nil))
	out, err := compiler.Compile(context.Background(), CheckerCompileRequest{
		SourceCode: []byte("#include \"testlib.h\"\nint main() { return 0; }\n"),
		SupportFiles: []CompileFile{{
			Name:    testlibHeaderKey,
			Content: []byte("// header\n"),
			Mode:    0o644,
		}},
	})
	require.NoError(t, err)
	require.True(t, out.Result.Succeeded)
	require.NotNil(t, out.Artifact)
	assert.Equal(t, checkerArtifactFileName, out.Artifact.Name)
	assert.Equal(t, []byte("checker-binary"), out.Artifact.Data)
}

func TestCheckerRunner_WritesFilesAndArguments(t *testing.T) {
	sb := &fakeSandbox{
		t: t,
		executeFunc: func(t *testing.T, req sandbox.ExecuteRequest) sandbox.ExecuteResult {
			t.Helper()

			checkerFile, err := os.ReadFile(filepath.Join(req.MountDir.HostPath, checkerArtifactFileName))
			require.NoError(t, err)
			assert.Equal(t, []byte("checker-binary"), checkerFile)

			inputFile, err := os.ReadFile(filepath.Join(req.MountDir.HostPath, checkerInputFileName))
			require.NoError(t, err)
			assert.Equal(t, "input", string(inputFile))

			outputFile, err := os.ReadFile(filepath.Join(req.MountDir.HostPath, checkerOutputFileName))
			require.NoError(t, err)
			assert.Equal(t, "output", string(outputFile))

			answerFile, err := os.ReadFile(filepath.Join(req.MountDir.HostPath, checkerAnswerFileName))
			require.NoError(t, err)
			assert.Equal(t, "answer", string(answerFile))

			require.NotNil(t, req.Cwd)
			assert.Equal(t, runMountDir, *req.Cwd)
			assert.Equal(t, []string{
				runMountDir + "/" + checkerArtifactFileName,
				runMountDir + "/" + checkerInputFileName,
				runMountDir + "/" + checkerOutputFileName,
				runMountDir + "/" + checkerAnswerFileName,
			}, req.Command)

			return sandbox.ExecuteResult{
				ExitCode: 1,
				Stdout:   "stdout ignored",
				Stderr:   "checker says WA",
				Verdict:  sandbox.VerdictOK,
			}
		},
	}

	runner := NewCheckerRunner(NewRunner(sb))
	out, err := runner.Run(context.Background(), CheckerRunRequest{
		Checker: model.CompiledArtifact{
			Name: checkerArtifactFileName,
			Data: []byte("checker-binary"),
			Mode: 0o755,
		},
		InputText:      "input",
		ActualOutput:   "output",
		ExpectedOutput: "answer",
	})
	require.NoError(t, err)
	assert.Equal(t, CheckerRunResult{
		Verdict:  model.VerdictWA,
		Message:  "checker says WA",
		ExitCode: 1,
	}, out)
}

func TestConvertCheckerRunResult(t *testing.T) {
	tests := []struct {
		name string
		in   RunResult
		want CheckerRunResult
	}{
		{
			name: "ok exit code",
			in: RunResult{
				ExitCode: 0,
				Stdout:   "ok",
				Verdict:  sandbox.VerdictOK,
			},
			want: CheckerRunResult{
				Verdict:  model.VerdictOK,
				Message:  "ok",
				ExitCode: 0,
			},
		},
		{
			name: "wa exit code with sandbox runtime error verdict",
			in: RunResult{
				ExitCode: 1,
				Stderr:   "wrong answer",
				Verdict:  sandbox.VerdictRE,
			},
			want: CheckerRunResult{
				Verdict:  model.VerdictWA,
				Message:  "wrong answer",
				ExitCode: 1,
			},
		},
		{
			name: "presentation error treated as wa",
			in: RunResult{
				ExitCode: 2,
				Stdout:   "presentation issue",
				Verdict:  sandbox.VerdictRE,
			},
			want: CheckerRunResult{
				Verdict:  model.VerdictWA,
				Message:  "presentation issue",
				ExitCode: 2,
			},
		},
		{
			name: "checker internal failure becomes uke",
			in: RunResult{
				ExitCode: 3,
				Stderr:   "checker failed",
				Verdict:  sandbox.VerdictRE,
			},
			want: CheckerRunResult{
				Verdict:  model.VerdictUKE,
				Message:  "checker failed",
				ExitCode: 3,
			},
		},
		{
			name: "sandbox timeout becomes uke",
			in: RunResult{
				ExitCode:  124,
				ExtraInfo: "time limit exceeded",
				Verdict:   sandbox.VerdictTLE,
			},
			want: CheckerRunResult{
				Verdict:  model.VerdictUKE,
				Message:  "time limit exceeded",
				ExitCode: 124,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, convertCheckerRunResult(tt.in))
		})
	}
}
