package service

import (
	"context"
	"os"
	"testing"

	"afterglow-judge-sandbox/internal/sandbox"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileCacheKey_ChangesWithFiles(t *testing.T) {
	base := CompileRequest{
		Files: []CompileFile{{
			Name:    "main.c",
			Content: []byte("int main() { return 0; }"),
			Mode:    0644,
		}},
		ImageRef:     "compiler-image",
		Command:      []string{"gcc", "-o", "/work/program", "/work/main.c"},
		ArtifactName: "program",
		ArtifactMode: 0o755,
		ArtifactPath: "program",
	}

	changedContent := base
	changedContent.Files = []CompileFile{{
		Name:    "main.c",
		Content: []byte("int main() { return 1; }"),
		Mode:    0644,
	}}

	changedName := base
	changedName.Files = []CompileFile{{
		Name:    "alt.c",
		Content: []byte("int main() { return 0; }"),
		Mode:    0644,
	}}

	assert.NotEqual(t, compileCacheKey(base), compileCacheKey(changedContent))
	assert.NotEqual(t, compileCacheKey(base), compileCacheKey(changedName))
}

func TestCachedCompiler_NilCacheGracefulDegradation(t *testing.T) {
	sb := &fakeSandbox{
		t: t,
		executeFunc: func(t *testing.T, req sandbox.ExecuteRequest) sandbox.ExecuteResult {
			t.Helper()
			// Write artifact file to workspace
			if req.MountDir != nil {
				artifactPath := req.MountDir.HostPath + "/program"
				err := os.WriteFile(artifactPath, []byte("binary"), 0o755)
				require.NoError(t, err)
			}
			return sandbox.ExecuteResult{
				ExitCode: 0,
				Verdict:  sandbox.VerdictOK,
				Stdout:   "compiled",
			}
		},
	}

	baseCompiler := NewCompiler(sb)
	// Pass nil cache - should gracefully degrade to base compiler
	cachedCompiler := NewCachedCompiler(baseCompiler, nil)

	req := CompileRequest{
		Files: []CompileFile{{
			Name:    "main.c",
			Content: []byte("int main() { return 0; }"),
			Mode:    0644,
		}},
		ImageRef:     "test-image",
		Command:      []string{"gcc", "-o", "/work/program", "/work/main.c"},
		ArtifactName: "program",
		ArtifactMode: 0o755,
		ArtifactPath: "program",
		Limits:       sandbox.ResourceLimits{CPUTimeMs: 1000, WallTimeMs: 3000, MemoryMB: 128, OutputBytes: 1024},
	}

	// Should not panic with nil cache
	out, err := cachedCompiler.Compile(context.Background(), req)
	require.NoError(t, err)
	require.True(t, out.Result.Succeeded)
	require.NotNil(t, out.Artifact)
	assert.Equal(t, "program", out.Artifact.Name)
	assert.Equal(t, []byte("binary"), out.Artifact.Data)
}
