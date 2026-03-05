package service

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"afterglow-judge-sandbox/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostCompiler_Compile_PythonSuccess(t *testing.T) {
	compiler := NewHostCompiler()

	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language:   model.LanguagePython,
		SourceCode: "print(42)\n",
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.True(t, out.Result.Succeeded)
	assert.Equal(t, model.LanguagePython, out.RuntimeLanguage)
	assert.Contains(t, out.Result.Log, "does not require compile")
	assert.NotEmpty(t, out.ArtifactPath)

	data, readErr := os.ReadFile(out.ArtifactPath)
	require.NoError(t, readErr)
	assert.Equal(t, "print(42)\n", string(data))
}

func TestHostCompiler_Compile_UnknownLanguage(t *testing.T) {
	compiler := NewHostCompiler()

	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language:   model.LanguageUnknown,
		SourceCode: "whatever",
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.False(t, out.Result.Succeeded)
	assert.Empty(t, out.ArtifactPath)
	assert.Contains(t, out.Result.Log, "unsupported language")
}

func TestHostCompiler_Compile_CPPToolchainMissing(t *testing.T) {
	t.Setenv("PATH", "")

	compiler := NewHostCompiler()
	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language:   model.LanguageCPP,
		SourceCode: "int main(){return 0;}\n",
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.False(t, out.Result.Succeeded)
	assert.Empty(t, out.ArtifactPath)
	assert.Contains(t, out.Result.Log, "g++ not found in PATH")
}

func TestHostCompiler_Compile_JavaToolchainMissing(t *testing.T) {
	t.Setenv("PATH", "")

	compiler := NewHostCompiler()
	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language: model.LanguageJava,
		SourceCode: `public class Main {
	public static void main(String[] args) {
		System.out.println(42);
	}
}`,
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.False(t, out.Result.Succeeded)
	assert.Empty(t, out.ArtifactPath)
	assert.True(t, strings.Contains(out.Result.Log, "javac not found") || strings.Contains(out.Result.Log, "jar not found"))
}

func TestHostCompiler_Compile_CPPSyntaxError(t *testing.T) {
	if _, err := exec.LookPath("g++"); err != nil {
		t.Skip("g++ not available")
	}

	compiler := NewHostCompiler()
	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language:   model.LanguageCPP,
		SourceCode: "int main( { return 0; }\n",
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.False(t, out.Result.Succeeded)
	assert.Empty(t, out.ArtifactPath)
	assert.NotEmpty(t, strings.TrimSpace(out.Result.Log))
}

func TestHostCompiler_CleanupRemovesWorkDir(t *testing.T) {
	compiler := NewHostCompiler()
	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language:   model.LanguagePython,
		SourceCode: "print(1)\n",
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)

	workDir := filepath.Dir(out.ArtifactPath)
	_, statErr := os.Stat(workDir)
	require.NoError(t, statErr)

	out.Cleanup()
	_, statErr = os.Stat(workDir)
	require.Error(t, statErr)
	assert.True(t, os.IsNotExist(statErr))
}
