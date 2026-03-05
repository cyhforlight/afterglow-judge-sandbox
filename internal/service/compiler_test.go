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

// TestHostCompiler_CPP_RealCompilation tests real C++ compilation with executable verification.
func TestHostCompiler_CPP_RealCompilation(t *testing.T) {
	if _, err := exec.LookPath("g++"); err != nil {
		t.Skip("g++ not available")
	}

	compiler := NewHostCompiler()
	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language: model.LanguageCPP,
		SourceCode: `#include <iostream>
int main() {
    int n;
    std::cin >> n;
    std::cout << n * 2 << std::endl;
    return 0;
}`,
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.True(t, out.Result.Succeeded, "compilation should succeed")
	assert.NotEmpty(t, out.ArtifactPath)
	assert.Equal(t, model.LanguageCPP, out.RuntimeLanguage)

	// Verify the binary exists and is executable
	info, statErr := os.Stat(out.ArtifactPath)
	require.NoError(t, statErr)
	assert.NotZero(t, info.Mode()&0111, "binary should be executable")
}

// TestHostCompiler_C_RealCompilation tests real C compilation.
func TestHostCompiler_C_RealCompilation(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available")
	}

	compiler := NewHostCompiler()
	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language: model.LanguageC,
		SourceCode: `#include <stdio.h>
int main() {
    printf("Hello, World!\n");
    return 0;
}`,
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.True(t, out.Result.Succeeded)
	assert.NotEmpty(t, out.ArtifactPath)
	assert.Equal(t, model.LanguageC, out.RuntimeLanguage)

	// Verify the binary exists
	_, statErr := os.Stat(out.ArtifactPath)
	require.NoError(t, statErr)
}

// TestHostCompiler_Java_RealCompilation tests real Java compilation.
func TestHostCompiler_Java_RealCompilation(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac not available")
	}
	if _, err := exec.LookPath("jar"); err != nil {
		t.Skip("jar not available")
	}

	compiler := NewHostCompiler()
	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language: model.LanguageJava,
		SourceCode: `import java.util.Scanner;
public class Main {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        int n = sc.nextInt();
        System.out.println(n * 2);
    }
}`,
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.True(t, out.Result.Succeeded, "compilation should succeed")
	assert.NotEmpty(t, out.ArtifactPath)
	assert.Contains(t, out.ArtifactPath, ".jar", "artifact should be a JAR file")
	assert.Equal(t, model.LanguageJava, out.RuntimeLanguage)

	// Verify the JAR exists
	_, statErr := os.Stat(out.ArtifactPath)
	require.NoError(t, statErr)
}

// TestHostCompiler_Python_MultilineCode tests Python with multiline code.
func TestHostCompiler_Python_MultilineCode(t *testing.T) {
	compiler := NewHostCompiler()
	sourceCode := `import sys

def double(n):
    return n * 2

if __name__ == "__main__":
    n = int(sys.stdin.readline())
    print(double(n))
`
	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language:   model.LanguagePython,
		SourceCode: sourceCode,
	})
	require.NoError(t, err)
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.True(t, out.Result.Succeeded)
	assert.NotEmpty(t, out.ArtifactPath)

	// Verify the source code is correctly written
	data, readErr := os.ReadFile(out.ArtifactPath)
	require.NoError(t, readErr)
	assert.Equal(t, sourceCode, string(data))
}

// TestHostCompiler_CPP_CompileErrorDetails tests that compile errors include useful details.
func TestHostCompiler_CPP_CompileErrorDetails(t *testing.T) {
	if _, err := exec.LookPath("g++"); err != nil {
		t.Skip("g++ not available")
	}

	compiler := NewHostCompiler()
	out, err := compiler.Compile(context.Background(), CompileRequest{
		Language:   model.LanguageCPP,
		SourceCode: "int main() { undeclared_variable = 42; return 0; }\n",
	})
	require.NoError(t, err, "Compile should not return error, but set Succeeded=false")
	require.NotNil(t, out.Cleanup)
	defer out.Cleanup()

	assert.False(t, out.Result.Succeeded)
	assert.Empty(t, out.ArtifactPath)
	assert.NotEmpty(t, out.Result.Log)
	// Verify the log contains useful error information
	assert.Contains(t, out.Result.Log, "undeclared", "error log should mention undeclared variable")
}
