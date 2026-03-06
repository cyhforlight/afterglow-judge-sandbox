package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContainerdSandbox_Integration tests require containerd to be running.
// Run with: go test -tags=integration ./internal/sandbox/...

func TestContainerdSandbox_PreflightCheck(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 5*time.Second)

	err := sb.PreflightCheck(ctx)
	assert.NoError(t, err, "Preflight check should pass when containerd is running")
}

func TestContainerdSandbox_Execute_SimpleEcho(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	req := ExecuteRequest{
		ImageRef: testPythonImageRef,
		Command:  []string{"python3", "-c", "print('Hello World')"},
		Limits: ResourceLimits{
			CPUTimeMs:   1000,
			WallTimeMs:  3000,
			MemoryMB:    128,
			OutputBytes: 1024,
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, VerdictOK, result.Verdict)
	assert.Contains(t, result.Stdout, "Hello World")
}

func TestContainerdSandbox_Execute_WithStdin(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	stdin := bytes.NewBufferString("test input\n")

	req := ExecuteRequest{
		ImageRef: testPythonImageRef,
		Command:  []string{"python3", "-c", "import sys; print(sys.stdin.read(), end='')"},
		Stdin:    stdin,
		Limits: ResourceLimits{
			CPUTimeMs:   1000,
			WallTimeMs:  3000,
			MemoryMB:    128,
			OutputBytes: 1024,
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, VerdictOK, result.Verdict)
	assert.Contains(t, result.Stdout, "test input")
}

func TestContainerdSandbox_Execute_TLE(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	req := ExecuteRequest{
		ImageRef: testPythonImageRef,
		Command:  []string{"python3", "-c", "while True: pass"},
		Limits: ResourceLimits{
			CPUTimeMs:   100, // 100ms limit
			WallTimeMs:  300, // 300ms wall time
			MemoryMB:    128,
			OutputBytes: 1024,
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, VerdictTLE, result.Verdict)
	assert.Contains(t, result.ExtraInfo, "limit")
}

func TestContainerdSandbox_Execute_OLE(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	req := ExecuteRequest{
		ImageRef: testPythonImageRef,
		Command:  []string{"python3", "-c", "print('x' * 10000000)"},
		Limits: ResourceLimits{
			CPUTimeMs:   5000,
			WallTimeMs:  15000,
			MemoryMB:    128,
			OutputBytes: 1024 * 1024, // 1MB limit
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, VerdictOLE, result.Verdict)
	assert.Contains(t, result.ExtraInfo, "output limit")
}

func TestContainerdSandbox_Execute_NonZeroExit(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	req := ExecuteRequest{
		ImageRef: testPythonImageRef,
		Command:  []string{"python3", "-c", "import sys; sys.exit(42)"},
		Limits: ResourceLimits{
			CPUTimeMs:   1000,
			WallTimeMs:  3000,
			MemoryMB:    128,
			OutputBytes: 1024,
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, 42, result.ExitCode)
	assert.Equal(t, VerdictRE, result.Verdict)
}

func TestContainerdSandbox_Execute_MultipleMounts(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	// Create test files
	err := os.WriteFile(filepath.Join(tmpDir1, "file1.txt"), []byte("content1"), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir2, "file2.txt"), []byte("content2"), 0o644)
	require.NoError(t, err)

	// Python script to read both files
	pythonCode := `
with open('/dir1/file1.txt', 'r') as f1:
    print(f1.read(), end='')
with open('/dir2/file2.txt', 'r') as f2:
    print(f2.read(), end='')
`

	req := ExecuteRequest{
		ImageRef: testPythonImageRef,
		Command:  []string{"python3", "-c", pythonCode},
		Mounts: []Mount{
			{
				HostPath:      tmpDir1,
				ContainerPath: "/dir1",
				ReadOnly:      true,
			},
			{
				HostPath:      tmpDir2,
				ContainerPath: "/dir2",
				ReadOnly:      true,
			},
		},
		Limits: ResourceLimits{
			CPUTimeMs:   1000,
			WallTimeMs:  3000,
			MemoryMB:    128,
			OutputBytes: 1024,
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, VerdictOK, result.Verdict)
	assert.Contains(t, result.Stdout, "content1")
	assert.Contains(t, result.Stdout, "content2")
}

func TestContainerdSandbox_Execute_MountedBinary(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	// 挂载 testdata/test_runner 二进制
	testRunnerPath := filepath.Join("..", "..", "testdata", "test_runner")
	absPath, err := filepath.Abs(testRunnerPath)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	// 复制二进制到临时目录（确保权限正确）
	data, err := os.ReadFile(absPath)
	require.NoError(t, err)
	binaryPath := filepath.Join(tmpDir, "test_runner")
	err = os.WriteFile(binaryPath, data, 0o755)
	require.NoError(t, err)

	req := ExecuteRequest{
		ImageRef: testStaticImageRef,
		Command:  []string{"/sandbox/test_runner"},
		Mounts: []Mount{{
			HostPath:      tmpDir,
			ContainerPath: "/sandbox",
			ReadOnly:      true,
		}},
		Limits: ResourceLimits{
			CPUTimeMs:   1000,
			WallTimeMs:  3000,
			MemoryMB:    128,
			OutputBytes: 1024,
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, VerdictOK, result.Verdict)
	assert.Contains(t, result.Stdout, "Hello from test binary")
}

func TestContainerdSandbox_Execute_MountedBinaryReadFile(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	// 准备测试二进制和数据文件
	testRunnerPath := filepath.Join("..", "..", "testdata", "test_runner")
	absPath, err := filepath.Abs(testRunnerPath)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	data, err := os.ReadFile(absPath)
	require.NoError(t, err)
	binaryPath := filepath.Join(tmpDir, "test_runner")
	err = os.WriteFile(binaryPath, data, 0o755)
	require.NoError(t, err)

	// 创建输入文件
	inputPath := filepath.Join(tmpDir, "input.txt")
	err = os.WriteFile(inputPath, []byte("7\n"), 0o644)
	require.NoError(t, err)

	req := ExecuteRequest{
		ImageRef: testStaticImageRef,
		Command:  []string{"/sandbox/test_runner", "readfile", "/sandbox/input.txt"},
		Mounts: []Mount{{
			HostPath:      tmpDir,
			ContainerPath: "/sandbox",
			ReadOnly:      true,
		}},
		Limits: ResourceLimits{
			CPUTimeMs:   1000,
			WallTimeMs:  3000,
			MemoryMB:    128,
			OutputBytes: 1024,
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, VerdictOK, result.Verdict)
	assert.Contains(t, result.Stdout, "49") // 7*7=49
}

func TestContainerdSandbox_Execute_MLE(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	req := ExecuteRequest{
		ImageRef: testPythonImageRef,
		Command:  []string{"python3", "-c", "x = bytearray(100 * 1024 * 1024)"},
		Limits: ResourceLimits{
			CPUTimeMs:   5000,
			WallTimeMs:  15000,
			MemoryMB:    64, // 64MB limit
			OutputBytes: 1024,
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, VerdictMLE, result.Verdict)
	assert.Contains(t, result.ExtraInfo, "memory limit")
}

func TestContainerdSandbox_Execute_WriteFile(t *testing.T) {
	requireSandboxIntegrationTest(t)

	sb := newTestSandbox(t)
	ctx := newSandboxTestContext(t, 10*time.Second)

	tmpDir := t.TempDir()

	pythonCode := `
with open('/output/result.txt', 'w') as f:
    f.write('test output')
print('done')
`

	req := ExecuteRequest{
		ImageRef: testPythonImageRef,
		Command:  []string{"python3", "-c", pythonCode},
		Mounts: []Mount{{
			HostPath:      tmpDir,
			ContainerPath: "/output",
			ReadOnly:      false,
		}},
		Limits: ResourceLimits{
			CPUTimeMs:   1000,
			WallTimeMs:  3000,
			MemoryMB:    128,
			OutputBytes: 1024,
		},
	}

	result, err := sb.Execute(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, VerdictOK, result.Verdict)

	// 验证文件被创建
	outputPath := filepath.Join(tmpDir, "result.txt")
	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Equal(t, "test output", string(content))
}
