package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"afterglow-judge-sandbox/internal/model"
	"afterglow-judge-sandbox/internal/service"
)

const defaultContainerdSocketPath = "/run/containerd/containerd.sock"
const defaultRunnerNamespace = "afterglow"

type appRunOutput struct {
	Verdict    string `json:"verdict"`
	Stdout     string `json:"stdout"`
	TimeUsed   int    `json:"timeUsed"`
	MemoryUsed int    `json:"memoryUsed"`
	ExitCode   int    `json:"exitCode"`
	ExtraInfo  string `json:"extraInfo"`
}

func TestRun_E2E_WithFixturePrograms(t *testing.T) {
	skipIfE2EPrerequisitesMissing(t)

	fixtureRoot := pathFromRepoRoot(t, "testprograms")
	inputPath := filepath.Join(fixtureRoot, "data.in")
	require.FileExists(t, inputPath)

	tests := []struct {
		name          string
		programRel    string
		lang          string
		timeLimitMs   int
		memoryLimitMB int
		wantVerdict   model.Verdict
		wantStdout    string
	}{
		{
			name:          "cpp ok",
			programRel:    filepath.Join("cpp", "ok"),
			lang:          "C++",
			timeLimitMs:   1000,
			memoryLimitMB: 256,
			wantVerdict:   model.VerdictOK,
			wantStdout:    "0 1 1 1 1 1 1 4 4 5 8 9 9\n",
		},
		{
			name:          "cpp tle",
			programRel:    filepath.Join("cpp", "tle"),
			lang:          "C++",
			timeLimitMs:   200,
			memoryLimitMB: 256,
			wantVerdict:   model.VerdictTLE,
		},
		{
			name:          "cpp mle",
			programRel:    filepath.Join("cpp", "mle"),
			lang:          "C++",
			timeLimitMs:   2000,
			memoryLimitMB: 64,
			wantVerdict:   model.VerdictMLE,
		},
		{
			name:          "cpp re",
			programRel:    filepath.Join("cpp", "re"),
			lang:          "C++",
			timeLimitMs:   1000,
			memoryLimitMB: 256,
			wantVerdict:   model.VerdictRE,
		},
		{
			name:          "cpp ole",
			programRel:    filepath.Join("cpp", "ole"),
			lang:          "C++",
			timeLimitMs:   2000,
			memoryLimitMB: 8,
			wantVerdict:   model.VerdictOLE,
		},
		{
			name:          "python ok",
			programRel:    filepath.Join("python", "ok.py"),
			lang:          "Python",
			timeLimitMs:   1000,
			memoryLimitMB: 256,
			wantVerdict:   model.VerdictOK,
			wantStdout:    "0 1 1 1 1 1 1 4 4 5 8 9 9\n",
		},
		{
			name:          "python tle",
			programRel:    filepath.Join("python", "tle.py"),
			lang:          "Python",
			timeLimitMs:   200,
			memoryLimitMB: 256,
			wantVerdict:   model.VerdictTLE,
		},
		{
			name:          "python mle",
			programRel:    filepath.Join("python", "mle.py"),
			lang:          "Python",
			timeLimitMs:   2000,
			memoryLimitMB: 64,
			wantVerdict:   model.VerdictMLE,
		},
		{
			name:          "python re",
			programRel:    filepath.Join("python", "re.py"),
			lang:          "Python",
			timeLimitMs:   1000,
			memoryLimitMB: 256,
			wantVerdict:   model.VerdictRE,
		},
		{
			name:          "java ok",
			programRel:    filepath.Join("java", "ok.jar"),
			lang:          "Java",
			timeLimitMs:   2000,
			memoryLimitMB: 256,
			wantVerdict:   model.VerdictOK,
			wantStdout:    "0 1 1 1 1 1 1 4 4 5 8 9 9\n",
		},
		{
			name:          "java tle",
			programRel:    filepath.Join("java", "tle.jar"),
			lang:          "Java",
			timeLimitMs:   500,
			memoryLimitMB: 256,
			wantVerdict:   model.VerdictTLE,
		},
		{
			name:          "java mle",
			programRel:    filepath.Join("java", "mle.jar"),
			lang:          "Java",
			timeLimitMs:   3000,
			memoryLimitMB: 128,
			wantVerdict:   model.VerdictMLE,
		},
		{
			name:          "java re",
			programRel:    filepath.Join("java", "re.jar"),
			lang:          "Java",
			timeLimitMs:   2000,
			memoryLimitMB: 256,
			wantVerdict:   model.VerdictRE,
		},
	}

	runner := service.NewDispatchRunner(os.Getenv("CONTAINERD_SOCKET"))

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			programPath := filepath.Join(fixtureRoot, testCase.programRel)
			require.FileExists(t, programPath)

			var out bytes.Buffer
			var errOut bytes.Buffer
			application := New(runner, &out, &errOut)

			args := []string{
				"--exec", programPath,
				"--input", inputPath,
				"--lang", testCase.lang,
				"--time-limit", strconv.Itoa(testCase.timeLimitMs),
				"--memory-limit", strconv.Itoa(testCase.memoryLimitMB),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()

			exitCode := application.Run(ctx, args)
			require.Equalf(t, 0, exitCode, "stderr=%s", errOut.String())
			assert.Empty(t, errOut.String())

			var got appRunOutput
			require.NoError(t, json.Unmarshal(out.Bytes(), &got), "raw output: %s", out.String())

			assert.Equal(t, testCase.wantVerdict.String(), got.Verdict)
			assert.GreaterOrEqual(t, got.TimeUsed, 0)
			assert.GreaterOrEqual(t, got.MemoryUsed, 0)
			if testCase.wantStdout != "" {
				assert.Equal(t, testCase.wantStdout, got.Stdout)
			}
		})
	}
}

func skipIfE2EPrerequisitesMissing(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("skip e2e: requires root. run with: sudo env GOCACHE=/tmp/go-build go test ./internal/app -run TestRun_E2E_WithFixturePrograms -v")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skipf("skip e2e: cgroup v2 is required: %v", err)
	}

	socketPath := os.Getenv("CONTAINERD_SOCKET")
	if socketPath == "" {
		socketPath = defaultContainerdSocketPath
	}

	client, err := containerd.New(socketPath)
	if err != nil {
		t.Skipf("skip e2e: containerd unavailable on %q: %v", socketPath, err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = namespaces.WithNamespace(ctx, defaultRunnerNamespace)

	if _, err = client.Version(ctx); err != nil {
		t.Skipf("skip e2e: containerd is not ready on %q: %v", socketPath, err)
	}

	for _, imageRef := range requiredImageRefs() {
		if _, err = client.GetImage(ctx, imageRef); err != nil {
			if errdefs.IsNotFound(err) {
				t.Skipf("skip e2e: required image %q not found locally", imageRef)
			}
			t.Skipf("skip e2e: failed to inspect image %q: %v", imageRef, err)
		}
	}
}

func requiredImageRefs() []string {
	refs := map[string]struct{}{
		service.NativeRunProfile().ImageRef: {},
		service.PythonRunProfile().ImageRef: {},
		service.JavaRunProfile().ImageRef:   {},
	}
	imageRefs := make([]string, 0, len(refs))
	for imageRef := range refs {
		imageRefs = append(imageRefs, imageRef)
	}
	return imageRefs
}

func pathFromRepoRoot(t *testing.T, elements ...string) string {
	t.Helper()

	base := filepath.Join("..", "..")
	for _, element := range elements {
		base = filepath.Join(base, element)
	}

	path, err := filepath.Abs(base)
	require.NoError(t, err)
	return path
}
