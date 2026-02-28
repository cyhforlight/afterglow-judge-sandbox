package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseArgs_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name: "missing language",
			args: []string{
				"--exec", "/tmp/a.out",
				"--input", "/tmp/in.txt",
				"--time-limit", "1000",
				"--memory-limit", "256",
			},
			wantErr: "missing required flag: --lang",
		},
		{
			name: "whitespace-only executable path",
			args: []string{
				"--exec", "   ",
				"--input", "/tmp/in.txt",
				"--lang", "Python",
				"--time-limit", "1000",
				"--memory-limit", "256",
			},
			wantErr: "missing required flag: --exec",
		},
		{
			name: "whitespace-only input path",
			args: []string{
				"--exec", "/tmp/a.out",
				"--input", "   ",
				"--lang", "Python",
				"--time-limit", "1000",
				"--memory-limit", "256",
			},
			wantErr: "missing required flag: --input",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ParseArgs(testCase.args)
			assert.EqualError(t, err, testCase.wantErr)
		})
	}
}
