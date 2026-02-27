package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseArgs_MissingLanguage(t *testing.T) {
	_, err := ParseArgs([]string{
		"--exec", "/tmp/a.out",
		"--input", "/tmp/in.txt",
		"--time-limit", "1000",
		"--memory-limit", "256",
	})
	assert.EqualError(t, err, "missing required flag: --lang")
}

func TestParseArgs_RejectsWhitespaceOnlyPaths(t *testing.T) {
	_, err := ParseArgs([]string{
		"--exec", "   ",
		"--input", "/tmp/in.txt",
		"--lang", "Python",
		"--time-limit", "1000",
		"--memory-limit", "256",
	})
	assert.EqualError(t, err, "missing required flag: --exec")

	_, err = ParseArgs([]string{
		"--exec", "/tmp/a.out",
		"--input", "   ",
		"--lang", "Python",
		"--time-limit", "1000",
		"--memory-limit", "256",
	})
	assert.EqualError(t, err, "missing required flag: --input")
}
