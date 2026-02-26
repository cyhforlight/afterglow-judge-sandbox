package cli

import "testing"

func TestParseArgs_MissingLanguage(t *testing.T) {
	_, err := ParseArgs([]string{
		"--exec", "/tmp/a.out",
		"--input", "/tmp/in.txt",
		"--time-limit", "1000",
		"--memory-limit", "256",
	})
	if err == nil || err.Error() != "missing required flag: --lang" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_RejectsWhitespaceOnlyPaths(t *testing.T) {
	_, err := ParseArgs([]string{
		"--exec", "   ",
		"--input", "/tmp/in.txt",
		"--lang", "Python",
		"--time-limit", "1000",
		"--memory-limit", "256",
	})
	if err == nil || err.Error() != "missing required flag: --exec" {
		t.Fatalf("unexpected error for exec path: %v", err)
	}

	_, err = ParseArgs([]string{
		"--exec", "/tmp/a.out",
		"--input", "   ",
		"--lang", "Python",
		"--time-limit", "1000",
		"--memory-limit", "256",
	})
	if err == nil || err.Error() != "missing required flag: --input" {
		t.Fatalf("unexpected error for input path: %v", err)
	}
}
