package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"afterglow-judge-sandbox/internal/model"
)

func Usage() string {
	return strings.TrimSpace(`
Usage:
  sandbox --exec <path> --input <path> --lang <C|C++|Java|Python> --time-limit <ms> --memory-limit <mb>

Flags:
  --exec          Executable file path
  --input         Input file path
  --lang          Language type: C, C++, Java, Python
  --time-limit    Time limit in milliseconds (int, > 0)
  --memory-limit  Memory limit in megabytes (int, > 0)
`)
}

func ParseArgs(args []string) (model.ExecuteRequest, error) {
	var req model.ExecuteRequest
	var languageRaw string

	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&req.ExecutablePath, "exec", "", "Executable file path")
	fs.StringVar(&req.InputPath, "input", "", "Input file path")
	fs.StringVar(&languageRaw, "lang", "", "Language type: C, C++, Java, Python")
	fs.IntVar(&req.TimeLimit, "time-limit", 0, "Time limit in milliseconds")
	fs.IntVar(&req.MemoryLimit, "memory-limit", 0, "Memory limit in megabytes")

	if err := fs.Parse(args); err != nil {
		return model.ExecuteRequest{}, fmt.Errorf("failed to parse flags: %w", err)
	}
	if fs.NArg() > 0 {
		return model.ExecuteRequest{}, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	req.ExecutablePath = strings.TrimSpace(req.ExecutablePath)
	req.InputPath = strings.TrimSpace(req.InputPath)
	languageRaw = strings.TrimSpace(languageRaw)

	if languageRaw == "" {
		return model.ExecuteRequest{}, fmt.Errorf("missing required flag: --lang")
	}

	lang, err := model.ParseLanguage(languageRaw)
	if err != nil {
		return model.ExecuteRequest{}, err
	}
	req.Language = lang

	if req.ExecutablePath == "" {
		return model.ExecuteRequest{}, fmt.Errorf("missing required flag: --exec")
	}
	if req.InputPath == "" {
		return model.ExecuteRequest{}, fmt.Errorf("missing required flag: --input")
	}
	if req.TimeLimit <= 0 {
		return model.ExecuteRequest{}, fmt.Errorf("--time-limit must be > 0")
	}
	if req.MemoryLimit <= 0 {
		return model.ExecuteRequest{}, fmt.Errorf("--memory-limit must be > 0")
	}

	return req, nil
}
