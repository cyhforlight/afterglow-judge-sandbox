// Package model defines core domain types for the sandbox system.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Language represents a supported programming language.
type Language int

// Supported programming languages.
const (
	LanguageUnknown Language = iota
	LanguageC
	LanguageCPP
	LanguageJava
	LanguagePython
)

// ParseLanguage converts a string to a Language constant.
func ParseLanguage(raw string) (Language, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "C":
		return LanguageC, nil
	case "C++", "CPP":
		return LanguageCPP, nil
	case "JAVA":
		return LanguageJava, nil
	case "PYTHON", "PY", "PY3":
		return LanguagePython, nil
	default:
		return LanguageUnknown, fmt.Errorf("unsupported language: %q", raw)
	}
}

func (l Language) String() string {
	switch l {
	case LanguageC:
		return "C"
	case LanguageCPP:
		return "C++"
	case LanguageJava:
		return "Java"
	case LanguagePython:
		return "Python"
	default:
		return "Unknown"
	}
}

// MarshalJSON implements json.Marshaler for Language.
func (l Language) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

// Verdict represents the execution result status.
type Verdict int

// Execution verdicts.
const (
	VerdictUnknown Verdict = iota
	VerdictOK
	VerdictTLE
	VerdictMLE
	VerdictOLE
	VerdictRE
	VerdictUKE
)

func (v Verdict) String() string {
	switch v {
	case VerdictOK:
		return "OK"
	case VerdictTLE:
		return "TimeLimitExceeded"
	case VerdictMLE:
		return "MemoryLimitExceeded"
	case VerdictOLE:
		return "OutputLimitExceeded"
	case VerdictRE:
		return "RuntimeError"
	case VerdictUKE:
		return "UnknownError"
	default:
		return "Unknown"
	}
}

// MarshalJSON implements json.Marshaler for Verdict.
func (v Verdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

// ExecuteRequest contains parameters for code execution.
type ExecuteRequest struct {
	ExecutablePath string   `json:"executablePath"`
	InputPath      string   `json:"inputPath"`
	Language       Language `json:"language"`
	TimeLimit      int      `json:"timeLimit"`   // milliseconds
	MemoryLimit    int      `json:"memoryLimit"` // megabytes
}

// ExecuteResult contains the execution outcome and resource usage.
type ExecuteResult struct {
	Verdict    Verdict `json:"verdict"`
	Stdout     string  `json:"stdout"`
	TimeUsed   int     `json:"timeUsed"`   // milliseconds
	MemoryUsed int     `json:"memoryUsed"` // megabytes
	ExitCode   int     `json:"exitCode"`
	ExtraInfo  string  `json:"extraInfo"`
}
