package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Language int

const (
	LanguageUnknown Language = iota
	LanguageC
	LanguageCPP
	LanguageJava
	LanguagePython
)

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

type Verdict int

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

func (v Verdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

type ExecuteRequest struct {
	ExecutablePath string   `json:"executablePath"`
	InputPath      string   `json:"inputPath"`
	Language       Language `json:"language"`
	TimeLimit      int      `json:"timeLimit"`   // milliseconds
	MemoryLimit    int      `json:"memoryLimit"` // megabytes
}

type ExecuteResult struct {
	Verdict    Verdict `json:"verdict"`
	Stdout     string  `json:"stdout"`
	TimeUsed   int     `json:"timeUsed"`   // milliseconds
	MemoryUsed int     `json:"memoryUsed"` // megabytes
	ExitCode   int     `json:"exitCode"`
	ExtraInfo  string  `json:"extraInfo"`
}
