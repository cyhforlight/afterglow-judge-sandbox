package model

import (
	"encoding/json"
	"testing"
)

func TestVerdictString(t *testing.T) {
	tests := []struct {
		verdict Verdict
		want    string
	}{
		{VerdictOK, "OK"},
		{VerdictTLE, "TimeLimitExceeded"},
		{VerdictMLE, "MemoryLimitExceeded"},
		{VerdictOLE, "OutputLimitExceeded"},
		{VerdictRE, "RuntimeError"},
		{VerdictUKE, "UnknownError"},
	}
	for _, tt := range tests {
		if got := tt.verdict.String(); got != tt.want {
			t.Fatalf("verdict %d: got %q, want %q", tt.verdict, got, tt.want)
		}
	}
}

func TestVerdictMarshalJSON(t *testing.T) {
	src := struct {
		Verdict Verdict `json:"verdict"`
	}{Verdict: VerdictTLE}

	data, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if string(data) != `{"verdict":"TimeLimitExceeded"}` {
		t.Fatalf("unexpected json: %s", data)
	}
}

func TestParseLanguage(t *testing.T) {
	tests := []struct {
		raw  string
		want Language
	}{
		{"C", LanguageC},
		{"c++", LanguageCPP},
		{"CPP", LanguageCPP},
		{"Java", LanguageJava},
		{"python", LanguagePython},
		{"py", LanguagePython},
		{"PY3", LanguagePython},
	}
	for _, tt := range tests {
		got, err := ParseLanguage(tt.raw)
		if err != nil {
			t.Fatalf("ParseLanguage(%q): unexpected error: %v", tt.raw, err)
		}
		if got != tt.want {
			t.Fatalf("ParseLanguage(%q): got %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestParseLanguageRejectsUnknown(t *testing.T) {
	_, err := ParseLanguage("COBOL")
	if err == nil {
		t.Fatal("expected error for unsupported language")
	}
}
