package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		assert.Equal(t, tt.want, tt.verdict.String(), "verdict %d", tt.verdict)
	}
}

func TestVerdictMarshalJSON(t *testing.T) {
	src := struct {
		Verdict Verdict `json:"verdict"`
	}{Verdict: VerdictTLE}

	data, err := json.Marshal(src)
	require.NoError(t, err)
	assert.JSONEq(t, `{"verdict":"TimeLimitExceeded"}`, string(data))
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
		require.NoError(t, err, "ParseLanguage(%q)", tt.raw)
		assert.Equal(t, tt.want, got, "ParseLanguage(%q)", tt.raw)
	}
}

func TestParseLanguageRejectsUnknown(t *testing.T) {
	_, err := ParseLanguage("COBOL")
	assert.Error(t, err)
}
