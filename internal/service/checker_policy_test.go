package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCheckerPolicy_Defaults(t *testing.T) {
	policy, err := NewCheckerPolicy("", nil)
	require.NoError(t, err)

	resolved, err := policy.Resolve("")
	require.NoError(t, err)
	assert.Equal(t, defaultCheckerName, resolved)
	assert.Equal(t, defaultCheckerSourceKey, policy.StorageKey(defaultCheckerName))
}

func TestCheckerPolicy_Resolve(t *testing.T) {
	policy, err := NewCheckerPolicy(defaultCheckerName, []string{defaultCheckerName, "ncmp", "wcmp"})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "empty uses default", input: "", want: defaultCheckerName},
		{name: "allowed checker", input: "ncmp", want: "ncmp"},
		{name: "disallowed checker", input: "yesno", wantErr: `checker "yesno" is not allowed`},
		{name: "file name rejected", input: "ncmp.cpp", wantErr: `checker "ncmp.cpp" must be a builtin short name`},
		{name: "path rejected", input: "../ncmp", wantErr: `checker "../ncmp" must be a builtin short name`},
		{name: "uppercase rejected", input: "NCMP", wantErr: `checker "NCMP" must be a builtin short name`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := policy.Resolve(tt.input)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewCheckerPolicy_RejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name           string
		defaultChecker string
		allowed        []string
		wantErr        string
	}{
		{
			name:           "default not allowed",
			defaultChecker: "ncmp",
			allowed:        []string{defaultCheckerName},
			wantErr:        `default checker "ncmp" is not in allowed checkers`,
		},
		{
			name:           "invalid allowed checker",
			defaultChecker: defaultCheckerName,
			allowed:        []string{defaultCheckerName, "ncmp.cpp"},
			wantErr:        `allowed checker "ncmp.cpp"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCheckerPolicy(tt.defaultChecker, tt.allowed)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
