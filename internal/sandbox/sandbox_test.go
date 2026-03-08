package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveCwd(t *testing.T) {
	tests := []struct {
		name    string
		req     ExecuteRequest
		want    string
		wantOK  bool
		wantErr bool
	}{
		{
			name:   "explicit cwd wins",
			req:    ExecuteRequest{MountDir: &Mount{ContainerPath: "/sandbox"}, Cwd: stringPtr("/work")},
			want:   "/work",
			wantOK: true,
		},
		{
			name:   "mount dir becomes default cwd",
			req:    ExecuteRequest{MountDir: &Mount{ContainerPath: "/sandbox"}},
			want:   "/sandbox",
			wantOK: true,
		},
		{
			name:   "no mount and no cwd uses image default",
			req:    ExecuteRequest{},
			wantOK: false,
		},
		{
			name:    "relative cwd is rejected",
			req:     ExecuteRequest{Cwd: stringPtr("sandbox")},
			wantErr: true,
		},
		{
			name:    "relative mount path is rejected",
			req:     ExecuteRequest{MountDir: &Mount{ContainerPath: "sandbox"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := resolveCwd(tt.req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func stringPtr(val string) *string {
	return &val
}
