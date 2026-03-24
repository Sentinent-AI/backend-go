package handlers

import (
	"testing"
)

func TestGenerateSecureToken(t *testing.T) {
	// Test that tokens are generated
	token, err := generateSecureToken()
	if err != nil {
		t.Errorf("generateSecureToken() returned error: %v", err)
	}
	if token == "" {
		t.Error("generateSecureToken() returned empty token")
	}

	// Test that tokens are unique
	token2, err := generateSecureToken()
	if err != nil {
		t.Errorf("generateSecureToken() returned error on second call: %v", err)
	}
	if token == token2 {
		t.Error("generateSecureToken() returned duplicate tokens")
	}

	// Test token length (32 bytes = 64 hex characters)
	if len(token) != 64 {
		t.Errorf("generateSecureToken() returned token of wrong length: got %d, want 64", len(token))
	}
}

func TestExtractWorkspaceIDFromPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    int
		wantErr bool
	}{
		{
			name:    "valid invitations path",
			path:    "/api/workspaces/123/invitations",
			want:    123,
			wantErr: false,
		},
		{
			name:    "valid members path",
			path:    "/api/workspaces/456/members",
			want:    456,
			wantErr: false,
		},
		{
			name:    "valid nested path",
			path:    "/api/workspaces/789/members/10",
			want:    789,
			wantErr: false,
		},
		{
			name:    "invalid path - no workspace",
			path:    "/api/invitations/token123",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid path - non-numeric id",
			path:    "/api/workspaces/abc/invitations",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractWorkspaceIDFromPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractWorkspaceIDFromPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractWorkspaceIDFromPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractTokenFromPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "valid token path",
			path: "/api/invitations/token123abc",
			want: "token123abc",
		},
		{
			name: "valid token with accept",
			path: "/api/invitations/token456def/accept",
			want: "token456def",
		},
		{
			name: "invalid path - no token",
			path: "/api/workspaces/123/invitations",
			want: "",
		},
		{
			name: "empty path",
			path: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTokenFromPath(tt.path)
			if got != tt.want {
				t.Errorf("extractTokenFromPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
