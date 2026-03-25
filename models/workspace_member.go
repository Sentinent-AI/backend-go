package models

import "time"

type WorkspaceMemberRole string

const (
	RoleOwner  WorkspaceMemberRole = "owner"
	RoleMember WorkspaceMemberRole = "member"
	RoleViewer WorkspaceMemberRole = "viewer"
)

type WorkspaceMember struct {
	ID          int                 `json:"id"`
	WorkspaceID int                 `json:"workspace_id"`
	UserID      int                 `json:"user_id"`
	Role        WorkspaceMemberRole `json:"role"`
	JoinedAt    time.Time           `json:"joined_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
	Email       string              `json:"email,omitempty"`
}
