package models

import "time"

type Invitation struct {
	ID          int                 `json:"id"`
	WorkspaceID int                 `json:"workspace_id"`
	Email       string              `json:"email"`
	Token       string              `json:"token,omitempty"`
	Role        WorkspaceMemberRole `json:"role"`
	ExpiresAt   time.Time           `json:"expires_at"`
	CreatedBy   int                 `json:"created_by"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
	AcceptedAt  *time.Time          `json:"accepted_at,omitempty"`
	AcceptedBy  *int                `json:"accepted_by,omitempty"`
}

type CreateInvitationRequest struct {
	Email string              `json:"email"`
	Role  WorkspaceMemberRole `json:"role"`
}

type InvitationResponse struct {
	ID          int                 `json:"id"`
	WorkspaceID int                 `json:"workspace_id"`
	Email       string              `json:"email"`
	Token       string              `json:"token,omitempty"`
	Role        WorkspaceMemberRole `json:"role"`
	ExpiresAt   time.Time           `json:"expires_at"`
	CreatedAt   time.Time           `json:"created_at"`
}
