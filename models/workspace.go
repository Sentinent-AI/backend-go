package models

type Workspace struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	OwnerID    int    `json:"ownerId"`
	OwnerEmail string `json:"ownerEmail,omitempty"`
	CreatedAt  string `json:"createdAt"`
}

type WorkspaceMember struct {
	WorkspaceID int64  `json:"workspaceId"`
	UserID      int    `json:"userId"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	CreatedAt   string `json:"createdAt"`
}
