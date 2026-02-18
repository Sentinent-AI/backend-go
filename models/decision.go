package models

type Decision struct {
	ID          int64  `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
	WorkspaceID int64  `json:"workspaceId"`
	OwnerID     int    `json:"ownerId"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}
