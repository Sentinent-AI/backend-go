package models

type Workspace struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"createdAt"`
	OwnerID    int    `json:"ownerId"`
	OwnerEmail string `json:"ownerEmail,omitempty"`
}
