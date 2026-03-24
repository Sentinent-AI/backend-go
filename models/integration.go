package models

import "time"

type ExternalIntegration struct {
	ID           int        `json:"id"`
	UserID       int        `json:"user_id"`
	Provider     string     `json:"provider"`
	AccessToken  string     `json:"-"`
	RefreshToken string     `json:"-"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type IntegrationStatus struct {
	Provider  string    `json:"provider"`
	Connected bool      `json:"connected"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}
