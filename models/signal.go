package models

import "time"

type Signal struct {
	ID             int             `json:"id"`
	UserID         int             `json:"user_id"`
	SourceType     string          `json:"source_type"`
	SourceID       string          `json:"source_id"`
	Title          string          `json:"title"`
	Body           string          `json:"body,omitempty"`
	URL            string          `json:"url,omitempty"`
	Status         string          `json:"status"`
	SourceMetadata *GitHubMetadata `json:"source_metadata,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type GitHubMetadata struct {
	Repository string   `json:"repository"`
	Number     int      `json:"number"`
	State      string   `json:"state"`
	Labels     []string `json:"labels,omitempty"`
	Type       string   `json:"type"`
}

type SignalFilter struct {
	SourceType string `json:"source_type,omitempty"`
	Status     string `json:"status,omitempty"`
}
