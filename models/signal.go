package models

import "time"

const (
	SourceTypeSlack     = "slack"
	SourceTypeGitHub    = "github"
	SignalStatusUnread  = "unread"
	SignalStatusRead    = "read"
	SignalStatusArchived = "archived"
)

type Signal struct {
	ID             int             `json:"id"`
	UserID         int             `json:"user_id"`
	WorkspaceID    int             `json:"workspace_id,omitempty"`
	SourceType     string          `json:"source_type"`
	SourceID       string          `json:"source_id"`
	ExternalID     string          `json:"external_id,omitempty"`
	Title          string          `json:"title"`
	Content        string          `json:"content,omitempty"`
	Author         string          `json:"author,omitempty"`
	Body           string          `json:"body,omitempty"`
	URL            string          `json:"url,omitempty"`
	Status         string          `json:"status"`
	SourceMetadata *GitHubMetadata `json:"source_metadata,omitempty"`
	ReceivedAt     time.Time       `json:"received_at,omitempty"`
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
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

type SignalListResponse struct {
	Signals []Signal `json:"signals"`
	Total   int      `json:"total"`
}
