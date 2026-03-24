package models

import "time"

type Signal struct {
	ID          int       `json:"id"`
	UserID      int       `json:"user_id"`
	WorkspaceID int       `json:"workspace_id"`
	SourceType  string    `json:"source_type"`
	SourceID    string    `json:"source_id"`
	ExternalID  string    `json:"external_id"`
	Title       string    `json:"title"`
	Content     string    `json:"content"`
	Author      string    `json:"author"`
	Status      string    `json:"status"`
	ReceivedAt  time.Time `json:"received_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type SignalStatus struct {
	SignalID  int       `json:"signal_id"`
	UserID    int       `json:"user_id"`
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SignalFilter struct {
	SourceType string
	Status     string
	Limit      int
	Offset     int
}

type SignalListResponse struct {
	Signals []Signal `json:"signals"`
	Total   int      `json:"total"`
}

const (
	SignalStatusUnread   = "unread"
	SignalStatusRead     = "read"
	SignalStatusArchived = "archived"
)

const (
	SourceTypeSlack = "slack"
	SourceTypeGitHub = "github"
	SourceTypeJIRA  = "jira"
	SourceTypeEmail = "email"
)
