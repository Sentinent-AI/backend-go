package models

import "time"

type ExternalIntegration struct {
	ID           int       `json:"id"`
	UserID       int       `json:"user_id"`
	WorkspaceID  int       `json:"workspace_id"`
	Provider     string    `json:"provider"`
	AccessToken  string    `json:"-"`
	RefreshToken string    `json:"-"`
	Metadata     string    `json:"metadata"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type IntegrationProvider string

const (
	ProviderSlack IntegrationProvider = "slack"
	ProviderGitHub IntegrationProvider = "github"
	ProviderJIRA IntegrationProvider = "jira"
	ProviderEmail IntegrationProvider = "email"
)
