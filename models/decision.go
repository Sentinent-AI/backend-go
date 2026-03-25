package models

import "time"

type DecisionStatus string

const (
	DecisionStatusDraft  DecisionStatus = "DRAFT"
	DecisionStatusOpen   DecisionStatus = "OPEN"
	DecisionStatusClosed DecisionStatus = "CLOSED"
)

type Decision struct {
	ID          int            `json:"id"`
	WorkspaceID int            `json:"workspace_id"`
	UserID      int            `json:"user_id"`
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Status      DecisionStatus `json:"status"`
	DueDate     *time.Time     `json:"due_date,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type DecisionRequest struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Status      DecisionStatus `json:"status"`
	DueDate     *time.Time     `json:"due_date"`
}
