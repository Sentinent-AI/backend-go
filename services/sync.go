package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"sentinent-backend/utils"
	"strconv"
	"time"
)

// SyncService handles background synchronization of external integrations
type SyncService struct {
	slackClient    *SlackClient
	tokenEncryptor *utils.TokenEncryptor
	ticker         *time.Ticker
	stopChan       chan bool
}

// NewSyncService creates a new SyncService
func NewSyncService(encryptor *utils.TokenEncryptor) *SyncService {
	return &SyncService{
		slackClient:    NewSlackClient(),
		tokenEncryptor: encryptor,
		stopChan:       make(chan bool),
	}
}

// Start begins the background sync process
func (s *SyncService) Start(interval time.Duration) {
	s.ticker = time.NewTicker(interval)
	go s.run()
	log.Printf("Sync service started with interval: %v", interval)
}

// Stop stops the background sync process
func (s *SyncService) Stop() {
	if s.ticker != nil {
		s.ticker.Stop()
		close(s.stopChan)
	}
}

func (s *SyncService) run() {
	for {
		select {
		case <-s.ticker.C:
			s.syncAllIntegrations()
		case <-s.stopChan:
			return
		}
	}
}

// syncAllIntegrations syncs all active integrations
func (s *SyncService) syncAllIntegrations() {
	rows, err := database.DB.Query(
		"SELECT id, user_id, workspace_id, provider, access_token, metadata FROM external_integrations",
	)
	if err != nil {
		log.Printf("Failed to fetch integrations: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var integration models.ExternalIntegration
		var encryptedToken string
		err := rows.Scan(
			&integration.ID, &integration.UserID, &integration.WorkspaceID,
			&integration.Provider, &encryptedToken, &integration.Metadata,
		)
		if err != nil {
			continue
		}

		// Decrypt token
		accessToken, err := s.tokenEncryptor.Decrypt(encryptedToken)
		if err != nil {
			log.Printf("Failed to decrypt token for integration %d: %v", integration.ID, err)
			continue
		}

		switch integration.Provider {
		case "slack":
			s.syncSlackIntegration(&integration, accessToken)
		default:
			log.Printf("Unknown provider: %s", integration.Provider)
		}
	}
}

// syncSlackIntegration syncs messages from Slack
func (s *SyncService) syncSlackIntegration(integration *models.ExternalIntegration, accessToken string) {
	// Parse metadata to get selected channels
	var metadata map[string]interface{}
	if err := json.Unmarshal([]byte(integration.Metadata), &metadata); err != nil {
		log.Printf("Failed to parse metadata for integration %d: %v", integration.ID, err)
		return
	}

	// Get channels to monitor (stored in metadata as "selected_channels")
	var channels []string
	if selectedChannels, ok := metadata["selected_channels"].([]interface{}); ok {
		for _, ch := range selectedChannels {
			if chStr, ok := ch.(string); ok {
				channels = append(channels, chStr)
			}
		}
	}

	// If no channels selected, fetch all channels
	if len(channels) == 0 {
		slackChannels, rateLimit, err := s.slackClient.GetChannels(accessToken)
		if err != nil {
			if rateLimit != nil && rateLimit.IsRateLimited() {
				log.Printf("Rate limited by Slack API, waiting %v", rateLimit.WaitDuration())
				time.Sleep(rateLimit.WaitDuration())
			}
			log.Printf("Failed to fetch Slack channels: %v", err)
			return
		}

		for _, ch := range slackChannels {
			channels = append(channels, ch.ID)
		}
	}

	// Get last sync timestamp
	var lastSync float64
	if lastSyncVal, ok := metadata["last_sync"]; ok {
		switch v := lastSyncVal.(type) {
		case float64:
			lastSync = v
		case string:
			lastSync, _ = strconv.ParseFloat(v, 64)
		}
	}

	// Fetch messages from each channel
	for _, channelID := range channels {
		messages, rateLimit, err := s.slackClient.GetMessages(accessToken, channelID, 100, fmt.Sprintf("%.6f", lastSync))
		if err != nil {
			if rateLimit != nil && rateLimit.IsRateLimited() {
				log.Printf("Rate limited by Slack API, waiting %v", rateLimit.WaitDuration())
				time.Sleep(rateLimit.WaitDuration())
				continue
			}
			log.Printf("Failed to fetch messages from channel %s: %v", channelID, err)
			continue
		}

		// Process and store messages
		for _, msg := range messages {
			if msg.Type != "message" || msg.User == "" {
				continue
			}

			sourceID := buildSlackSignalSourceID(channelID, msg.TS)

			// Get user info for author name
			authorName := msg.User
			userResp, _, err := s.slackClient.GetUserInfo(accessToken, msg.User)
			if err == nil && userResp != nil {
				if userResp.User.RealName != "" {
					authorName = userResp.User.RealName
				} else if userResp.User.Name != "" {
					authorName = userResp.User.Name
				}
			}

			// Check if signal already exists
			var existingID int
			err = database.DB.QueryRow(
				`SELECT id FROM signals
				 WHERE user_id = ? AND source_type = ?
				 AND (source_id = ? OR external_id = ?)`,
				integration.UserID, models.SourceTypeSlack, sourceID, msg.TS,
			).Scan(&existingID)

			if err == sql.ErrNoRows {
				// Insert new signal
				_, err = database.DB.Exec(
					`INSERT INTO signals (user_id, workspace_id, source_type, source_id, external_id, title, content, author, status, received_at)
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					integration.UserID, integration.WorkspaceID, models.SourceTypeSlack,
					sourceID, msg.TS, truncate(msg.Text, 100), msg.Text, authorName,
					models.SignalStatusUnread, time.Unix(msg.Timestamp, 0),
				)
				if err != nil {
					log.Printf("Failed to insert signal: %v", err)
				}
			} else if err != nil {
				log.Printf("Failed to check existing signal: %v", err)
			}
		}

		// Respect rate limits only when Slack actually returned limit metadata.
		if rateLimit != nil && rateLimit.Limit > 0 && rateLimit.Remaining < 5 {
			time.Sleep(time.Duration(60/rateLimit.Limit) * time.Second)
		}
	}

	// Update last sync timestamp
	metadata["last_sync"] = float64(time.Now().Unix())
	metadataJSON, _ := json.Marshal(metadata)
	_, err := database.DB.Exec(
		"UPDATE external_integrations SET metadata = ?, updated_at = ? WHERE id = ?",
		string(metadataJSON), time.Now(), integration.ID,
	)
	if err != nil {
		log.Printf("Failed to update last sync timestamp: %v", err)
	}

	log.Printf("Synced Slack integration %d, channels: %d", integration.ID, len(channels))
}

// truncate truncates a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func buildSlackSignalSourceID(channelID, messageTS string) string {
	return channelID + ":" + messageTS
}

// ManualSync triggers a manual sync for a specific integration
func (s *SyncService) ManualSync(integrationID int) error {
	var integration models.ExternalIntegration
	var encryptedToken string
	err := database.DB.QueryRow(
		"SELECT id, user_id, workspace_id, provider, access_token, metadata FROM external_integrations WHERE id = ?",
		integrationID,
	).Scan(
		&integration.ID, &integration.UserID, &integration.WorkspaceID,
		&integration.Provider, &encryptedToken, &integration.Metadata,
	)
	if err != nil {
		return err
	}

	accessToken, err := s.tokenEncryptor.Decrypt(encryptedToken)
	if err != nil {
		return fmt.Errorf("failed to decrypt token: %w", err)
	}

	if integration.Provider == "slack" {
		s.syncSlackIntegration(&integration, accessToken)
	}

	return nil
}
