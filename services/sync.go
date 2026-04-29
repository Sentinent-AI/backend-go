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
	slackClient    slackSyncClient
	tokenEncryptor *utils.TokenEncryptor
	ticker         *time.Ticker
	stopChan       chan bool
}

type slackSyncClient interface {
	GetChannels(accessToken string) ([]SlackChannel, *RateLimitInfo, error)
	GetMessages(accessToken, channelID string, limit int, oldest string) ([]SlackMessage, *RateLimitInfo, error)
	GetUserInfo(accessToken, userID string) (*SlackUserResponse, *RateLimitInfo, error)
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

	type syncRecord struct {
		integration    models.ExternalIntegration
		encryptedToken string
	}

	records := make([]syncRecord, 0)
	for rows.Next() {
		var integration models.ExternalIntegration
		var encryptedToken string
		var workspaceID sql.NullInt64
		err := rows.Scan(
			&integration.ID, &integration.UserID, &workspaceID,
			&integration.Provider, &encryptedToken, &integration.Metadata,
		)
		if err != nil {
			continue
		}
		if workspaceID.Valid {
			integration.WorkspaceID = int(workspaceID.Int64)
		}
		records = append(records, syncRecord{
			integration:    integration,
			encryptedToken: encryptedToken,
		})
	}

	if err := rows.Err(); err != nil {
		log.Printf("Failed while iterating integrations: %v", err)
		return
	}
	if err := rows.Close(); err != nil {
		log.Printf("Failed to close integration rows: %v", err)
		return
	}

	for _, record := range records {
		// Decrypt token
		accessToken, err := s.tokenEncryptor.Decrypt(record.encryptedToken)
		if err != nil {
			log.Printf("Failed to decrypt token for integration %d: %v", record.integration.ID, err)
			continue
		}

		switch record.integration.Provider {
		case "slack":
			s.syncSlackIntegration(&record.integration, accessToken)
		case "github":
			// GitHub sync uses its own token management via GetGitHubClient
			go func(userID, workspaceID int) {
				if err := SyncGitHubSignals(userID, workspaceID); err != nil {
					log.Printf("Background GitHub sync error for user %d workspace %d: %v", userID, workspaceID, err)
				}
			}(record.integration.UserID, record.integration.WorkspaceID)
		case "jira":
			// Jira sync uses its own token management via GetJiraClient (with refresh)
			go func(userID, workspaceID int) {
				if err := SyncJiraSignals(userID, workspaceID); err != nil {
					log.Printf("Background Jira sync error for user %d workspace %d: %v", userID, workspaceID, err)
				}
			}(record.integration.UserID, record.integration.WorkspaceID)
		default:
			log.Printf("Unknown provider: %s", record.integration.Provider)
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

	// Cache for user names to avoid redundant API calls across channels
	userCache := make(map[string]string)
	var maxTS float64

	// Fetch messages from each channel
	for _, channelID := range channels {
		oldestStr := ""
		if lastSync > 0 {
			oldestStr = fmt.Sprintf("%.6f", lastSync)
		}

		messages, rateLimit, err := s.slackClient.GetMessages(accessToken, channelID, 100, oldestStr)
		if err != nil {
			if rateLimit != nil && rateLimit.IsRateLimited() {
				log.Printf("Rate limited by Slack API, waiting %v", rateLimit.WaitDuration())
				time.Sleep(rateLimit.WaitDuration())
				continue
			}
			if IsSlackAPIError(err, "not_in_channel") {
				log.Printf("Skipping Slack channel %s during sync: %v", channelID, err)
				continue
			}
			log.Printf("Failed to fetch messages from channel %s: %v", channelID, err)
			continue
		}

		// Use a transaction for all messages in this channel for speed
		tx, err := database.DB.Begin()
		if err != nil {
			log.Printf("Failed to start transaction for channel %s: %v", channelID, err)
			continue
		}

		// Process and store messages
		for _, msg := range messages {
			if msg.Type != "message" || msg.User == "" {
				continue
			}

			// Track latest message timestamp across all channels
			if ts, err := strconv.ParseFloat(msg.TS, 64); err == nil {
				if ts > maxTS {
					maxTS = ts
				}
			}

			sourceID := buildSlackSignalSourceID(channelID, msg.TS)

			// Get user info for author name
			authorName := msg.User
			if cachedName, ok := userCache[msg.User]; ok {
				authorName = cachedName
			} else {
				// Only fetch if not already in cache
				userResp, _, err := s.slackClient.GetUserInfo(accessToken, msg.User)
				if err == nil && userResp != nil {
					if userResp.User.RealName != "" {
						authorName = userResp.User.RealName
					} else if userResp.User.Name != "" {
						authorName = userResp.User.Name
					}
					userCache[msg.User] = authorName
				}
			}

			// Store metadata
			msgMetadata := map[string]interface{}{
				"channel_id": channelID,
				"ts":         msg.TS,
				"user_id":    msg.User,
			}
			metadataJSON, _ := json.Marshal(msgMetadata)

			title := truncate(msg.Text, 100)
			if title == "" {
				title = "Slack Message"
			}

			// Use UPSERT to handle duplicates and updates
			_, err = tx.Exec(
				`INSERT INTO signals 
				 (user_id, workspace_id, source_type, source_id, external_id, title, content, body, author, status, source_metadata, received_at, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
				 ON CONFLICT(user_id, source_type, source_id) DO UPDATE SET
					title = excluded.title,
					content = excluded.content,
					body = excluded.body,
					author = excluded.author,
					source_metadata = excluded.source_metadata,
					updated_at = CURRENT_TIMESTAMP`,
				integration.UserID, integration.WorkspaceID, models.SourceTypeSlack,
				sourceID, msg.TS, title, msg.Text, msg.Text, authorName,
				models.SignalStatusUnread, string(metadataJSON), time.Unix(msg.Timestamp, 0),
			)
			if err != nil {
				log.Printf("Failed to prepare upsert for Slack signal: %v", err)
			}
		}

		if err := tx.Commit(); err != nil {
			log.Printf("Failed to commit transaction for channel %s: %v", channelID, err)
		}

		// Respect rate limits only when Slack actually returned limit metadata.
		if rateLimit != nil && rateLimit.Limit > 0 && rateLimit.Remaining < 5 {
			time.Sleep(time.Duration(60/rateLimit.Limit) * time.Second)
		}
	}

	if maxTS > 0 {
		metadata["last_sync"] = maxTS
		newMetadata, _ := json.Marshal(metadata)
		_, err := database.DB.Exec(
			"UPDATE external_integrations SET metadata = ?, updated_at = ? WHERE id = ?",
			string(newMetadata), time.Now(), integration.ID,
		)
		if err != nil {
			log.Printf("Failed to update last sync timestamp: %v", err)
		}
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
	var workspaceID sql.NullInt64
	err := database.DB.QueryRow(
		"SELECT id, user_id, workspace_id, provider, access_token, metadata FROM external_integrations WHERE id = ?",
		integrationID,
	).Scan(
		&integration.ID, &integration.UserID, &workspaceID,
		&integration.Provider, &encryptedToken, &integration.Metadata,
	)
	if workspaceID.Valid {
		integration.WorkspaceID = int(workspaceID.Int64)
	}
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

// SyncSlackSignals triggers a manual sync for Slack signals
func SyncSlackSignals(userID, workspaceID int) error {
	var integration models.ExternalIntegration
	var encryptedToken string
	err := database.DB.QueryRow(
		`SELECT id, user_id, workspace_id, provider, access_token, metadata 
		 FROM external_integrations 
		 WHERE user_id = ? AND workspace_id = ? AND provider = 'slack'`,
		userID, workspaceID,
	).Scan(
		&integration.ID, &integration.UserID, &integration.WorkspaceID,
		&integration.Provider, &encryptedToken, &integration.Metadata,
	)
	if err != nil {
		return err
	}

	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		return err
	}

	accessToken, err := encryptor.Decrypt(encryptedToken)
	if err != nil {
		return err
	}

	s := NewSyncService(encryptor)
	s.syncSlackIntegration(&integration, accessToken)
	return nil
}
