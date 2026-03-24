package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	SlackAPIBaseURL = "https://slack.com/api"
)

// SlackClient handles interactions with the Slack API
type SlackClient struct {
	HTTPClient *http.Client
	BaseURL    string
}

// NewSlackClient creates a new Slack API client
func NewSlackClient() *SlackClient {
	return &SlackClient{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		BaseURL:    SlackAPIBaseURL,
	}
}

// SlackOAuthResponse represents the response from Slack OAuth token exchange
type SlackOAuthResponse struct {
	OK          bool   `json:"ok"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	BotUserID   string `json:"bot_user_id"`
	AppID       string `json:"app_id"`
	Team        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"team"`
	AuthedUser struct {
		ID string `json:"id"`
	} `json:"authed_user"`
	Error string `json:"error"`
}

// SlackChannel represents a Slack channel
type SlackChannel struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IsPrivate  bool   `json:"is_private"`
	IsArchived bool   `json:"is_archived"`
	NumMembers int    `json:"num_members"`
}

// SlackChannelsResponse represents the response from conversations.list
type SlackChannelsResponse struct {
	OK       bool           `json:"ok"`
	Channels []SlackChannel `json:"channels"`
	Error    string         `json:"error"`
}

// SlackMessage represents a Slack message
type SlackMessage struct {
	Type      string `json:"type"`
	User      string `json:"user"`
	Text      string `json:"text"`
	TS        string `json:"ts"`
	Timestamp int64
}

// SlackMessagesResponse represents the response from conversations.history
type SlackMessagesResponse struct {
	OK       bool           `json:"ok"`
	Messages []SlackMessage `json:"messages"`
	HasMore  bool           `json:"has_more"`
	Error    string         `json:"error"`
}

// SlackUserResponse represents the response from users.info
type SlackUserResponse struct {
	OK   bool `json:"ok"`
	User struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		RealName string `json:"real_name"`
	} `json:"user"`
	Error string `json:"error"`
}

// RateLimitInfo holds rate limit information from Slack API
type RateLimitInfo struct {
	Limit     int
	Remaining int
	ResetTime time.Time
}

// ExchangeCodeForToken exchanges an OAuth code for an access token
func (c *SlackClient) ExchangeCodeForToken(clientID, clientSecret, code, redirectURI string) (*SlackOAuthResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", c.BaseURL+"/oauth.v2.access", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var oauthResp SlackOAuthResponse
	if err := json.Unmarshal(body, &oauthResp); err != nil {
		return nil, err
	}

	if !oauthResp.OK {
		return nil, fmt.Errorf("slack oauth error: %s", oauthResp.Error)
	}

	return &oauthResp, nil
}

// GetChannels retrieves the list of channels for a workspace
func (c *SlackClient) GetChannels(accessToken string) ([]SlackChannel, *RateLimitInfo, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/conversations.list", nil)
	if err != nil {
		return nil, nil, err
	}

	q := req.URL.Query()
	q.Add("types", "public_channel,private_channel")
	q.Add("exclude_archived", "true")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	rateLimit := extractRateLimit(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, rateLimit, err
	}

	var channelsResp SlackChannelsResponse
	if err := json.Unmarshal(body, &channelsResp); err != nil {
		return nil, rateLimit, err
	}

	if !channelsResp.OK {
		return nil, rateLimit, fmt.Errorf("slack api error: %s", channelsResp.Error)
	}

	return channelsResp.Channels, rateLimit, nil
}

// GetMessages retrieves messages from a channel
func (c *SlackClient) GetMessages(accessToken, channelID string, limit int, oldest string) ([]SlackMessage, *RateLimitInfo, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/conversations.history", nil)
	if err != nil {
		return nil, nil, err
	}

	q := req.URL.Query()
	q.Add("channel", channelID)
	if limit > 0 {
		q.Add("limit", strconv.Itoa(limit))
	}
	if oldest != "" {
		q.Add("oldest", oldest)
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	rateLimit := extractRateLimit(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, rateLimit, err
	}

	var messagesResp SlackMessagesResponse
	if err := json.Unmarshal(body, &messagesResp); err != nil {
		return nil, rateLimit, err
	}

	if !messagesResp.OK {
		return nil, rateLimit, fmt.Errorf("slack api error: %s", messagesResp.Error)
	}

	// Convert timestamps
	for i := range messagesResp.Messages {
		if ts := messagesResp.Messages[i].TS; ts != "" {
			// Parse Slack timestamp (seconds.microseconds)
			parts := strings.Split(ts, ".")
			if len(parts) > 0 {
				sec, _ := strconv.ParseInt(parts[0], 10, 64)
				messagesResp.Messages[i].Timestamp = sec
			}
		}
	}

	return messagesResp.Messages, rateLimit, nil
}

// GetUserInfo retrieves user information
func (c *SlackClient) GetUserInfo(accessToken, userID string) (*SlackUserResponse, *RateLimitInfo, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/users.info", nil)
	if err != nil {
		return nil, nil, err
	}

	q := req.URL.Query()
	q.Add("user", userID)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	rateLimit := extractRateLimit(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, rateLimit, err
	}

	var userResp SlackUserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, rateLimit, err
	}

	if !userResp.OK {
		return nil, rateLimit, fmt.Errorf("slack api error: %s", userResp.Error)
	}

	return &userResp, rateLimit, nil
}

// MarkMessageAsRead marks a message as read using the conversations.mark API
func (c *SlackClient) MarkMessageAsRead(accessToken, channelID, timestamp string) (*RateLimitInfo, error) {
	data := url.Values{}
	data.Set("channel", channelID)
	data.Set("ts", timestamp)

	req, err := http.NewRequest("POST", c.BaseURL+"/conversations.mark", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	rateLimit := extractRateLimit(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return rateLimit, err
	}

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return rateLimit, err
	}

	if !result.OK {
		return rateLimit, fmt.Errorf("slack api error: %s", result.Error)
	}

	return rateLimit, nil
}

// extractRateLimit extracts rate limit headers from the response
func extractRateLimit(resp *http.Response) *RateLimitInfo {
	info := &RateLimitInfo{}

	if limit := resp.Header.Get("X-RateLimit-Limit"); limit != "" {
		info.Limit, _ = strconv.Atoi(limit)
	}
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		info.Remaining, _ = strconv.Atoi(remaining)
	}
	if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
		if resetSec, err := strconv.ParseInt(reset, 10, 64); err == nil {
			info.ResetTime = time.Unix(resetSec, 0)
		}
	}

	return info
}

// IsRateLimited checks if we are rate limited
func (r *RateLimitInfo) IsRateLimited() bool {
	if r == nil {
		return false
	}
	return r.Remaining <= 1 && time.Now().Before(r.ResetTime)
}

// WaitDuration returns the duration to wait before making another request
func (r *RateLimitInfo) WaitDuration() time.Duration {
	if r == nil || r.ResetTime.IsZero() {
		return 0
	}
	wait := time.Until(r.ResetTime)
	if wait < 0 {
		return 0
	}
	return wait
}

// SlackWebhookEvent represents an incoming webhook event from Slack
type SlackWebhookEvent struct {
	Token       string `json:"token"`
	TeamID      string `json:"team_id"`
	APIAppID    string `json:"api_app_id"`
	Event       json.RawMessage `json:"event"`
	Type        string `json:"type"`
	EventID     string `json:"event_id"`
	EventTime   int64  `json:"event_time"`
	AuthedUsers []string `json:"authed_users"`
	Challenge   string `json:"challenge"`
}

// SlackMessageEvent represents a message event from Slack
type SlackMessageEvent struct {
	Type    string `json:"type"`
	Channel string `json:"channel"`
	User    string `json:"user"`
	Text    string `json:"text"`
	TS      string `json:"ts"`
	ThreadTS string `json:"thread_ts"`
}

// ValidateWebhookRequest validates that a webhook request is from Slack
func (c *SlackClient) ValidateWebhookRequest(body []byte, signature, timestamp, signingSecret string) error {
	// In production, implement Slack's request signature verification
	// https://api.slack.com/authentication/verifying-requests-from-slack
	// For now, this is a placeholder
	if signingSecret == "" {
		return errors.New("signing secret not configured")
	}
	return nil
}
