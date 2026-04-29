package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// mockHTTPClient implements a mock HTTP client for testing without httptest.NewServer.
type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

// newMockResponse creates a mock HTTP response with JSON body.
func newMockResponse(statusCode int, body interface{}, headers map[string]string) (*http.Response, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(bodyBytes))),
	}
	resp.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	return resp, nil
}

// signSlackBody creates a valid Slack signature for test requests.
func signSlackBody(body []byte, timestamp, secret string) string {
	baseString := fmt.Sprintf("v0:%s:%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(baseString))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func TestSlackClient_GetChannels_ReturnsChannels(t *testing.T) {
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/api/conversations.list" {
					t.Errorf("expected path /api/conversations.list, got %s", req.URL.Path)
				}
				if req.Header.Get("Authorization") != "Bearer test-token" {
					t.Errorf("expected Bearer test-token")
				}
				return newMockResponse(200, map[string]interface{}{
					"ok": true,
					"channels": []map[string]interface{}{
						{"id": "C123", "name": "general", "is_private": false, "is_archived": false, "num_members": 10},
						{"id": "C456", "name": "random", "is_private": false, "is_archived": false, "num_members": 5},
					},
				}, map[string]string{
					"X-RateLimit-Limit":     "120",
					"X-RateLimit-Remaining": "119",
					"X-RateLimit-Reset":     fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()),
				})
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	channels, rateLimit, err := client.GetChannels("test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(channels) != 2 {
		t.Fatalf("expected 2 channels, got %d", len(channels))
	}
	if channels[0].ID != "C123" || channels[0].Name != "general" {
		t.Fatalf("unexpected channel: %+v", channels[0])
	}
	if rateLimit == nil || rateLimit.Limit != 120 || rateLimit.Remaining != 119 {
		t.Fatalf("unexpected rate limit: %+v", rateLimit)
	}
}

func TestSlackClient_GetChannels_HandlesAPIError(t *testing.T) {
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return newMockResponse(200, map[string]interface{}{
					"ok":    false,
					"error": "invalid_auth",
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	_, _, err := client.GetChannels("bad-token")
	if err == nil {
		t.Fatal("expected error for invalid_auth")
	}
	if !IsSlackAPIError(err, "invalid_auth") {
		t.Fatalf("expected SlackAPIError invalid_auth, got %v", err)
	}
}

func TestSlackClient_GetChannels_ExcludesArchived(t *testing.T) {
	var capturedURL string
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				capturedURL = req.URL.String()
				return newMockResponse(200, map[string]interface{}{
					"ok":       true,
					"channels": []map[string]interface{}{},
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	_, _, _ = client.GetChannels("test-token")
	if !strings.Contains(capturedURL, "exclude_archived=true") {
		t.Errorf("expected exclude_archived=true in URL: %s", capturedURL)
	}
}

func TestSlackClient_GetMessages_ReturnsMessages(t *testing.T) {
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/api/conversations.history" {
					t.Errorf("expected path /api/conversations.history")
				}
				if req.URL.Query().Get("channel") != "C123" {
					t.Errorf("expected channel=C123")
				}
				return newMockResponse(200, map[string]interface{}{
					"ok":       true,
					"messages": []map[string]interface{}{
						{"type": "message", "user": "U1", "text": "hello", "ts": "1234567890.123"},
						{"type": "message", "user": "U2", "text": "world", "ts": "1234567891.456"},
					},
					"has_more": false,
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	messages, _, err := client.GetMessages("test-token", "C123", 10, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(messages))
	}
	if messages[0].Text != "hello" || messages[1].Text != "world" {
		t.Fatalf("unexpected messages: %+v", messages)
	}
	if messages[0].Timestamp != 1234567890 {
		t.Fatalf("expected timestamp 1234567890, got %d", messages[0].Timestamp)
	}
}

func TestSlackClient_GetMessages_WithOldestParameter(t *testing.T) {
	var capturedURL string
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				capturedURL = req.URL.String()
				return newMockResponse(200, map[string]interface{}{
					"ok":       true,
					"messages": []map[string]interface{}{},
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	_, _, _ = client.GetMessages("test-token", "C123", 0, "1234567890.000")
	if !strings.Contains(capturedURL, "oldest=1234567890.000") {
		t.Errorf("expected oldest parameter in URL: %s", capturedURL)
	}
}

func TestSlackClient_GetMessages_InvalidChannel(t *testing.T) {
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return newMockResponse(200, map[string]interface{}{
					"ok":    false,
					"error": "channel_not_found",
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	_, _, err := client.GetMessages("test-token", "C999", 10, "")
	if err == nil {
		t.Fatal("expected error for channel_not_found")
	}
	if !IsSlackAPIError(err, "channel_not_found") {
		t.Fatalf("expected SlackAPIError channel_not_found, got %v", err)
	}
}

func TestSlackClient_GetUserInfo_ReturnsUser(t *testing.T) {
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/api/users.info" {
					t.Errorf("expected path /api/users.info")
				}
				if req.URL.Query().Get("user") != "U123" {
					t.Errorf("expected user=U123")
				}
				return newMockResponse(200, map[string]interface{}{
					"ok": true,
					"user": map[string]interface{}{
						"id":        "U123",
						"name":      "testuser",
						"real_name": "Test User",
					},
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	userResp, _, err := client.GetUserInfo("test-token", "U123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userResp.User.ID != "U123" || userResp.User.Name != "testuser" || userResp.User.RealName != "Test User" {
		t.Fatalf("unexpected user: %+v", userResp.User)
	}
}

func TestSlackClient_GetUserInfo_UserNotFound(t *testing.T) {
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return newMockResponse(200, map[string]interface{}{
					"ok":    false,
					"error": "user_not_found",
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	_, _, err := client.GetUserInfo("test-token", "U999")
	if err == nil {
		t.Fatal("expected error for user_not_found")
	}
	if !IsSlackAPIError(err, "user_not_found") {
		t.Fatalf("expected SlackAPIError user_not_found, got %v", err)
	}
}

func TestSlackClient_MarkMessageAsRead_Success(t *testing.T) {
	var capturedBody string
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/api/conversations.mark" {
					t.Errorf("expected path /api/conversations.mark")
				}
				if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Errorf("expected form content type")
				}
				body, _ := io.ReadAll(req.Body)
				capturedBody = string(body)
				return newMockResponse(200, map[string]interface{}{
					"ok": true,
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	_, err := client.MarkMessageAsRead("test-token", "C123", "1234567890.123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(capturedBody, "channel=C123") || !strings.Contains(capturedBody, "ts=1234567890.123") {
		t.Errorf("expected channel and ts in body: %s", capturedBody)
	}
}

func TestSlackClient_MarkMessageAsRead_Failed(t *testing.T) {
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return newMockResponse(200, map[string]interface{}{
					"ok":    false,
					"error": "channel_not_found",
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	_, err := client.MarkMessageAsRead("test-token", "C999", "1234567890.123")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRateLimitInfo_IsRateLimited(t *testing.T) {
	tests := []struct {
		name        string
		info        *RateLimitInfo
		now         time.Time
		shouldLimit bool
	}{
		{
			name:        "nil rate limit",
			info:        nil,
			shouldLimit: false,
		},
		{
			name: "remaining > 1, not limited",
			info: &RateLimitInfo{
				Limit:     120,
				Remaining: 50,
				ResetTime: time.Now().Add(time.Hour),
			},
			shouldLimit: false,
		},
		{
			name: "remaining <= 1, still before reset",
			info: &RateLimitInfo{
				Limit:     120,
				Remaining: 1,
				ResetTime: time.Now().Add(5 * time.Minute),
			},
			shouldLimit: true,
		},
		{
			name: "past reset time",
			info: &RateLimitInfo{
				Limit:     120,
				Remaining: 0,
				ResetTime: time.Now().Add(-time.Minute),
			},
			shouldLimit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.info.IsRateLimited()
			if result != tt.shouldLimit {
				t.Fatalf("expected rate limited = %v, got %v", tt.shouldLimit, result)
			}
		})
	}
}

func TestRateLimitInfo_WaitDuration(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		info     *RateLimitInfo
		expected time.Duration
	}{
		{
			name:     "nil rate limit",
			info:     nil,
			expected: 0,
		},
		{
			name: "future reset time",
			info: &RateLimitInfo{
				ResetTime: now.Add(10 * time.Minute),
			},
			expected: 10*time.Minute - time.Second, // approximate
		},
		{
			name: "past reset time",
			info: &RateLimitInfo{
				ResetTime: now.Add(-time.Minute),
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.info.WaitDuration()
			if tt.info != nil && tt.info.ResetTime.After(now) {
				// Allow some tolerance for the future case
				if result < 9*time.Minute || result > 11*time.Minute {
					t.Fatalf("expected ~10 min wait, got %v", result)
				}
			} else {
				if result != tt.expected {
					t.Fatalf("expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}

func TestExchangeCodeForToken_Success(t *testing.T) {
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/api/oauth.v2.access" {
					t.Errorf("expected path /api/oauth.v2.access")
				}
				if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Errorf("expected form content type")
				}
				body, _ := io.ReadAll(req.Body)
				bodyStr := string(body)
				if !strings.Contains(bodyStr, "client_id=test-client") ||
					!strings.Contains(bodyStr, "client_secret=test-secret") ||
					!strings.Contains(bodyStr, "code=auth-code") {
					t.Errorf("unexpected body: %s", bodyStr)
				}
				return newMockResponse(200, map[string]interface{}{
					"ok":           true,
					"access_token":  "xoxb-test-token",
					"token_type":    "Bearer",
					"scope":        "channels:read,channels:history",
					"bot_user_id":  "B123",
					"app_id":       "A123",
					"team":         map[string]interface{}{"id": "T123", "name": "Test Team"},
					"authed_user":  map[string]interface{}{"id": "U123"},
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	resp, err := client.ExchangeCodeForToken("test-client", "test-secret", "auth-code", "http://localhost/callback")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.OK || resp.AccessToken != "xoxb-test-token" || resp.Team.ID != "T123" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestExchangeCodeForToken_InvalidCode(t *testing.T) {
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return newMockResponse(200, map[string]interface{}{
					"ok":    false,
					"error": "invalid_code",
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	_, err := client.ExchangeCodeForToken("test-client", "test-secret", "bad-code", "http://localhost/callback")
	if err == nil {
		t.Fatal("expected error for invalid_code")
	}
	if !IsSlackAPIError(err, "invalid_code") {
		t.Fatalf("expected SlackAPIError invalid_code, got %v", err)
	}
}

func TestValidateWebhookRequest_ValidSignature(t *testing.T) {
	client := NewSlackClient()
	body := []byte(`{"type":"event_callback","event":{"type":"message"}}`)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	signature := signSlackBody(body, timestamp, "test-signing-secret")

	err := client.ValidateWebhookRequest(body, signature, timestamp, "test-signing-secret")
	if err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
}

func TestValidateWebhookRequest_InvalidSignature(t *testing.T) {
	client := NewSlackClient()
	body := []byte(`{"type":"event_callback"}`)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	signature := signSlackBody(body, timestamp, "wrong-secret")

	err := client.ValidateWebhookRequest(body, signature, timestamp, "test-signing-secret")
	if err == nil {
		t.Fatal("expected invalid signature error")
	}
}

func TestValidateWebhookRequest_StaleTimestamp(t *testing.T) {
	client := NewSlackClient()
	body := []byte(`{"type":"event_callback"}`)
	timestamp := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
	signature := signSlackBody(body, timestamp, "test-signing-secret")

	err := client.ValidateWebhookRequest(body, signature, timestamp, "test-signing-secret")
	if err == nil {
		t.Fatal("expected stale timestamp error")
	}
}

func TestValidateWebhookRequest_MissingSecret(t *testing.T) {
	client := NewSlackClient()
	body := []byte(`{"type":"event_callback"}`)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	err := client.ValidateWebhookRequest(body, "v0=abcdef", timestamp, "")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestValidateWebhookRequest_InvalidFormat(t *testing.T) {
	client := NewSlackClient()
	body := []byte(`{"type":"event_callback"}`)

	err := client.ValidateWebhookRequest(body, "invalid-format", "1234567890", "secret")
	if err == nil {
		t.Fatal("expected error for invalid signature format")
	}
}

func TestGetMessages_InvalidLimit(t *testing.T) {
	// Test that invalid limit values don't cause issues
	client := &SlackClient{
		HTTPClient: &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				// When limit=0 or negative, it shouldn't be added to query
				if req.URL.Query().Get("limit") != "" {
					t.Errorf("expected no limit parameter for 0 value")
				}
				return newMockResponse(200, map[string]interface{}{
					"ok":       true,
					"messages": []map[string]interface{}{},
				}, nil)
			},
		},
		BaseURL: SlackAPIBaseURL,
	}

	_, _, _ = client.GetMessages("test-token", "C123", 0, "")
}

func TestIsSlackAPIError_Helper(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		code     string
		expected bool
	}{
		{
			name:     "matching code",
			err:       &SlackAPIError{Code: "invalid_auth"},
			code:     "invalid_auth",
			expected: true,
		},
		{
			name:     "non-matching code",
			err:       &SlackAPIError{Code: "invalid_auth"},
			code:     "channel_not_found",
			expected: false,
		},
		{
			name:     "non-SlackAPIError",
			err:       errors.New("some other error"),
			code:     "invalid_auth",
			expected: false,
		},
		{
			name:     "nil error",
			err:       nil,
			code:     "invalid_auth",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSlackAPIError(tt.err, tt.code)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
