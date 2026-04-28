package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestValidateWebhookRequestAcceptsValidSlackSignature(t *testing.T) {
	client := NewSlackClient()
	body := []byte(`{"type":"event_callback"}`)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	signature := signSlackWebhookBody(body, timestamp, "slack-secret")

	if err := client.ValidateWebhookRequest(body, signature, timestamp, "slack-secret"); err != nil {
		t.Fatalf("expected valid Slack signature, got %v", err)
	}
}

func TestValidateWebhookRequestRejectsInvalidSlackSignature(t *testing.T) {
	client := NewSlackClient()
	body := []byte(`{"type":"event_callback"}`)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	signature := signSlackWebhookBody(body, timestamp, "wrong-secret")

	if err := client.ValidateWebhookRequest(body, signature, timestamp, "slack-secret"); err == nil {
		t.Fatal("expected invalid Slack signature to be rejected")
	}
}

func TestValidateWebhookRequestRejectsStaleSlackTimestamp(t *testing.T) {
	client := NewSlackClient()
	body := []byte(`{"type":"event_callback"}`)
	timestamp := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
	signature := signSlackWebhookBody(body, timestamp, "slack-secret")

	if err := client.ValidateWebhookRequest(body, signature, timestamp, "slack-secret"); err == nil {
		t.Fatal("expected stale Slack timestamp to be rejected")
	}
}

func signSlackWebhookBody(body []byte, timestamp, secret string) string {
	baseString := fmt.Sprintf("v0:%s:%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(baseString))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}
