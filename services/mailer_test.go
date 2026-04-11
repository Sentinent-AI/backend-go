package services

import "testing"

func TestLoadSMTPConfigFromEnv(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_USERNAME", "mailer")
	t.Setenv("SMTP_PASSWORD", "secret")
	t.Setenv("SMTP_FROM_EMAIL", "no-reply@example.com")
	t.Setenv("SMTP_FROM_NAME", "Sentinent")

	config, err := LoadSMTPConfigFromEnv()
	if err != nil {
		t.Fatalf("expected SMTP config to load, got error: %v", err)
	}

	if config.Host != "smtp.example.com" {
		t.Fatalf("expected host smtp.example.com, got %q", config.Host)
	}
	if config.Port != 587 {
		t.Fatalf("expected port 587, got %d", config.Port)
	}
	if config.FromEmail != "no-reply@example.com" {
		t.Fatalf("expected from email no-reply@example.com, got %q", config.FromEmail)
	}
}

func TestLoadSMTPConfigFromEnvRequiresCoreSettings(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")

	if _, err := LoadSMTPConfigFromEnv(); err != ErrSMTPNotConfigured {
		t.Fatalf("expected ErrSMTPNotConfigured, got %v", err)
	}
}

func TestLoadSMTPConfigFromEnvRejectsInvalidPort(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "invalid")
	t.Setenv("SMTP_FROM_EMAIL", "no-reply@example.com")

	if _, err := LoadSMTPConfigFromEnv(); err == nil {
		t.Fatal("expected invalid port to return an error")
	}
}
