package services

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

var ErrSMTPNotConfigured = errors.New("smtp configuration is incomplete")

const smtpTimeout = 15 * time.Second

type SMTPConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string
	FromEmail string
	FromName  string
}

func LoadSMTPConfigFromEnv() (SMTPConfig, error) {
	config := SMTPConfig{
		Host:      strings.TrimSpace(os.Getenv("SMTP_HOST")),
		Username:  strings.TrimSpace(os.Getenv("SMTP_USERNAME")),
		Password:  os.Getenv("SMTP_PASSWORD"),
		FromEmail: strings.TrimSpace(os.Getenv("SMTP_FROM_EMAIL")),
		FromName:  strings.TrimSpace(os.Getenv("SMTP_FROM_NAME")),
	}

	portValue := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	if config.Host == "" || portValue == "" || config.FromEmail == "" {
		return SMTPConfig{}, ErrSMTPNotConfigured
	}

	port, err := strconv.Atoi(portValue)
	if err != nil || port <= 0 {
		return SMTPConfig{}, fmt.Errorf("invalid SMTP_PORT value %q", portValue)
	}
	config.Port = port

	return config, nil
}

func PasswordResetEmailDeliveryConfigured() bool {
	_, err := LoadSMTPConfigFromEnv()
	return err == nil
}

// sendSMTP dials the SMTP server with a hard 15-second timeout for both the
// TCP connection and the entire SMTP conversation. This prevents the caller
// from blocking indefinitely when a firewall silently drops the connection.
func sendSMTP(config SMTPConfig, message string, recipients []string) error {
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	// Dial with explicit timeout so we fail fast instead of waiting minutes.
	conn, err := net.DialTimeout("tcp", addr, smtpTimeout)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	// Apply a deadline to every subsequent read/write on this connection.
	conn.SetDeadline(time.Now().Add(smtpTimeout)) //nolint:errcheck
	defer conn.Close()

	c, err := smtp.NewClient(conn, config.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	// Upgrade to TLS via STARTTLS if the server advertises it (port 587).
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(&tls.Config{ServerName: config.Host}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}

	// Authenticate when credentials are provided.
	if config.Username != "" || config.Password != "" {
		auth := smtp.PlainAuth("", config.Username, config.Password, config.Host)
		if err = c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err = c.Mail(config.FromEmail); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, to := range recipients {
		if err = c.Rcpt(to); err != nil {
			return fmt.Errorf("smtp RCPT TO <%s>: %w", to, err)
		}
	}

	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err = wc.Write([]byte(message)); err != nil {
		wc.Close()
		return fmt.Errorf("smtp write body: %w", err)
	}
	if err = wc.Close(); err != nil {
		return fmt.Errorf("smtp close data writer: %w", err)
	}
	return c.Quit()
}

// buildMessage creates the raw SMTP message bytes from config and body.
func buildMessage(config SMTPConfig, toEmail, subject, body string) string {
	fromHeader := config.FromEmail
	if config.FromName != "" {
		fromHeader = (&mail.Address{Name: config.FromName, Address: config.FromEmail}).String()
	}
	return strings.Join([]string{
		"From: " + fromHeader,
		"To: " + toEmail,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")
}

func SendInvitationEmail(toEmail, workspaceName, invitedByEmail, acceptURL string) error {
	config, err := LoadSMTPConfigFromEnv()
	if err != nil {
		return err
	}

	subject := fmt.Sprintf("You've been invited to join %s on Sentinent", workspaceName)
	body := fmt.Sprintf(
		"Hello,\r\n\r\n%s has invited you to join the workspace \"%s\" on Sentinent.\r\n\r\nAccept your invitation here:\r\n%s\r\n\r\nThis invitation expires in 7 days. If you weren't expecting this, you can safely ignore this email.\r\n",
		invitedByEmail, workspaceName, acceptURL,
	)

	return sendSMTP(config, buildMessage(config, toEmail, subject, body), []string{toEmail})
}

func SendPasswordResetEmail(toEmail, resetURL string) error {
	config, err := LoadSMTPConfigFromEnv()
	if err != nil {
		return err
	}

	subject := "Reset your Sentinent password"
	body := fmt.Sprintf(
		"Hello,\r\n\r\nWe received a request to reset your Sentinent password.\r\n\r\nUse this link to choose a new password:\r\n%s\r\n\r\nThis link expires in 1 hour. If you didn't request this change, you can ignore this email.\r\n",
		resetURL,
	)

	return sendSMTP(config, buildMessage(config, toEmail, subject, body), []string{toEmail})
}
