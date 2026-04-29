package services

import (
	"errors"
	"fmt"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
)

var ErrSMTPNotConfigured = errors.New("smtp configuration is incomplete")

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

	fromHeader := config.FromEmail
	if config.FromName != "" {
		fromHeader = (&mail.Address{Name: config.FromName, Address: config.FromEmail}).String()
	}

	message := strings.Join([]string{
		"From: " + fromHeader,
		"To: " + toEmail,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	var auth smtp.Auth
	if config.Username != "" || config.Password != "" {
		auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
	}

	return smtp.SendMail(
		fmt.Sprintf("%s:%d", config.Host, config.Port),
		auth,
		config.FromEmail,
		[]string{toEmail},
		[]byte(message),
	)
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

	fromHeader := config.FromEmail
	if config.FromName != "" {
		fromHeader = (&mail.Address{Name: config.FromName, Address: config.FromEmail}).String()
	}

	message := strings.Join([]string{
		"From: " + fromHeader,
		"To: " + toEmail,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	var auth smtp.Auth
	if config.Username != "" || config.Password != "" {
		auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
	}

	return smtp.SendMail(
		fmt.Sprintf("%s:%d", config.Host, config.Port),
		auth,
		config.FromEmail,
		[]string{toEmail},
		[]byte(message),
	)
}
