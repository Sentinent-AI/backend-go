# Sentinent Backend

## Required Environment Variables

Set these before running the server:

- `JWT_SECRET`: HMAC secret used to sign and verify JWT tokens.
- `CORS_ALLOWED_ORIGINS`: Comma-separated list of allowed browser origins.

Optional:

- `APP_ENV`: Set to `production` (or `prod`) to enable `Secure` auth cookies.
- `API_BASE_URL`: Public backend base URL used for Jira OAuth callbacks. Defaults to `http://localhost:8080`.
- `FRONTEND_BASE_URL`: Used when generating password reset links. Defaults to `http://localhost:4200`.

Token encryption:

- `TOKEN_ENCRYPTION_KEY`: Secret used to encrypt integration access and refresh tokens. Required when Slack, GitHub, Gmail, or Jira integrations are enabled.

SMTP password reset delivery:

- `SMTP_HOST`: SMTP host used to send password reset emails.
- `SMTP_PORT`: SMTP port used to send password reset emails.
- `SMTP_USERNAME`: SMTP username when the mail server requires authentication.
- `SMTP_PASSWORD`: SMTP password when the mail server requires authentication.
- `SMTP_FROM_EMAIL`: From address used for password reset emails.
- `SMTP_FROM_NAME`: Optional display name for password reset emails.

Production password reset email delivery requires the SMTP settings above. In non-production environments, the API falls back to returning `reset_url` in the forgot-password response when SMTP is not configured.

Slack integration:

- `SLACK_CLIENT_ID`: Slack OAuth app client ID.
- `SLACK_CLIENT_SECRET`: Slack OAuth app client secret.
- `SLACK_REDIRECT_URI`: Optional override for the Slack OAuth callback URL. Defaults to the current request host plus `/api/integrations/slack/callback`.

GitHub integration:

- `GITHUB_CLIENT_ID`: GitHub OAuth app client ID.
- `GITHUB_CLIENT_SECRET`: GitHub OAuth app client secret.

Gmail integration:

- `GOOGLE_CLIENT_ID`: Google OAuth app client ID.
- `GOOGLE_CLIENT_SECRET`: Google OAuth app client secret.
- `GOOGLE_REDIRECT_URI`: Optional override for the Gmail OAuth callback URL. Defaults to the current request host plus `/api/integrations/gmail/callback`.

Jira integration:

- `JIRA_CLIENT_ID`: Atlassian OAuth app client ID.
- `JIRA_CLIENT_SECRET`: Atlassian OAuth app client secret.

## Example (local development)

```powershell
$env:JWT_SECRET = "replace-with-a-long-random-secret"
$env:CORS_ALLOWED_ORIGINS = "http://localhost:4200"
$env:APP_ENV = "development"
$env:TOKEN_ENCRYPTION_KEY = "replace-with-32-plus-random-characters"
go run .
```
