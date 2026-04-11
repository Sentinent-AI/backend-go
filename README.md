# Sentinent Backend

## Required Environment Variables

Set these before running the server:

- `JWT_SECRET`: HMAC secret used to sign and verify JWT tokens.
- `CORS_ALLOWED_ORIGINS`: Comma-separated list of allowed browser origins.

Optional:

- `APP_ENV`: Set to `production` (or `prod`) to enable `Secure` auth cookies.
- `FRONTEND_BASE_URL`: Used when generating password reset links. Defaults to `http://localhost:4200`.
- `SMTP_HOST`: SMTP host used to send password reset emails.
- `SMTP_PORT`: SMTP port used to send password reset emails.
- `SMTP_USERNAME`: SMTP username when the mail server requires authentication.
- `SMTP_PASSWORD`: SMTP password when the mail server requires authentication.
- `SMTP_FROM_EMAIL`: From address used for password reset emails.
- `SMTP_FROM_NAME`: Optional display name for password reset emails.

Production password reset email delivery requires the SMTP settings above. In non-production environments, the API falls back to returning `reset_url` in the forgot-password response when SMTP is not configured.

## Example (local development)

```powershell
$env:JWT_SECRET = "replace-with-a-long-random-secret"
$env:CORS_ALLOWED_ORIGINS = "http://localhost:4200"
$env:APP_ENV = "development"
go run .
```
