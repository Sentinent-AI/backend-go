# Sentinent Backend

## Required Environment Variables

Set these before running the server:

- `JWT_SECRET`: HMAC secret used to sign and verify JWT tokens.
- `CORS_ALLOWED_ORIGINS`: Comma-separated list of allowed browser origins.

Optional:

- `APP_ENV`: Set to `production` (or `prod`) to enable `Secure` auth cookies.
- `TOKEN_ENCRYPTION_KEY`: Required when using Slack, GitHub, or Gmail OAuth integrations so tokens are encrypted at rest.
- `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `SLACK_REDIRECT_URI`: Slack OAuth configuration.
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`: GitHub OAuth configuration.
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`: Gmail OAuth configuration.

## Example (local development)

```powershell
$env:JWT_SECRET = "replace-with-a-long-random-secret"
$env:CORS_ALLOWED_ORIGINS = "http://localhost:4200"
$env:APP_ENV = "development"
go run .
```
