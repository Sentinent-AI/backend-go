# Sentinent Backend

## Required Environment Variables

Set these before running the server:

- `JWT_SECRET`: HMAC secret used to sign and verify JWT tokens.
- `CORS_ALLOWED_ORIGINS`: Comma-separated list of allowed browser origins.

Optional:

- `APP_ENV`: Set to `production` (or `prod`) to enable `Secure` auth cookies.

## Example (local development)

```powershell
$env:JWT_SECRET = "replace-with-a-long-random-secret"
$env:CORS_ALLOWED_ORIGINS = "http://localhost:4200"
$env:APP_ENV = "development"
go run .
```

## Postman Testing

Import these files in Postman:

- `postman/Sentinent-Backend.postman_collection.json`
- `postman/Sentinent-Local.postman_environment.json`

Collection includes:

- `GET /api/health`
- `POST /api/signup`
- `POST /api/login` (stores JWT into `authToken`)
- `GET /api/protected` (uses `Authorization: Bearer {{authToken}}`)

Before running requests, start the server with required env vars and select the `Sentinent Local` environment.
