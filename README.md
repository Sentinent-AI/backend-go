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

## Decision API

Update a decision (authenticated):

```bash
curl -X PUT http://localhost:8080/api/decisions/1 \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Q1 Launch Plan","description":"Refined timeline and risks","status":"approved"}'
```

Create a workspace:

```bash
curl -X POST http://localhost:8080/api/workspaces \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Product"}'
```

Add a user to workspace:

```bash
curl -X POST http://localhost:8080/api/workspaces/1/members \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email":"teammate@example.com"}'
```

Create a decision in workspace:

```bash
curl -X POST http://localhost:8080/api/workspaces/1/decisions \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Ship feature","description":"Rollout plan","status":"draft"}'
```
