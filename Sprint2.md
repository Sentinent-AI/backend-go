# Sprint 2

## Backend Work Completed
- Integrated the Go backend with the frontend-facing authentication and signal routes.
- Added backend unit tests for auth handlers, auth middleware, integration handlers, signal handlers, CORS middleware, encryption utilities, validation utilities, and sync behavior.
- Hardened OAuth state handling for GitHub and Slack integration flows.
- Fixed signal status consistency and Slack message deduplication behavior in the backend.

## Backend API Documentation

### `POST /api/signup`
- Description: Creates a new user account.
- Auth: No
- Request body:
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```
- Success:
  - `201 Created`
- Common errors:
  - `400 Bad Request` for invalid JSON or invalid email format
  - `409 Conflict` if the email already exists

### `POST /api/login`
- Description: Signs in a user and returns a JWT token in both an HttpOnly cookie and JSON response.
- Auth: No
- Request body:
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```
- Success:
  - `200 OK`
  - Response body:
```json
{
  "token": "jwt-token"
}
```
- Common errors:
  - `400 Bad Request` for invalid JSON or invalid email
  - `401 Unauthorized` for invalid credentials
  - `500 Internal Server Error` for missing server JWT configuration

### `GET /api/protected`
- Description: Example protected endpoint used to verify JWT authentication.
- Auth: Yes
- Success:
  - `200 OK`
  - Response body: plain text greeting
- Common errors:
  - `401 Unauthorized`

### `GET /api/integrations`
- Description: Lists integrations for the authenticated user.
- Auth: Yes
- Query params:
  - `workspace_id` optional, filters to workspace-specific integrations plus global integrations
- Success:
  - `200 OK`
- Common errors:
  - `400 Bad Request` for invalid `workspace_id`
  - `401 Unauthorized`

### `DELETE /api/integrations/:id`
- Description: Deletes an integration owned by the authenticated user.
- Auth: Yes
- Success:
  - `204 No Content`
- Common errors:
  - `400 Bad Request` for invalid integration ID
  - `401 Unauthorized`
  - `404 Not Found`

### `GET /api/integrations/status`
- Description: Returns configured and connected status for supported integrations.
- Auth: Yes
- Query params:
  - `workspace_id` optional
- Success:
  - `200 OK`
- Response body example:
```json
[
  {
    "provider": "slack",
    "configured": true,
    "connected": true
  },
  {
    "provider": "github",
    "configured": false,
    "connected": true
  }
]
```

### `GET /api/integrations/slack/auth`
- Description: Starts Slack OAuth and returns the Slack authorization URL.
- Auth: Yes
- Query params:
  - `workspace_id` required
- Success:
  - `200 OK`
- Common errors:
  - `400 Bad Request`
  - `401 Unauthorized`
  - `503 Service Unavailable` when Slack is not configured

### `GET /api/integrations/slack/callback`
- Description: Handles the Slack OAuth callback and stores the integration token.
- Auth: No
- Query params:
  - `code` required
  - `state` required
- Success:
  - `200 OK`
- Common errors:
  - `400 Bad Request`
  - `500 Internal Server Error`
  - `503 Service Unavailable`

### `GET /api/integrations/slack/channels`
- Description: Lists Slack channels for a connected Slack integration.
- Auth: Yes
- Query params:
  - `integration_id` required
- Success:
  - `200 OK`
- Common errors:
  - `400 Bad Request`
  - `401 Unauthorized`
  - `404 Not Found`
  - `429 Too Many Requests`

### `GET /api/integrations/github/auth`
- Description: Starts GitHub OAuth and returns the GitHub authorization URL.
- Auth: Yes
- Success:
  - `200 OK`
- Common errors:
  - `401 Unauthorized`
  - `503 Service Unavailable`

### `GET /api/integrations/github/callback`
- Description: Handles the GitHub OAuth callback and stores the GitHub integration.
- Auth: No
- Query params:
  - `code` required
  - `state` required
- Success:
  - `200 OK`
- Common errors:
  - `400 Bad Request`
  - `401 Unauthorized`
  - `500 Internal Server Error`

### `GET /api/integrations/github/repos`
- Description: Lists repositories accessible to the authenticated user’s GitHub integration.
- Auth: Yes
- Success:
  - `200 OK`
- Common errors:
  - `401 Unauthorized`
  - `500 Internal Server Error`

### `POST /api/integrations/github/sync`
- Description: Starts a background GitHub signal sync for the authenticated user.
- Auth: Yes
- Success:
  - `200 OK`
  - Response body:
```json
{
  "status": "sync_started"
}
```

### `DELETE /api/integrations/github`
- Description: Disconnects the authenticated user’s GitHub integration.
- Auth: Yes
- Success:
  - `200 OK`

### `GET /api/signals`
- Description: Lists all signals for the authenticated user with optional filtering.
- Auth: Yes
- Query params:
  - `source_type` optional
  - `status` optional
- Success:
  - `200 OK`

### `GET /api/workspaces/:id/signals`
- Description: Lists workspace-scoped signals with pagination and filtering.
- Auth: Yes
- Query params:
  - `source_type` optional
  - `status` optional
  - `limit` optional
  - `offset` optional
- Success:
  - `200 OK`
- Response body example:
```json
{
  "signals": [],
  "total": 0
}
```

### `GET /api/signals/:id`
- Description: Returns one signal for the authenticated user.
- Auth: Yes
- Success:
  - `200 OK`
- Common errors:
  - `400 Bad Request`
  - `401 Unauthorized`
  - `404 Not Found`

### `POST /api/signals/:id/read`
- Description: Marks a signal as read for the authenticated user.
- Auth: Yes
- Success:
  - `204 No Content`
- Common errors:
  - `400 Bad Request`
  - `401 Unauthorized`
  - `404 Not Found`

### `POST /api/signals/:id/archive`
- Description: Marks a signal as archived for the authenticated user.
- Auth: Yes
- Success:
  - `204 No Content`
- Common errors:
  - `400 Bad Request`
  - `401 Unauthorized`
  - `404 Not Found`

### `POST /api/webhooks/github`
- Description: Receives GitHub webhook payloads.
- Auth: No
- Headers:
  - `X-GitHub-Event` required
- Success:
  - `200 OK`
- Common errors:
  - `400 Bad Request`
  - `405 Method Not Allowed`

## Backend Unit Tests

### `handlers/auth_test.go`
- `TestSignup`
- `TestSignin`
- `TestSigninCookieSecureInProduction`
- `TestSignupInvalidEmail`
- `TestSigninInvalidEmail`

### `handlers/integrations_test.go`
- `TestSlackAuthHandlerSetsSignedState`
- `TestValidateSlackOAuthStateRejectsExpiredState`
- `TestSlackCallbackHandlerAcceptsValidStateWithoutCookie`
- `TestGitHubAuthHandlerSetsSignedStateCookie`
- `TestGitHubCallbackHandlerRejectsMissingStateCookie`
- `TestGitHubCallbackHandlerRejectsTamperedState`
- `TestValidateGitHubOAuthStateRejectsExpiredState`
- `TestGitHubCallbackHandlerAcceptsValidState`
- `TestGetIntegrationsFiltersByWorkspaceAndIncludesGlobalIntegrations`
- `TestDeleteIntegrationDeletesOwnedIntegration`
- `TestDeleteIntegrationRejectsDifferentOwner`
- `TestIntegrationStatusHandlerReturnsConnectionState`

### `handlers/signals_test.go`
- `TestSignalsHandlerUsesResolvedSignalStatus`
- `TestWorkspaceSignalsStatusFilterUsesResolvedStatusForResultsAndTotal`

### `middleware/auth_test.go`
- `TestAuthMiddlewareAcceptsBearerToken`
- `TestAuthMiddlewareAcceptsCookieToken`
- `TestAuthMiddlewareRejectsMissingToken`
- `TestAuthMiddlewareRejectsMalformedBearerToken`

### `middleware/cors_test.go`
- `TestCorsMiddlewareAllowsConfiguredOrigin`
- `TestCorsMiddlewareDoesNotSetHeadersForDisallowedOrigin`
- `TestCorsMiddlewareRejectsDisallowedPreflight`
- `TestCorsMiddlewareHandlesAllowedPreflight`
- `TestSetAllowedOriginsRejectsInvalidOrigin`

### `services/github_test.go`
- `TestSplitGitHubIssuesAndPullRequests`

### `services/sync_test.go`
- `TestSyncSlackIntegrationStoresMultipleMessagesPerChannelWithoutDuplicates`

### `utils/encryption_test.go`
- `TestTokenEncryptor`
- `TestTokenEncryptor_KeyPadding`

### `utils/validation_test.go`
- `TestIsEmailValid`

## Backend Integration Notes
- The frontend can authenticate against the backend using `/api/signup` and `/api/login`.
- Protected routes depend on JWT auth via cookie or Bearer token.
- Signal and integration routes are available behind auth middleware for frontend consumption.

## Remaining Backend Work
- Add broader tests for Slack and GitHub external API edge cases.
- Add webhook signature verification for production webhook handling.
- Increase build and test automation coverage once a local Go toolchain is available in every dev environment.
