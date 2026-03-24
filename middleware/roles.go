package middleware

import (
	"database/sql"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"strconv"
	"strings"
)

// RequireRole checks if the user has one of the required roles for a workspace
func RequireRole(roles ...models.WorkspaceMemberRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Extract workspace ID from URL path
			workspaceID, err := extractWorkspaceID(r.URL.Path)
			if err != nil {
				http.Error(w, "Invalid workspace ID", http.StatusBadRequest)
				return
			}

			// Check if user has the required role
			var userRole string
			err = database.DB.QueryRow(
				"SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
				workspaceID, userID,
			).Scan(&userRole)

			if err == sql.ErrNoRows {
				http.Error(w, "Forbidden: Not a member of this workspace", http.StatusForbidden)
				return
			}
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Check if user's role is in the allowed roles
			allowed := false
			for _, role := range roles {
				if string(role) == userRole {
					allowed = true
					break
				}
			}

			if !allowed {
				http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOwner ensures only workspace owners can access the route
func RequireOwner(next http.Handler) http.Handler {
	return RequireRole(models.RoleOwner)(next)
}

// RequireMember ensures the user is at least a member (owner or member) of the workspace
func RequireMember(next http.Handler) http.Handler {
	return RequireRole(models.RoleOwner, models.RoleMember)(next)
}

// RequireViewer ensures the user has at least viewer access to the workspace
func RequireViewer(next http.Handler) http.Handler {
	return RequireRole(models.RoleOwner, models.RoleMember, models.RoleViewer)(next)
}

// extractWorkspaceID extracts the workspace ID from the URL path
// Expected format: /api/workspaces/{id}/... or /api/invitations/...
func extractWorkspaceID(path string) (int, error) {
	// Handle /api/workspaces/{id}/... paths
	if strings.HasPrefix(path, "/api/workspaces/") {
		parts := strings.Split(path, "/")
		if len(parts) >= 4 {
			return strconv.Atoi(parts[3])
		}
	}
	return 0, nil
}

// GetWorkspaceRole returns the user's role in a workspace, or empty string if not a member
func GetWorkspaceRole(userID, workspaceID int) (models.WorkspaceMemberRole, error) {
	var role string
	err := database.DB.QueryRow(
		"SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
		workspaceID, userID,
	).Scan(&role)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return models.WorkspaceMemberRole(role), nil
}

// IsWorkspaceOwner checks if a user is the owner of a workspace
func IsWorkspaceOwner(userID, workspaceID int) (bool, error) {
	role, err := GetWorkspaceRole(userID, workspaceID)
	if err != nil {
		return false, err
	}
	return role == models.RoleOwner, nil
}
