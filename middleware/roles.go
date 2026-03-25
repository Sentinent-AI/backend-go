package middleware

import (
	"database/sql"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"strconv"
	"strings"
)

func RequireRole(roles ...models.WorkspaceMemberRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			workspaceID, err := extractWorkspaceID(r.URL.Path)
			if err != nil {
				http.Error(w, "Invalid workspace ID", http.StatusBadRequest)
				return
			}

			role, err := GetWorkspaceRole(userID, workspaceID)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if role == "" {
				http.Error(w, "Forbidden: Not a member of this workspace", http.StatusForbidden)
				return
			}

			for _, allowedRole := range roles {
				if role == allowedRole {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
		})
	}
}

func RequireOwner(next http.Handler) http.Handler {
	return RequireRole(models.RoleOwner)(next)
}

func RequireMember(next http.Handler) http.Handler {
	return RequireRole(models.RoleOwner, models.RoleMember)(next)
}

func RequireViewer(next http.Handler) http.Handler {
	return RequireRole(models.RoleOwner, models.RoleMember, models.RoleViewer)(next)
}

func GetWorkspaceRole(userID, workspaceID int) (models.WorkspaceMemberRole, error) {
	var role string
	err := database.DB.QueryRow(
		"SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
		workspaceID, userID,
	).Scan(&role)
	if err == nil {
		return models.WorkspaceMemberRole(role), nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}

	var ownerID int
	err = database.DB.QueryRow("SELECT owner_id FROM workspaces WHERE id = ?", workspaceID).Scan(&ownerID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if ownerID == userID {
		return models.RoleOwner, nil
	}
	return "", nil
}

func IsWorkspaceOwner(userID, workspaceID int) (bool, error) {
	var ownerID int
	err := database.DB.QueryRow("SELECT owner_id FROM workspaces WHERE id = ?", workspaceID).Scan(&ownerID)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return ownerID == userID, nil
}

func extractWorkspaceID(path string) (int, error) {
	if !strings.HasPrefix(path, "/api/workspaces/") {
		return 0, strconv.ErrSyntax
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "workspaces" {
		return 0, strconv.ErrSyntax
	}
	return strconv.Atoi(parts[2])
}
