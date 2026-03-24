package main

import (
	"log"
	"net/http"
	"os"
	"sentinent-backend/database"
	"sentinent-backend/handlers"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"strconv"
	"strings"
)

func main() {
	jwtSecret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}
	models.JwtKey = []byte(jwtSecret)

	corsAllowedOrigins := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if corsAllowedOrigins == "" {
		log.Fatal("CORS_ALLOWED_ORIGINS is required (comma-separated origins)")
	}
	if err := middleware.SetAllowedOrigins(strings.Split(corsAllowedOrigins, ",")); err != nil {
		log.Fatalf("invalid CORS_ALLOWED_ORIGINS: %v", err)
	}

	database.InitDB()

	// Create a new ServeMux for our application routes
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/api/signup", handlers.Signup)
	mux.HandleFunc("/api/login", handlers.Signin) // Frontend calls /login

	// Public invitation validation (no auth required)
	mux.HandleFunc("/api/invitations/", handleInvitationPublicRoutes)

	// Protected routes
	mux.Handle("/api/protected", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, ok := r.Context().Value(middleware.UserEmailKey).(string)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("Hello, " + email))
	})))

	// Workspace member routes (require authentication)
	mux.Handle("/api/workspaces/", middleware.AuthMiddleware(http.HandlerFunc(handleWorkspaceRoutes)))

	// Apply CORS middleware to the entire mux
	handler := middleware.CorsMiddleware(mux)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// handleInvitationPublicRoutes handles public invitation routes (validate invitation)
func handleInvitationPublicRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// GET /api/invitations/:token - Validate invitation (public)
	if r.Method == http.MethodGet && !strings.HasSuffix(path, "/accept") {
		handlers.ValidateInvitation(w, r)
		return
	}

	// POST /api/invitations/:token/accept - Accept invitation (requires auth)
	if r.Method == http.MethodPost && strings.HasSuffix(path, "/accept") {
		// This will be handled by the AuthMiddleware wrapped handler
		handlers.AcceptInvitation(w, r)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleWorkspaceRoutes handles all workspace-related routes
func handleWorkspaceRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check if this is an invitations endpoint
	if strings.Contains(path, "/invitations") {
		handleWorkspaceInvitations(w, r)
		return
	}

	// Check if this is a members endpoint
	if strings.Contains(path, "/members") {
		handleWorkspaceMembers(w, r)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleWorkspaceInvitations handles workspace invitation routes
func handleWorkspaceInvitations(w http.ResponseWriter, r *http.Request) {
	// POST /api/workspaces/:id/invitations - Create invitation (owner only)
	if r.Method == http.MethodPost {
		// Check if user is owner
		if !checkWorkspaceOwnership(w, r) {
			return
		}
		handlers.CreateInvitation(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleWorkspaceMembers handles workspace member routes
func handleWorkspaceMembers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// GET /api/workspaces/:id/members - List members (any member)
		if !checkWorkspaceMembership(w, r) {
			return
		}
		handlers.ListMembers(w, r)
	case http.MethodDelete:
		// DELETE /api/workspaces/:id/members/:userId - Remove member (owner only)
		if !checkWorkspaceOwnership(w, r) {
			return
		}
		handlers.RemoveMember(w, r)
	case http.MethodPatch:
		// PATCH /api/workspaces/:id/members/:userId - Update role (owner only)
		if !checkWorkspaceOwnership(w, r) {
			return
		}
		handlers.UpdateMemberRole(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// checkWorkspaceOwnership checks if the current user is an owner of the workspace
func checkWorkspaceOwnership(w http.ResponseWriter, r *http.Request) bool {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	workspaceID, err := extractWorkspaceID(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace ID", http.StatusBadRequest)
		return false
	}

	isOwner, err := middleware.IsWorkspaceOwner(userID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return false
	}
	if !isOwner {
		http.Error(w, "Forbidden: Only owners can perform this action", http.StatusForbidden)
		return false
	}
	return true
}

// checkWorkspaceMembership checks if the current user is a member of the workspace
func checkWorkspaceMembership(w http.ResponseWriter, r *http.Request) bool {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	workspaceID, err := extractWorkspaceID(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace ID", http.StatusBadRequest)
		return false
	}

	role, err := middleware.GetWorkspaceRole(userID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return false
	}
	if role == "" {
		http.Error(w, "Forbidden: Not a member of this workspace", http.StatusForbidden)
		return false
	}
	return true
}

// extractWorkspaceID extracts workspace ID from URL path like /api/workspaces/123/...
func extractWorkspaceID(path string) (int, error) {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "workspaces" && i+1 < len(parts) {
			return strconv.Atoi(parts[i+1])
		}
	}
	return 0, strconv.ErrSyntax
}
