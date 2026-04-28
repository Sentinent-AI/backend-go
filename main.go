package main

import (
	"log"
	"net/http"
	"os"
	"sentinent-backend/database"
	"sentinent-backend/handlers"
	"sentinent-backend/middleware"
	"sentinent-backend/services"
	"sentinent-backend/utils"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	// Attempt to load .env file; log but proceed if it fails (it might be set in environment directly in prod)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on system environment variables")
	}

	jwtSecret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}
	utils.JwtKey = []byte(jwtSecret)

	corsAllowedOrigins := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if corsAllowedOrigins == "" {
		log.Fatal("CORS_ALLOWED_ORIGINS is required (comma-separated origins)")
	}
	if err := middleware.SetAllowedOrigins(strings.Split(corsAllowedOrigins, ",")); err != nil {
		log.Fatalf("invalid CORS_ALLOWED_ORIGINS: %v", err)
	}

	database.InitDB()

	// Initialize optional integration providers.
	if err := handlers.InitIntegrationHandlers(); err != nil {
		log.Printf("Some integrations are unavailable: %v", err)
	}
	if err := services.InitGitHubService(); err != nil {
		log.Printf("GitHub integration not configured: %v", err)
	}
	if err := services.InitJiraService(); err != nil {
		log.Printf("Jira integration not configured: %v", err)
	}
	if tokenEncryptor, err := utils.NewTokenEncryptor(); err == nil {
		syncService := services.NewSyncService(tokenEncryptor)
		syncService.Start(5 * time.Minute)
		defer syncService.Stop()
	} else {
		log.Printf("Background integration sync disabled: %v", err)
	}

	// Create a new ServeMux for our application routes
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/api/signup", handlers.Signup)
	mux.HandleFunc("/api/login", handlers.Signin) // Frontend calls /login
	mux.HandleFunc("/api/logout", handlers.Logout)
	mux.HandleFunc("/api/forgot-password", handlers.ForgotPassword)
	mux.HandleFunc("/api/reset-password/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.ValidatePasswordResetToken(w, r)
		case http.MethodPost:
			handlers.ResetPassword(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Provider callbacks (public)
	mux.HandleFunc("/api/integrations/slack/callback", handlers.SlackCallback)
	mux.HandleFunc("/api/integrations/github/callback", handlers.GitHubCallbackHandler)
	mux.HandleFunc("/api/integrations/gmail/callback", handlers.GmailCallbackHandler)
	mux.HandleFunc("/api/integrations/jira/callback", handlers.JiraCallbackHandler)

	// Protected routes
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, ok := middleware.GetUserEmail(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("Hello, " + email))
	})

	mux.Handle("/api/protected", middleware.AuthMiddleware(protectedHandler))

	// Integration routes (protected)
	mux.Handle("/api/profile", middleware.AuthMiddleware(http.HandlerFunc(handlers.ProfileHandler)))
	mux.Handle("/api/integrations", middleware.AuthMiddleware(http.HandlerFunc(handlers.GetIntegrations)))
	mux.Handle("/api/integrations/slack/auth", middleware.AuthMiddleware(http.HandlerFunc(handlers.SlackAuth)))
	mux.Handle("/api/integrations/slack/channels", middleware.AuthMiddleware(http.HandlerFunc(handlers.GetSlackChannels)))
	mux.Handle("/api/integrations/github/auth", middleware.AuthMiddleware(http.HandlerFunc(handlers.GitHubAuthHandler)))
	mux.Handle("/api/integrations/github/repos", middleware.AuthMiddleware(http.HandlerFunc(handlers.GitHubReposHandler)))
	mux.Handle("/api/integrations/github/sync", middleware.AuthMiddleware(http.HandlerFunc(handlers.GitHubSyncHandler)))
	mux.Handle("/api/integrations/github", middleware.AuthMiddleware(http.HandlerFunc(handlers.GitHubDisconnectHandler)))
	mux.Handle("/api/integrations/gmail/auth", middleware.AuthMiddleware(http.HandlerFunc(handlers.GmailAuthHandler)))
	mux.Handle("/api/integrations/gmail", middleware.AuthMiddleware(http.HandlerFunc(handlers.GmailDisconnectHandler)))
	mux.Handle("/api/integrations/jira/auth", middleware.AuthMiddleware(http.HandlerFunc(handlers.JiraAuthHandler)))
	mux.Handle("/api/integrations/jira/projects", middleware.AuthMiddleware(http.HandlerFunc(handlers.JiraProjectsHandler)))
	mux.Handle("/api/integrations/jira/sync", middleware.AuthMiddleware(http.HandlerFunc(handlers.JiraSyncHandler)))
	mux.Handle("/api/integrations/jira/issues/", middleware.AuthMiddleware(http.HandlerFunc(handlers.JiraIssueActionHandler)))
	mux.Handle("/api/integrations/jira", middleware.AuthMiddleware(http.HandlerFunc(handlers.JiraDisconnectHandler)))
	mux.Handle("/api/integrations/status", middleware.AuthMiddleware(http.HandlerFunc(handlers.IntegrationStatusHandler)))
	mux.Handle("/api/integrations/", middleware.AuthMiddleware(http.HandlerFunc(handlers.DeleteIntegration)))

	// Signal routes (protected)
	mux.Handle("/api/signals", middleware.AuthMiddleware(http.HandlerFunc(handlers.SignalsHandler)))
	mux.Handle("/api/workspaces", middleware.AuthMiddleware(http.HandlerFunc(handlers.WorkspacesRouter)))
	mux.Handle("/api/workspaces/", middleware.AuthMiddleware(http.HandlerFunc(handlers.WorkspacesRouter)))
	mux.Handle("/api/invitations/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			handlers.ValidateInvitation(w, r)
		case r.Method == http.MethodDelete:
			middleware.AuthMiddleware(http.HandlerFunc(handlers.CancelInvitation)).ServeHTTP(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/accept"):
			middleware.AuthMiddleware(http.HandlerFunc(handlers.AcceptInvitation)).ServeHTTP(w, r)
		default:
			http.Error(w, "Not found", http.StatusNotFound)
		}
	}))
	mux.Handle("/api/signals/", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodGet && !strings.HasSuffix(path, "/read") && !strings.HasSuffix(path, "/archive"):
			handlers.GetSignal(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/read"):
			handlers.MarkSignalAsRead(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/archive"):
			handlers.ArchiveSignal(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	// Webhook routes (public, but should verify signature in production)
	mux.HandleFunc("/api/webhooks/github", handlers.GitHubWebhookHandler)

	// Apply CORS and logging middleware
	handler := loggingMiddleware(middleware.CorsMiddleware(mux))

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
