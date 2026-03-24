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
)

func main() {
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

	// Initialize GitHub service (optional - won't fail if env vars not set)
	if err := services.InitGitHubService(); err != nil {
		log.Printf("GitHub integration not configured: %v", err)
	}

	// Create a new ServeMux for our application routes
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/api/signup", handlers.Signup)
	mux.HandleFunc("/api/login", handlers.Signin) // Frontend calls /login

	// GitHub OAuth callback (public)
	mux.HandleFunc("/api/integrations/github/callback", handlers.GitHubCallbackHandler)

	// Protected routes
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, ok := r.Context().Value(middleware.UserEmailKey).(string)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("Hello, " + email))
	})

	mux.Handle("/api/protected", middleware.AuthMiddleware(protectedHandler))

	// Integration routes (protected)
	mux.Handle("/api/integrations/github/auth", middleware.AuthMiddleware(http.HandlerFunc(handlers.GitHubAuthHandler)))
	mux.Handle("/api/integrations/github/repos", middleware.AuthMiddleware(http.HandlerFunc(handlers.GitHubReposHandler)))
	mux.Handle("/api/integrations/github/sync", middleware.AuthMiddleware(http.HandlerFunc(handlers.GitHubSyncHandler)))
	mux.Handle("/api/integrations/github", middleware.AuthMiddleware(http.HandlerFunc(handlers.GitHubDisconnectHandler)))
	mux.Handle("/api/integrations/status", middleware.AuthMiddleware(http.HandlerFunc(handlers.IntegrationStatusHandler)))

	// Signals routes (protected)
	mux.Handle("/api/signals", middleware.AuthMiddleware(http.HandlerFunc(handlers.SignalsHandler)))

	// Webhook routes (public, but should verify signature in production)
	mux.HandleFunc("/api/webhooks/github", handlers.GitHubWebhookHandler)

	// Apply CORS middleware to the entire mux
	handler := middleware.CorsMiddleware(mux)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
