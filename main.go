package main

import (
	"log"
	"net/http"
	"os"
	"sentinent-backend/database"
	"sentinent-backend/handlers"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"sentinent-backend/services"
	"sentinent-backend/utils"
	"strings"
	"time"
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

	// Initialize integration handlers
	if err := handlers.InitIntegrationHandlers(); err != nil {
		log.Printf("Warning: Failed to initialize integration handlers: %v", err)
	}

	// Initialize token encryptor for sync service
	tokenEncryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		log.Printf("Warning: TOKEN_ENCRYPTION_KEY not set, sync service will not start: %v", err)
	} else {
		// Start background sync service
		syncService := services.NewSyncService(tokenEncryptor)
		syncService.Start(5 * time.Minute) // Sync every 5 minutes
		defer syncService.Stop()
	}

	// Create a new ServeMux for our application routes
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/api/signup", handlers.Signup)
	mux.HandleFunc("/api/login", handlers.Signin) // Frontend calls /login

	// Slack OAuth routes (public callback, protected auth start)
	mux.HandleFunc("/api/integrations/slack/callback", handlers.SlackCallback)

	// Protected routes
	mux.Handle("/api/protected", middleware.AuthMiddleware(http.HandlerFunc(protectedHandler)))

	// Integration routes (protected)
	mux.Handle("/api/integrations/slack/auth", middleware.AuthMiddleware(http.HandlerFunc(handlers.SlackAuth)))
	mux.Handle("/api/integrations", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.GetIntegrations(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/integrations/", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			handlers.DeleteIntegration(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/integrations/slack/channels", middleware.AuthMiddleware(http.HandlerFunc(handlers.GetSlackChannels)))

	// Signal routes (protected)
	mux.Handle("/api/workspaces/", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/signals") && r.Method == http.MethodGet {
			handlers.GetSignals(w, r)
		} else {
			http.Error(w, "Not found", http.StatusNotFound)
		}
	})))
	mux.Handle("/api/signals/", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		method := r.Method

		switch {
		case method == http.MethodGet && !strings.HasSuffix(path, "/read") && !strings.HasSuffix(path, "/archive"):
			handlers.GetSignal(w, r)
		case method == http.MethodPost && strings.HasSuffix(path, "/read"):
			handlers.MarkSignalAsRead(w, r)
		case method == http.MethodPost && strings.HasSuffix(path, "/archive"):
			handlers.ArchiveSignal(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	// Apply CORS middleware to the entire mux
	handler := middleware.CorsMiddleware(mux)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	email, ok := r.Context().Value(middleware.UserEmailKey).(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("Hello, " + email))
}
