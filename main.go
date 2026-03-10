package main

import (
	"log"
	"net/http"
	"os"
	"sentinent-backend/database"
	"sentinent-backend/handlers"
	"sentinent-backend/middleware"
	"strings"
)

func main() {
	jwtSecret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}
	handlers.JwtKey = []byte(jwtSecret)

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

	decisionHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, ok := r.Context().Value(middleware.UserEmailKey).(string)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handlers.UpdateDecision(w, r, email)
	})
	mux.Handle("/api/decisions/", middleware.AuthMiddleware(decisionHandler))

	// Apply CORS middleware to the entire mux
	handler := middleware.CorsMiddleware(mux)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
