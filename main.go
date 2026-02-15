package main

import (
	"log"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/handlers"
	"sentinent-backend/middleware"
)

func main() {
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

	// Apply CORS middleware to the entire mux
	handler := middleware.CorsMiddleware(mux)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
