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

	// Public routes
	http.HandleFunc("/signup", handlers.Signup)
	http.HandleFunc("/signin", handlers.Signin)

	// Protected routes
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, ok := r.Context().Value(middleware.UserEmailKey).(string)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("Hello, " + email))
	})

	http.Handle("/protected", middleware.AuthMiddleware(protectedHandler))

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
