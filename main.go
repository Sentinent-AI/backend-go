package main

import (
	"log"
	"net/http"

	"github.com/Sentinent-AI/backend-go/db"
	"github.com/Sentinent-AI/backend-go/handlers"
	"github.com/Sentinent-AI/backend-go/middleware"
)

func main() {
	db.InitDB()

	http.HandleFunc("/api/signup", handlers.Register)
	http.HandleFunc("/api/login", handlers.Login)

	// Example protected route
	http.Handle("/api/profile", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Protected Profile Data"))
	})))

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
