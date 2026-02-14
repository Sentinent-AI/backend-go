package middleware

import (
	"context"
	"net/http"
	"sentinent-backend/handlers"
	"sentinent-backend/models"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const UserEmailKey contextKey = "userEmail"

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := ""

		// Check cookie first
		c, err := r.Cookie("token")
		if err == nil {
			tokenString = c.Value
		}

		// Check Authorization header (Bearer <token>)
		if tokenString == "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				splitToken := strings.Split(authHeader, "Bearer ")
				if len(splitToken) == 2 {
					tokenString = splitToken[1]
				}
			}
		}

		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims := &models.Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return handlers.JwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserEmailKey, claims.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
