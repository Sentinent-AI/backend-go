package middleware

import (
	"context"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const UserEmailKey contextKey = "userEmail"
const UserIDKey contextKey = "userId"

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
			return models.JwtKey, nil
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

		// If UserID is not in claims, look it up from database
		userID := claims.UserID
		if userID == 0 {
			var id int
			err := database.DB.QueryRow("SELECT id FROM users WHERE email = ?", claims.Email).Scan(&id)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			userID = id
		}

		ctx := context.WithValue(r.Context(), UserEmailKey, claims.Email)
		ctx = context.WithValue(ctx, UserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserID extracts the user ID from the context
func GetUserID(ctx context.Context) (int, bool) {
	userID, ok := ctx.Value(UserIDKey).(int)
	return userID, ok
}

// GetUserEmail extracts the user email from the context
func GetUserEmail(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(UserEmailKey).(string)
	return email, ok
}
