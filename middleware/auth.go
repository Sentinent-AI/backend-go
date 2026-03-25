package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"sentinent-backend/utils"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const UserEmailKey contextKey = "userEmail"
const UserIDKey contextKey = "userID"

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
			return utils.JwtKey, nil
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

		userID := claims.UserID
		if userID == 0 && claims.Email != "" {
			err = database.DB.QueryRow("SELECT id FROM users WHERE email = ?", claims.Email).Scan(&userID)
			if err == sql.ErrNoRows {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}

		ctx := context.WithValue(r.Context(), UserEmailKey, claims.Email)
		if userID != 0 {
			ctx = context.WithValue(ctx, UserIDKey, userID)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUserID(ctx context.Context) (int, bool) {
	userID, ok := ctx.Value(UserIDKey).(int)
	return userID, ok
}

func GetUserEmail(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(UserEmailKey).(string)
	return email, ok
}
