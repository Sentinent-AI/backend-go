package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"sentinent-backend/services"
	"sentinent-backend/utils"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const passwordResetTTL = time.Hour

var sendPasswordResetEmailFunc = services.SendPasswordResetEmail

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Password string `json:"password"`
}

type profileUpdateRequest struct {
	FullName     string `json:"full_name"`
	JobTitle     string `json:"job_title"`
	Organization string `json:"organization"`
	Timezone     string `json:"timezone"`
	Bio          string `json:"bio"`
	RoleLabel    string `json:"role_label"`
}

func Signup(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !utils.IsEmailValid(user.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	user.Email = strings.TrimSpace(user.Email)
	user.FullName = strings.TrimSpace(user.FullName)
	user.JobTitle = strings.TrimSpace(user.JobTitle)
	user.Organization = strings.TrimSpace(user.Organization)
	user.Timezone = strings.TrimSpace(user.Timezone)
	user.Bio = strings.TrimSpace(user.Bio)
	user.RoleLabel = strings.TrimSpace(user.RoleLabel)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = database.DB.Exec(
		`INSERT INTO users (email, password, full_name, job_title, organization, timezone, bio, role_label)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		user.Email,
		string(hashedPassword),
		user.FullName,
		user.JobTitle,
		user.Organization,
		user.Timezone,
		user.Bio,
		user.RoleLabel,
	)
	if err != nil {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func Signin(w http.ResponseWriter, r *http.Request) {
	var creds models.User
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !utils.IsEmailValid(creds.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	var storedUser models.User
	err = database.DB.QueryRow("SELECT id, email, password FROM users WHERE email = ?", creds.Email).Scan(&storedUser.ID, &storedUser.Email, &storedUser.Password)
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &models.Claims{
		UserID: storedUser.ID,
		Email:  creds.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if len(utils.JwtKey) == 0 {
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}
	tokenString, err := token.SignedString(utils.JwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isProductionEnv(),
	})

	// Also return JSON for non-browser clients
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
		Secure:   isProductionEnv(),
	})

	w.WriteHeader(http.StatusNoContent)
}

func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	emailDeliveryConfigured := services.PasswordResetEmailDeliveryConfigured()
	if isProductionEnv() && !emailDeliveryConfigured {
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}

	var req forgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	if !utils.IsEmailValid(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	var userID int
	err := database.DB.QueryRow("SELECT id FROM users WHERE email = ?", req.Email).Scan(&userID)
	if err == sql.ErrNoRows {
		writeForgotPasswordResponse(w, "")
		return
	}
	if err != nil {
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}

	resetToken, err := generatePasswordResetToken()
	if err != nil {
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(passwordResetTTL)
	tokenHash := hashPasswordResetToken(resetToken)

	tx, err := database.DB.Begin()
	if err != nil {
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		"DELETE FROM password_reset_tokens WHERE user_id = ? OR expires_at <= ? OR used_at IS NOT NULL",
		userID, time.Now(),
	); err != nil {
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}

	if _, err := tx.Exec(
		`INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
		 VALUES (?, ?, ?)`,
		userID, tokenHash, expiresAt,
	); err != nil {
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}

	resetURL := buildPasswordResetURL(resetToken)
	if !emailDeliveryConfigured {
		writeForgotPasswordResponse(w, resetURL)
		return
	}

	if err := sendPasswordResetEmailFunc(req.Email, resetURL); err != nil {
		log.Printf("failed to send password reset email for %s: %v", req.Email, err)
		if _, cleanupErr := database.DB.Exec("DELETE FROM password_reset_tokens WHERE token_hash = ?", tokenHash); cleanupErr != nil {
			log.Printf("failed to clean up password reset token after email delivery error: %v", cleanupErr)
		}
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}

	writeForgotPasswordResponse(w, "")
}

func ValidatePasswordResetToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	record, statusCode, err := lookupPasswordResetRecord(extractPasswordResetToken(r.URL.Path))
	if err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": true,
		"email": record.Email,
	})
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	record, statusCode, err := lookupPasswordResetRecord(extractPasswordResetToken(r.URL.Path))
	if err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.Password = strings.TrimSpace(req.Password)
	if len(req.Password) < 8 {
		http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	tx, err := database.DB.Begin()
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), record.UserID); err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	if _, err := tx.Exec(
		"UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
		time.Now(), record.UserID,
	); err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getProfile(w, r)
	case http.MethodPatch:
		updateProfile(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user models.User
	err := database.DB.QueryRow(
		`SELECT id, email, full_name, job_title, organization, timezone, bio, role_label
		 FROM users WHERE id = ?`,
		userID,
	).Scan(
		&user.ID,
		&user.Email,
		&user.FullName,
		&user.JobTitle,
		&user.Organization,
		&user.Timezone,
		&user.Bio,
		&user.RoleLabel,
	)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to load profile", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

func updateProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req profileUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.FullName = strings.TrimSpace(req.FullName)
	req.JobTitle = strings.TrimSpace(req.JobTitle)
	req.Organization = strings.TrimSpace(req.Organization)
	req.Timezone = strings.TrimSpace(req.Timezone)
	req.Bio = strings.TrimSpace(req.Bio)
	req.RoleLabel = strings.TrimSpace(req.RoleLabel)

	if req.FullName == "" {
		http.Error(w, "Full name is required", http.StatusBadRequest)
		return
	}

	_, err := database.DB.Exec(
		`UPDATE users
		 SET full_name = ?, job_title = ?, organization = ?, timezone = ?, bio = ?, role_label = ?
		 WHERE id = ?`,
		req.FullName,
		req.JobTitle,
		req.Organization,
		req.Timezone,
		req.Bio,
		req.RoleLabel,
		userID,
	)
	if err != nil {
		http.Error(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	getProfile(w, r)
}

func isProductionEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV"))) {
	case "production", "prod":
		return true
	default:
		return false
	}
}

type passwordResetRecord struct {
	ID     int
	UserID int
	Email  string
}

func lookupPasswordResetRecord(token string) (*passwordResetRecord, int, error) {
	if token == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("Invalid reset token")
	}

	var record passwordResetRecord
	var expiresAt time.Time
	var usedAt sql.NullTime
	err := database.DB.QueryRow(
		`SELECT prt.id, prt.user_id, u.email, prt.expires_at, prt.used_at
		 FROM password_reset_tokens prt
		 JOIN users u ON u.id = prt.user_id
		 WHERE prt.token_hash = ?`,
		hashPasswordResetToken(token),
	).Scan(&record.ID, &record.UserID, &record.Email, &expiresAt, &usedAt)
	if err == sql.ErrNoRows {
		return nil, http.StatusNotFound, fmt.Errorf("Invalid reset token")
	}
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("Failed to validate reset token")
	}
	if usedAt.Valid {
		return nil, http.StatusGone, fmt.Errorf("Reset token has already been used")
	}
	if time.Now().After(expiresAt) {
		return nil, http.StatusGone, fmt.Errorf("Reset token has expired")
	}

	return &record, http.StatusOK, nil
}

func writeForgotPasswordResponse(w http.ResponseWriter, resetURL string) {
	response := map[string]string{
		"message": "If an account exists for that email, password reset instructions have been sent.",
	}
	if resetURL != "" {
		response["reset_url"] = resetURL
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func buildPasswordResetURL(token string) string {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("FRONTEND_BASE_URL")), "/")
	if baseURL == "" {
		baseURL = "http://localhost:4200"
	}
	return fmt.Sprintf("%s/reset-password/%s", baseURL, token)
}

func extractPasswordResetToken(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "reset-password" {
		return parts[2]
	}
	return ""
}

func generatePasswordResetToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashPasswordResetToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
