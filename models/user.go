package models

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// JwtKey is the global JWT signing key, set at startup from environment
var JwtKey []byte
