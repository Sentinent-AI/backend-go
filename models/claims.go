package models

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	Email  string `json:"email"`
	UserID int    `json:"userId"`
	jwt.RegisteredClaims
}
