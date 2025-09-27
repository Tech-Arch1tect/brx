package testutils

import (
	"time"

	"github.com/tech-arch1tect/brx/config"
	"golang.org/x/crypto/bcrypt"
)

func GetTestConfig() *config.Config {
	return &config.Config{
		App: config.AppConfig{
			Name: "Test App",
			URL:  "http://localhost:8080",
		},
		Auth: config.AuthConfig{
			MinLength:                    8,
			RequireUpper:                 true,
			RequireLower:                 true,
			RequireNumber:                true,
			RequireSpecial:               false,
			BcryptCost:                   bcrypt.MinCost,
			PasswordResetEnabled:         true,
			PasswordResetTokenLength:     32,
			PasswordResetExpiry:          time.Hour,
			EmailVerificationEnabled:     true,
			EmailVerificationTokenLength: 32,
			EmailVerificationExpiry:      24 * time.Hour,
			RememberMeEnabled:            true,
			RememberMeExpiry:             30 * 24 * time.Hour,
			RememberMeCookieSecure:       false,
			RememberMeCookieSameSite:     "lax",
		},
		JWT: config.JWTConfig{
			SecretKey:    "test-secret-key-32-chars-long!!",
			Algorithm:    "HS256",
			AccessExpiry: 15 * time.Minute,
			Issuer:       "test-issuer",
		},
		TOTP: config.TOTPConfig{
			Enabled: true,
			Issuer:  "Test App",
		},
		Database: config.DatabaseConfig{
			Driver: "sqlite",
			DSN:    ":memory:",
		},
	}
}

var TestPasswords = struct {
	Valid       string
	TooShort    string
	NoUpper     string
	NoLower     string
	NoNumber    string
	WithSpecial string
}{
	Valid:       "Password123",
	TooShort:    "Pass1",
	NoUpper:     "password123",
	NoLower:     "PASSWORD123",
	NoNumber:    "Password",
	WithSpecial: "Password123!",
}

var TestUsers = struct {
	ValidUser struct {
		Username string
		Email    string
		Password string
	}
	InvalidEmail struct {
		Username string
		Email    string
		Password string
	}
}{
	ValidUser: struct {
		Username string
		Email    string
		Password string
	}{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "Password123",
	},
	InvalidEmail: struct {
		Username string
		Email    string
		Password string
	}{
		Username: "testuser2",
		Email:    "invalid-email",
		Password: "Password123",
	},
}

var TestTokens = struct {
	ValidClaims   map[string]interface{}
	ExpiredClaims map[string]interface{}
}{
	ValidClaims: map[string]interface{}{
		"user_id": uint(1),
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iss":     "test-issuer",
		"jti":     "test-jti",
	},
	ExpiredClaims: map[string]interface{}{
		"user_id": uint(1),
		"iat":     time.Now().Add(-2 * time.Hour).Unix(),
		"exp":     time.Now().Add(-time.Hour).Unix(),
		"iss":     "test-issuer",
		"jti":     "expired-jti",
	},
}
