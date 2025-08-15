package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/tech-arch1tect/brx/config"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrPasswordHashingFailed     = errors.New("failed to hash password")
	ErrInvalidCredentials        = errors.New("invalid credentials")
	ErrPasswordResetDisabled     = errors.New("password reset is disabled")
	ErrPasswordResetTokenInvalid = errors.New("invalid or expired password reset token")
	ErrPasswordResetTokenExpired = errors.New("password reset token has expired")
	ErrPasswordResetTokenUsed    = errors.New("password reset token has already been used")
)

type MailService interface {
	SendTemplate(templateName string, to []string, subject string, data map[string]any) error
}

type Service struct {
	config      *config.Config
	db          *gorm.DB
	mailService MailService
}

func NewService(cfg *config.Config, db *gorm.DB) *Service {
	if cfg.Auth.BcryptCost < bcrypt.MinCost || cfg.Auth.BcryptCost > bcrypt.MaxCost {
		cfg.Auth.BcryptCost = bcrypt.DefaultCost
	}
	return &Service{
		config: cfg,
		db:     db,
	}
}

func (s *Service) SetMailService(mailService MailService) {
	s.mailService = mailService
}

func NewServiceWithDefaults() *Service {
	return NewService(&config.Config{
		App: config.AppConfig{
			Name: "brx Application",
			URL:  "http://localhost:8080",
		},
		Auth: config.AuthConfig{
			MinLength:                8,
			RequireUpper:             true,
			RequireLower:             true,
			RequireNumber:            true,
			RequireSpecial:           false,
			BcryptCost:               bcrypt.DefaultCost,
			PasswordResetEnabled:     true,
			PasswordResetTokenLength: 32,
			PasswordResetExpiry:      time.Hour,
		},
	}, nil)
}

func (s *Service) ValidatePassword(password string) error {
	if len(password) < s.config.Auth.MinLength {
		return fmt.Errorf("password must be at least %d characters", s.config.Auth.MinLength)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	var missing []string

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if s.config.Auth.RequireUpper && !hasUpper {
		missing = append(missing, "one uppercase letter")
	}
	if s.config.Auth.RequireLower && !hasLower {
		missing = append(missing, "one lowercase letter")
	}
	if s.config.Auth.RequireNumber && !hasNumber {
		missing = append(missing, "one number")
	}
	if s.config.Auth.RequireSpecial && !hasSpecial {
		missing = append(missing, "one special character")
	}

	if len(missing) > 0 {
		return fmt.Errorf("password must contain at least %s", strings.Join(missing, ", "))
	}

	return nil
}

func (s *Service) HashPassword(password string) (string, error) {
	if err := s.ValidatePassword(password); err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.config.Auth.BcryptCost)
	if err != nil {
		return "", ErrPasswordHashingFailed
	}

	return string(hash), nil
}

func (s *Service) VerifyPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

func (s *Service) MustHashPassword(password string) string {
	hash, err := s.HashPassword(password)
	if err != nil {
		panic(err)
	}
	return hash
}

func (s *Service) generateSecureToken() (string, error) {
	bytes := make([]byte, s.config.Auth.PasswordResetTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func (s *Service) CreatePasswordResetToken(email string) (*PasswordResetToken, error) {
	if !s.config.Auth.PasswordResetEnabled {
		return nil, ErrPasswordResetDisabled
	}

	if s.db == nil {
		return nil, fmt.Errorf("database is required for password reset functionality")
	}

	token, err := s.generateSecureToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	resetToken := &PasswordResetToken{
		Email:     email,
		Token:     token,
		ExpiresAt: now.Add(s.config.Auth.PasswordResetExpiry),
		Used:      false,
	}

	if err := s.db.Create(resetToken).Error; err != nil {
		return nil, fmt.Errorf("failed to create password reset token: %w", err)
	}

	return resetToken, nil
}

func (s *Service) ValidatePasswordResetToken(token string) (*PasswordResetToken, error) {
	if !s.config.Auth.PasswordResetEnabled {
		return nil, ErrPasswordResetDisabled
	}

	if s.db == nil {
		return nil, fmt.Errorf("database is required for password reset functionality")
	}

	var resetToken PasswordResetToken
	if err := s.db.Where("token = ?", token).First(&resetToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPasswordResetTokenInvalid
		}
		return nil, fmt.Errorf("failed to validate password reset token: %w", err)
	}

	if resetToken.Used {
		return nil, ErrPasswordResetTokenUsed
	}

	if time.Now().After(resetToken.ExpiresAt) {
		return nil, ErrPasswordResetTokenExpired
	}

	return &resetToken, nil
}

func (s *Service) UsePasswordResetToken(token string) (*PasswordResetToken, error) {
	resetToken, err := s.ValidatePasswordResetToken(token)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	resetToken.Used = true
	resetToken.UsedAt = &now

	if err := s.db.Save(resetToken).Error; err != nil {
		return nil, fmt.Errorf("failed to mark password reset token as used: %w", err)
	}

	return resetToken, nil
}

func (s *Service) CleanupExpiredTokens() error {
	if !s.config.Auth.PasswordResetEnabled {
		return ErrPasswordResetDisabled
	}

	if s.db == nil {
		return fmt.Errorf("database is required for password reset functionality")
	}

	result := s.db.Where("expires_at < ?", time.Now()).Delete(&PasswordResetToken{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup expired password reset tokens: %w", result.Error)
	}

	return nil
}

func (s *Service) ResetPassword(token, newPassword string) error {
	resetToken, err := s.UsePasswordResetToken(token)
	if err != nil {
		return err
	}

	hashedPassword, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}

	if err := s.db.Table("users").Where("email = ?", resetToken.Email).Update("password", hashedPassword).Error; err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

func (s *Service) SendPasswordResetEmail(email, resetURL string, expiryDuration time.Duration) error {
	if s.mailService == nil {
		return fmt.Errorf("mail service is not configured")
	}

	data := map[string]any{
		"Email":          email,
		"ResetURL":       resetURL,
		"ExpiryDuration": expiryDuration.String(),
		"AppName":        s.config.App.Name,
	}

	subject := "Password Reset Request"
	return s.mailService.SendTemplate("password_reset", []string{email}, subject, data)
}

func (s *Service) SendPasswordResetSuccessEmail(email string) error {
	if s.mailService == nil {
		return fmt.Errorf("mail service is not configured")
	}

	data := map[string]any{
		"Email":   email,
		"AppName": s.config.App.Name,
	}

	subject := "Password Reset Successful"
	return s.mailService.SendTemplate("password_reset_success", []string{email}, subject, data)
}

func (s *Service) RequestPasswordReset(email string) error {
	if !s.config.Auth.PasswordResetEnabled {
		return ErrPasswordResetDisabled
	}

	resetToken, err := s.CreatePasswordResetToken(email)
	if err != nil {
		return err
	}

	resetURL := fmt.Sprintf("%s/auth/password-reset/confirm?token=%s", s.config.App.URL, resetToken.Token)

	if err := s.SendPasswordResetEmail(email, resetURL, s.config.Auth.PasswordResetExpiry); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	return nil
}

func (s *Service) CompletePasswordReset(token, newPassword string) error {
	if err := s.ResetPassword(token, newPassword); err != nil {
		return err
	}

	resetToken, err := s.ValidatePasswordResetToken(token)
	if err == nil {
		if err := s.SendPasswordResetSuccessEmail(resetToken.Email); err != nil {
			return fmt.Errorf("password was reset but failed to send confirmation email: %w", err)
		}
	}

	return nil
}
