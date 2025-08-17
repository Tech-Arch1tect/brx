package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode"

	"github.com/tech-arch1tect/brx/config"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrPasswordHashingFailed         = errors.New("failed to hash password")
	ErrInvalidCredentials            = errors.New("invalid credentials")
	ErrPasswordResetDisabled         = errors.New("password reset is disabled")
	ErrPasswordResetTokenInvalid     = errors.New("invalid or expired password reset token")
	ErrPasswordResetTokenExpired     = errors.New("password reset token has expired")
	ErrPasswordResetTokenUsed        = errors.New("password reset token has already been used")
	ErrEmailVerificationDisabled     = errors.New("email verification is disabled")
	ErrEmailVerificationTokenInvalid = errors.New("invalid or expired email verification token")
	ErrEmailVerificationTokenExpired = errors.New("email verification token has expired")
	ErrEmailVerificationTokenUsed    = errors.New("email verification token has already been used")
	ErrEmailAlreadyVerified          = errors.New("email is already verified")
	ErrRememberMeDisabled            = errors.New("remember me functionality is disabled")
	ErrRememberMeTokenInvalid        = errors.New("invalid or expired remember me token")
	ErrRememberMeTokenExpired        = errors.New("remember me token has expired")
	ErrRememberMeTokenUsed           = errors.New("remember me token has already been used")
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
			MinLength:                    8,
			RequireUpper:                 true,
			RequireLower:                 true,
			RequireNumber:                true,
			RequireSpecial:               false,
			BcryptCost:                   bcrypt.DefaultCost,
			PasswordResetEnabled:         true,
			PasswordResetTokenLength:     32,
			PasswordResetExpiry:          time.Hour,
			EmailVerificationEnabled:     false,
			EmailVerificationTokenLength: 32,
			EmailVerificationExpiry:      24 * time.Hour,
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

func (s *Service) generateEmailVerificationToken() (string, error) {
	bytes := make([]byte, s.config.Auth.EmailVerificationTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func (s *Service) generateRememberMeToken() (string, error) {
	bytes := make([]byte, s.config.Auth.RememberMeTokenLength)
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
	resetToken, err := s.ValidatePasswordResetToken(token)
	if err != nil {
		return err
	}

	if err := s.ResetPassword(token, newPassword); err != nil {
		return err
	}

	if err := s.SendPasswordResetSuccessEmail(resetToken.Email); err != nil {
		return fmt.Errorf("password was reset but failed to send confirmation email: %w", err)
	}

	return nil
}

func (s *Service) CreateEmailVerificationToken(email string) (*EmailVerificationToken, error) {
	if !s.config.Auth.EmailVerificationEnabled {
		return nil, ErrEmailVerificationDisabled
	}

	if s.db == nil {
		return nil, fmt.Errorf("database is required for email verification functionality")
	}

	token, err := s.generateEmailVerificationToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	verificationToken := &EmailVerificationToken{
		Email:     email,
		Token:     token,
		ExpiresAt: now.Add(s.config.Auth.EmailVerificationExpiry),
		Used:      false,
	}

	if err := s.db.Create(verificationToken).Error; err != nil {
		return nil, fmt.Errorf("failed to create email verification token: %w", err)
	}

	return verificationToken, nil
}

func (s *Service) ValidateEmailVerificationToken(token string) (*EmailVerificationToken, error) {
	if !s.config.Auth.EmailVerificationEnabled {
		return nil, ErrEmailVerificationDisabled
	}

	if s.db == nil {
		return nil, fmt.Errorf("database is required for email verification functionality")
	}

	var verificationToken EmailVerificationToken
	if err := s.db.Where("token = ?", token).First(&verificationToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEmailVerificationTokenInvalid
		}
		return nil, fmt.Errorf("failed to validate email verification token: %w", err)
	}

	if verificationToken.Used {
		return nil, ErrEmailVerificationTokenUsed
	}

	if time.Now().After(verificationToken.ExpiresAt) {
		return nil, ErrEmailVerificationTokenExpired
	}

	return &verificationToken, nil
}

func (s *Service) UseEmailVerificationToken(token string) (*EmailVerificationToken, error) {
	verificationToken, err := s.ValidateEmailVerificationToken(token)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	verificationToken.Used = true
	verificationToken.UsedAt = &now

	if err := s.db.Save(verificationToken).Error; err != nil {
		return nil, fmt.Errorf("failed to mark email verification token as used: %w", err)
	}

	return verificationToken, nil
}

func (s *Service) CleanupExpiredEmailVerificationTokens() error {
	if !s.config.Auth.EmailVerificationEnabled {
		return ErrEmailVerificationDisabled
	}

	if s.db == nil {
		return fmt.Errorf("database is required for email verification functionality")
	}

	result := s.db.Where("expires_at < ?", time.Now()).Delete(&EmailVerificationToken{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup expired email verification tokens: %w", result.Error)
	}

	return nil
}

func (s *Service) SendEmailVerificationEmail(email, verificationURL string, expiryDuration time.Duration) error {
	log.Printf("SendEmailVerificationEmail called for: %s", email)

	if s.mailService == nil {
		log.Printf("Mail service is not configured")
		return fmt.Errorf("mail service is not configured")
	}

	data := map[string]any{
		"Email":           email,
		"VerificationURL": verificationURL,
		"ExpiryDuration":  expiryDuration.String(),
		"AppName":         s.config.App.Name,
	}

	log.Printf("Mail service configured, sending template with data: %+v", data)
	subject := "Please verify your email address"
	err := s.mailService.SendTemplate("email_verification", []string{email}, subject, data)
	if err != nil {
		log.Printf("Mail service SendTemplate failed: %v", err)
	} else {
		log.Printf("Mail service SendTemplate succeeded for: %s", email)
	}
	return err
}

func (s *Service) RequestEmailVerification(email string) error {
	log.Printf("RequestEmailVerification called for email: %s", email)

	if !s.config.Auth.EmailVerificationEnabled {
		log.Printf("Email verification is disabled")
		return ErrEmailVerificationDisabled
	}

	log.Printf("Creating email verification token for: %s", email)
	verificationToken, err := s.CreateEmailVerificationToken(email)
	if err != nil {
		log.Printf("Failed to create email verification token: %v", err)
		return err
	}

	verificationURL := fmt.Sprintf("%s/auth/verify-email?token=%s", s.config.App.URL, verificationToken.Token)
	log.Printf("Generated verification URL: %s", verificationURL)

	log.Printf("Sending email verification email to: %s", email)
	if err := s.SendEmailVerificationEmail(email, verificationURL, s.config.Auth.EmailVerificationExpiry); err != nil {
		log.Printf("Failed to send email verification email: %v", err)
		return fmt.Errorf("failed to send email verification email: %w", err)
	}

	log.Printf("Email verification email sent successfully to: %s", email)
	return nil
}

func (s *Service) VerifyEmail(token string) error {
	verificationToken, err := s.UseEmailVerificationToken(token)
	if err != nil {
		return err
	}

	if err := s.db.Table("users").Where("email = ?", verificationToken.Email).Update("email_verified_at", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to mark email as verified: %w", err)
	}

	return nil
}

func (s *Service) IsEmailVerificationRequired() bool {
	return s.config.Auth.EmailVerificationEnabled
}

func (s *Service) IsEmailVerified(email string) bool {
	if !s.config.Auth.EmailVerificationEnabled {
		return true
	}

	if s.db == nil {
		return true
	}

	var count int64
	s.db.Table("users").Where("email = ? AND email_verified_at IS NOT NULL", email).Count(&count)
	return count > 0
}

func (s *Service) CreateRememberMeToken(userID uint) (*RememberMeToken, error) {
	if !s.config.Auth.RememberMeEnabled {
		return nil, ErrRememberMeDisabled
	}

	if s.db == nil {
		return nil, fmt.Errorf("database is required for remember me functionality")
	}

	s.db.Where("user_id = ?", userID).Delete(&RememberMeToken{})

	token, err := s.generateRememberMeToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	rememberToken := &RememberMeToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: now.Add(s.config.Auth.RememberMeExpiry),
		Used:      false,
	}

	if err := s.db.Create(rememberToken).Error; err != nil {
		return nil, fmt.Errorf("failed to create remember me token: %w", err)
	}

	return rememberToken, nil
}

func (s *Service) ValidateRememberMeToken(token string) (*RememberMeToken, error) {
	if !s.config.Auth.RememberMeEnabled {
		return nil, ErrRememberMeDisabled
	}

	if s.db == nil {
		return nil, fmt.Errorf("database is required for remember me functionality")
	}

	var rememberToken RememberMeToken
	if err := s.db.Where("token = ?", token).First(&rememberToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRememberMeTokenInvalid
		}
		return nil, fmt.Errorf("failed to validate remember me token: %w", err)
	}

	if rememberToken.Used {
		return nil, ErrRememberMeTokenUsed
	}

	if time.Now().After(rememberToken.ExpiresAt) {
		return nil, ErrRememberMeTokenExpired
	}

	return &rememberToken, nil
}

func (s *Service) UseRememberMeToken(token string) (*RememberMeToken, error) {
	rememberToken, err := s.ValidateRememberMeToken(token)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	rememberToken.Used = true
	rememberToken.UsedAt = &now

	if err := s.db.Save(rememberToken).Error; err != nil {
		return nil, fmt.Errorf("failed to mark remember me token as used: %w", err)
	}

	return rememberToken, nil
}

func (s *Service) CleanupExpiredRememberMeTokens() error {
	if !s.config.Auth.RememberMeEnabled {
		return ErrRememberMeDisabled
	}

	if s.db == nil {
		return fmt.Errorf("database is required for remember me functionality")
	}

	result := s.db.Where("expires_at < ?", time.Now()).Delete(&RememberMeToken{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup expired remember me tokens: %w", result.Error)
	}

	return nil
}

func (s *Service) IsRememberMeEnabled() bool {
	return s.config.Auth.RememberMeEnabled
}

func (s *Service) InvalidateRememberMeTokens(userID uint) error {
	if !s.config.Auth.RememberMeEnabled {
		return ErrRememberMeDisabled
	}

	if s.db == nil {
		return fmt.Errorf("database is required for remember me functionality")
	}

	result := s.db.Where("user_id = ?", userID).Delete(&RememberMeToken{})
	if result.Error != nil {
		return fmt.Errorf("failed to invalidate remember me tokens: %w", result.Error)
	}

	return nil
}

func (s *Service) GetRememberMeExpiry() time.Duration {
	return s.config.Auth.RememberMeExpiry
}

func (s *Service) GetRememberMeCookieSecure() bool {
	return s.config.Auth.RememberMeCookieSecure
}

func (s *Service) GetRememberMeCookieSameSite() string {
	return s.config.Auth.RememberMeCookieSameSite
}

func (s *Service) ShouldRotateRememberMeToken() bool {
	return s.config.Auth.RememberMeRotateOnUse
}

func (s *Service) RotateRememberMeToken(oldToken string) (*RememberMeToken, error) {
	if !s.config.Auth.RememberMeEnabled {
		return nil, ErrRememberMeDisabled
	}

	rememberToken, err := s.ValidateRememberMeToken(oldToken)
	if err != nil {
		return nil, err
	}

	newToken, err := s.CreateRememberMeToken(rememberToken.UserID)
	if err != nil {
		return nil, err
	}

	if err := s.db.Delete(rememberToken).Error; err != nil {
		return nil, fmt.Errorf("failed to delete old remember me token: %w", err)
	}

	return newToken, nil
}
