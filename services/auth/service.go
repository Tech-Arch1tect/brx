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
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
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
	logger      *logging.Service
}

func NewService(cfg *config.Config, db *gorm.DB, logger *logging.Service) *Service {
	if cfg.Auth.BcryptCost < bcrypt.MinCost || cfg.Auth.BcryptCost > bcrypt.MaxCost {
		cfg.Auth.BcryptCost = bcrypt.DefaultCost
	}
	return &Service{
		config: cfg,
		db:     db,
		logger: logger,
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
	}, nil, nil)
}

func (s *Service) ValidatePassword(password string) error {
	if s.logger != nil {
		s.logger.Debug("validating password strength")
	}

	if len(password) < s.config.Auth.MinLength {
		if s.logger != nil {
			s.logger.Warn("password validation failed: insufficient length",
				zap.Int("length", len(password)),
				zap.Int("min_required", s.config.Auth.MinLength))
		}
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
		if s.logger != nil {
			s.logger.Warn("password validation failed: missing requirements",
				zap.Strings("missing_requirements", missing))
		}
		return fmt.Errorf("password must contain at least %s", strings.Join(missing, ", "))
	}

	if s.logger != nil {
		s.logger.Debug("password validation passed")
	}
	return nil
}

func (s *Service) HashPassword(password string) (string, error) {
	if err := s.ValidatePassword(password); err != nil {
		return "", err
	}

	if s.logger != nil {
		s.logger.Debug("generating password hash", zap.Int("bcrypt_cost", s.config.Auth.BcryptCost))
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.config.Auth.BcryptCost)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("password hashing failed", zap.Error(err))
		}
		return "", ErrPasswordHashingFailed
	}

	if s.logger != nil {
		s.logger.Debug("password hash generated successfully")
	}
	return string(hash), nil
}

func (s *Service) VerifyPassword(hashedPassword, password string) error {
	if s.logger != nil {
		s.logger.Debug("verifying password")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("password verification failed", zap.Error(err))
		}
		return ErrInvalidCredentials
	}

	if s.logger != nil {
		s.logger.Debug("password verification successful")
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
	if s.logger != nil {
		s.logger.Info("creating password reset token", zap.String("email", email))
	}

	if !s.config.Auth.PasswordResetEnabled {
		if s.logger != nil {
			s.logger.Warn("password reset attempted but feature is disabled", zap.String("email", email))
		}
		return nil, ErrPasswordResetDisabled
	}

	if s.db == nil {
		if s.logger != nil {
			s.logger.Error("password reset failed: database not configured")
		}
		return nil, fmt.Errorf("database is required for password reset functionality")
	}

	token, err := s.generateSecureToken()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate secure token for password reset", zap.Error(err), zap.String("email", email))
		}
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
		if s.logger != nil {
			s.logger.Error("failed to create password reset token in database", zap.Error(err), zap.String("email", email))
		}
		return nil, fmt.Errorf("failed to create password reset token: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("password reset token created successfully",
			zap.String("email", email),
			zap.Time("expires_at", resetToken.ExpiresAt))
	}
	return resetToken, nil
}

func (s *Service) ValidatePasswordResetToken(token string) (*PasswordResetToken, error) {
	if s.logger != nil {
		s.logger.Debug("validating password reset token")
	}

	if !s.config.Auth.PasswordResetEnabled {
		if s.logger != nil {
			s.logger.Warn("password reset token validation attempted but feature is disabled")
		}
		return nil, ErrPasswordResetDisabled
	}

	if s.db == nil {
		if s.logger != nil {
			s.logger.Error("password reset token validation failed: database not configured")
		}
		return nil, fmt.Errorf("database is required for password reset functionality")
	}

	var resetToken PasswordResetToken
	if err := s.db.Where("token = ?", token).First(&resetToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if s.logger != nil {
				s.logger.Warn("invalid password reset token attempted")
			}
			return nil, ErrPasswordResetTokenInvalid
		}
		if s.logger != nil {
			s.logger.Error("database error during password reset token validation", zap.Error(err))
		}
		return nil, fmt.Errorf("failed to validate password reset token: %w", err)
	}

	if resetToken.Used {
		if s.logger != nil {
			s.logger.Warn("already used password reset token attempted", zap.String("email", resetToken.Email))
		}
		return nil, ErrPasswordResetTokenUsed
	}

	if time.Now().After(resetToken.ExpiresAt) {
		if s.logger != nil {
			s.logger.Warn("expired password reset token attempted",
				zap.String("email", resetToken.Email),
				zap.Time("expired_at", resetToken.ExpiresAt))
		}
		return nil, ErrPasswordResetTokenExpired
	}

	if s.logger != nil {
		s.logger.Debug("password reset token validation successful", zap.String("email", resetToken.Email))
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
	if s.logger != nil {
		s.logger.Debug("starting cleanup of expired password reset tokens")
	}

	if !s.config.Auth.PasswordResetEnabled {
		if s.logger != nil {
			s.logger.Debug("skipping password reset token cleanup: feature disabled")
		}
		return ErrPasswordResetDisabled
	}

	if s.db == nil {
		if s.logger != nil {
			s.logger.Error("password reset token cleanup failed: database not configured")
		}
		return fmt.Errorf("database is required for password reset functionality")
	}

	result := s.db.Where("expires_at < ?", time.Now()).Delete(&PasswordResetToken{})
	if result.Error != nil {
		if s.logger != nil {
			s.logger.Error("failed to cleanup expired password reset tokens", zap.Error(result.Error))
		}
		return fmt.Errorf("failed to cleanup expired password reset tokens: %w", result.Error)
	}

	if s.logger != nil {
		s.logger.Info("expired password reset tokens cleaned up", zap.Int64("tokens_removed", result.RowsAffected))
	}
	return nil
}

func (s *Service) ResetPassword(token, newPassword string) error {
	if s.logger != nil {
		s.logger.Info("password reset requested")
	}

	resetToken, err := s.UsePasswordResetToken(token)
	if err != nil {
		return err
	}

	hashedPassword, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}

	if err := s.db.Table("users").Where("email = ?", resetToken.Email).Update("password", hashedPassword).Error; err != nil {
		if s.logger != nil {
			s.logger.Error("failed to update password in database", zap.Error(err), zap.String("email", resetToken.Email))
		}
		return fmt.Errorf("failed to update password: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("password reset completed successfully", zap.String("email", resetToken.Email))
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
	if s.logger != nil {
		s.logger.Info("password reset requested", zap.String("email", email))
	}

	if !s.config.Auth.PasswordResetEnabled {
		if s.logger != nil {
			s.logger.Warn("password reset requested but feature is disabled", zap.String("email", email))
		}
		return ErrPasswordResetDisabled
	}

	resetToken, err := s.CreatePasswordResetToken(email)
	if err != nil {
		return err
	}

	resetURL := fmt.Sprintf("%s/auth/password-reset/confirm?token=%s", s.config.App.URL, resetToken.Token)

	if err := s.SendPasswordResetEmail(email, resetURL, s.config.Auth.PasswordResetExpiry); err != nil {
		if s.logger != nil {
			s.logger.Error("failed to send password reset email", zap.Error(err), zap.String("email", email))
		}
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("password reset email sent successfully", zap.String("email", email))
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
	s.logger.Info("sending email verification email", zap.String("email", email))

	if s.mailService == nil {
		s.logger.Warn("mail service is not configured")
		return fmt.Errorf("mail service is not configured")
	}

	data := map[string]any{
		"Email":           email,
		"VerificationURL": verificationURL,
		"ExpiryDuration":  expiryDuration.String(),
		"AppName":         s.config.App.Name,
	}

	s.logger.Info("sending email verification template", zap.String("email", email), zap.String("template", "email_verification"))
	subject := "Please verify your email address"
	err := s.mailService.SendTemplate("email_verification", []string{email}, subject, data)
	if err != nil {
		s.logger.Error("failed to send email verification template", zap.Error(err), zap.String("email", email))
	} else {
		s.logger.Info("email verification template sent successfully", zap.String("email", email))
	}
	return err
}

func (s *Service) RequestEmailVerification(email string) error {
	s.logger.Info("requesting email verification", zap.String("email", email))

	if !s.config.Auth.EmailVerificationEnabled {
		s.logger.Warn("email verification is disabled")
		return ErrEmailVerificationDisabled
	}

	s.logger.Info("creating email verification token", zap.String("email", email))
	verificationToken, err := s.CreateEmailVerificationToken(email)
	if err != nil {
		s.logger.Error("failed to create email verification token", zap.Error(err), zap.String("email", email))
		return err
	}

	verificationURL := fmt.Sprintf("%s/auth/verify-email?token=%s", s.config.App.URL, verificationToken.Token)
	s.logger.Info("generated verification URL", zap.String("email", email))

	s.logger.Info("sending email verification email", zap.String("email", email))
	if err := s.SendEmailVerificationEmail(email, verificationURL, s.config.Auth.EmailVerificationExpiry); err != nil {
		s.logger.Error("failed to send email verification email", zap.Error(err), zap.String("email", email))
		return fmt.Errorf("failed to send email verification email: %w", err)
	}

	s.logger.Info("email verification email sent successfully", zap.String("email", email))
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
	if s.logger != nil {
		s.logger.Info("creating remember me token", zap.Uint("user_id", userID))
	}

	if !s.config.Auth.RememberMeEnabled {
		if s.logger != nil {
			s.logger.Warn("remember me token creation attempted but feature is disabled", zap.Uint("user_id", userID))
		}
		return nil, ErrRememberMeDisabled
	}

	if s.db == nil {
		if s.logger != nil {
			s.logger.Error("remember me token creation failed: database not configured")
		}
		return nil, fmt.Errorf("database is required for remember me functionality")
	}

	// Clean up existing tokens for this user
	result := s.db.Where("user_id = ?", userID).Delete(&RememberMeToken{})
	if s.logger != nil && result.RowsAffected > 0 {
		s.logger.Debug("cleaned up existing remember me tokens",
			zap.Uint("user_id", userID),
			zap.Int64("tokens_removed", result.RowsAffected))
	}

	token, err := s.generateRememberMeToken()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate remember me token", zap.Error(err), zap.Uint("user_id", userID))
		}
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
		if s.logger != nil {
			s.logger.Error("failed to create remember me token in database", zap.Error(err), zap.Uint("user_id", userID))
		}
		return nil, fmt.Errorf("failed to create remember me token: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("remember me token created successfully",
			zap.Uint("user_id", userID),
			zap.Time("expires_at", rememberToken.ExpiresAt))
	}
	return rememberToken, nil
}

func (s *Service) ValidateRememberMeToken(token string) (*RememberMeToken, error) {
	if s.logger != nil {
		s.logger.Debug("validating remember me token")
	}

	if !s.config.Auth.RememberMeEnabled {
		if s.logger != nil {
			s.logger.Warn("remember me token validation attempted but feature is disabled")
		}
		return nil, ErrRememberMeDisabled
	}

	if s.db == nil {
		if s.logger != nil {
			s.logger.Error("remember me token validation failed: database not configured")
		}
		return nil, fmt.Errorf("database is required for remember me functionality")
	}

	var rememberToken RememberMeToken
	if err := s.db.Where("token = ?", token).First(&rememberToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if s.logger != nil {
				s.logger.Warn("invalid remember me token attempted")
			}
			return nil, ErrRememberMeTokenInvalid
		}
		if s.logger != nil {
			s.logger.Error("database error during remember me token validation", zap.Error(err))
		}
		return nil, fmt.Errorf("failed to validate remember me token: %w", err)
	}

	if rememberToken.Used {
		if s.logger != nil {
			s.logger.Warn("already used remember me token attempted", zap.Uint("user_id", rememberToken.UserID))
		}
		return nil, ErrRememberMeTokenUsed
	}

	if time.Now().After(rememberToken.ExpiresAt) {
		if s.logger != nil {
			s.logger.Warn("expired remember me token attempted",
				zap.Uint("user_id", rememberToken.UserID),
				zap.Time("expired_at", rememberToken.ExpiresAt))
		}
		return nil, ErrRememberMeTokenExpired
	}

	if s.logger != nil {
		s.logger.Debug("remember me token validation successful", zap.Uint("user_id", rememberToken.UserID))
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
	if s.logger != nil {
		s.logger.Debug("starting cleanup of expired remember me tokens")
	}

	if !s.config.Auth.RememberMeEnabled {
		if s.logger != nil {
			s.logger.Debug("skipping remember me token cleanup: feature disabled")
		}
		return ErrRememberMeDisabled
	}

	if s.db == nil {
		if s.logger != nil {
			s.logger.Error("remember me token cleanup failed: database not configured")
		}
		return fmt.Errorf("database is required for remember me functionality")
	}

	result := s.db.Where("expires_at < ?", time.Now()).Delete(&RememberMeToken{})
	if result.Error != nil {
		if s.logger != nil {
			s.logger.Error("failed to cleanup expired remember me tokens", zap.Error(result.Error))
		}
		return fmt.Errorf("failed to cleanup expired remember me tokens: %w", result.Error)
	}

	if s.logger != nil {
		s.logger.Info("expired remember me tokens cleaned up", zap.Int64("tokens_removed", result.RowsAffected))
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
