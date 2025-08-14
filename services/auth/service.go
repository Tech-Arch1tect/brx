package auth

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/tech-arch1tect/brx/config"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordHashingFailed = errors.New("failed to hash password")
	ErrInvalidCredentials    = errors.New("invalid credentials")
)

type Service struct {
	config *config.AuthConfig
}

func NewService(authConfig *config.AuthConfig) *Service {
	if authConfig.BcryptCost < bcrypt.MinCost || authConfig.BcryptCost > bcrypt.MaxCost {
		authConfig.BcryptCost = bcrypt.DefaultCost
	}
	return &Service{
		config: authConfig,
	}
}

func NewServiceWithDefaults() *Service {
	return NewService(&config.AuthConfig{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: false,
		BcryptCost:     bcrypt.DefaultCost,
	})
}

func (s *Service) ValidatePassword(password string) error {
	if len(password) < s.config.MinLength {
		return fmt.Errorf("password must be at least %d characters", s.config.MinLength)
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

	if s.config.RequireUpper && !hasUpper {
		missing = append(missing, "one uppercase letter")
	}
	if s.config.RequireLower && !hasLower {
		missing = append(missing, "one lowercase letter")
	}
	if s.config.RequireNumber && !hasNumber {
		missing = append(missing, "one number")
	}
	if s.config.RequireSpecial && !hasSpecial {
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

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.config.BcryptCost)
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
