package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
)

var (
	ErrInvalidToken     = errors.New("invalid JWT token")
	ErrExpiredToken     = errors.New("JWT token has expired")
	ErrMalformedToken   = errors.New("malformed JWT token")
	ErrTokenMissingKid  = errors.New("JWT token missing key ID")
	ErrInvalidSignature = errors.New("invalid JWT token signature")
)

type Claims struct {
	UserID    uint   `json:"user_id"`
	TokenType string `json:"token_type,omitempty"`
	jwt.RegisteredClaims
}

type Service struct {
	config *config.Config
	logger *logging.Service
}

func NewService(cfg *config.Config, logger *logging.Service) *Service {
	return &Service{
		config: cfg,
		logger: logger,
	}
}

func (s *Service) GetAccessExpirySeconds() int {
	return int(s.config.JWT.AccessExpiry.Seconds())
}

func (s *Service) GenerateToken(userID uint) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.JWT.Issuer,
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  []string{s.config.JWT.Issuer},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.JWT.AccessExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.JWT.SecretKey))
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to sign JWT token", zap.Error(err))
		}
		return "", fmt.Errorf("failed to generate JWT token: %w", err)
	}

	return tokenString, nil
}

func (s *Service) GenerateRefreshToken(userID uint) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.JWT.Issuer,
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  []string{s.config.JWT.Issuer},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.JWT.RefreshExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.JWT.SecretKey))
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to sign JWT refresh token", zap.Error(err))
		}
		return "", fmt.Errorf("failed to generate JWT refresh token: %w", err)
	}

	return tokenString, nil
}

func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWT.SecretKey), nil
	})

	if err != nil {
		if s.logger != nil {
			s.logger.Warn("JWT token validation failed", zap.Error(err))
		}

		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrExpiredToken
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, ErrMalformedToken
		case errors.Is(err, jwt.ErrSignatureInvalid):
			return nil, ErrInvalidSignature
		default:
			return nil, ErrInvalidToken
		}
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

func (s *Service) GenerateTOTPToken(userID uint) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		TokenType: "totp_pending",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.JWT.Issuer,
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  []string{s.config.JWT.Issuer},
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.JWT.SecretKey))
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to sign JWT TOTP token", zap.Error(err))
		}
		return "", fmt.Errorf("failed to generate JWT TOTP token: %w", err)
	}

	return tokenString, nil
}

func (s *Service) RefreshToken(refreshTokenString string) (string, string, error) {
	claims, err := s.ValidateToken(refreshTokenString)
	if err != nil {
		return "", "", err
	}

	newAccessToken, err := s.GenerateToken(claims.UserID)
	if err != nil {
		return "", "", err
	}

	newRefreshToken, err := s.GenerateRefreshToken(claims.UserID)
	if err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}
