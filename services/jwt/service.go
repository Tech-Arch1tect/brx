package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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
	ErrTokenRevoked     = errors.New("JWT token has been revoked")
)

type Claims struct {
	UserID    uint   `json:"user_id"`
	TokenType string `json:"token_type,omitempty"`
	JTI       string `json:"jti"`
	jwt.RegisteredClaims
}

type RevocationService interface {
	IsTokenRevoked(tokenString string) (bool, error)
	RevokeToken(tokenString string) error
}

type Service struct {
	config            *config.Config
	logger            *logging.Service
	revocationService RevocationService
}

func NewService(cfg *config.Config, logger *logging.Service) *Service {
	return &Service{
		config:            cfg,
		logger:            logger,
		revocationService: nil,
	}
}

func (s *Service) SetRevocationService(revocationService RevocationService) {
	s.revocationService = revocationService
}

func (s *Service) GetAccessExpirySeconds() int {
	return int(s.config.JWT.AccessExpiry.Seconds())
}

func (s *Service) GetRefreshExpirySeconds() int {
	return int(s.config.JWT.RefreshExpiry.Seconds())
}

func (s *Service) GenerateToken(userID uint) (string, error) {
	now := time.Now()
	jti := uuid.New().String()
	claims := Claims{
		UserID: userID,
		JTI:    jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
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
	jti := uuid.New().String()
	claims := Claims{
		UserID: userID,
		JTI:    jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
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
		if token.Method.Alg() == "none" {
			return nil, errors.New("'none' algorithm is not allowed")
		}

		if token.Method.Alg() != "HS256" {
			return nil, fmt.Errorf("unexpected algorithm: expected HS256, got %s", token.Method.Alg())
		}

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid algorithm family: %v", token.Header["alg"])
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

		if s.revocationService != nil {
			revoked, err := s.revocationService.IsTokenRevoked(tokenString)
			if err != nil {
				if s.logger != nil {
					s.logger.Error("failed to check token revocation status", zap.Error(err))
				}

			} else if revoked {
				if s.logger != nil {
					s.logger.Warn("token validation failed - token has been revoked")
				}
				return nil, ErrTokenRevoked
			}
		}

		return claims, nil
	}

	return nil, ErrInvalidToken
}

func (s *Service) GenerateTOTPToken(userID uint) (string, error) {
	now := time.Now()
	jti := uuid.New().String()
	claims := Claims{
		UserID:    userID,
		TokenType: "totp_pending",
		JTI:       jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
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

func (s *Service) RevokeToken(tokenString string) error {
	if s.revocationService == nil {
		if s.logger != nil {
			s.logger.Warn("token revocation requested but revocation service not available")
		}
		return nil
	}

	err := s.revocationService.RevokeToken(tokenString)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to revoke token", zap.Error(err))
		}
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("token revoked successfully")
	}

	return nil
}

func (s *Service) IsTokenRevoked(tokenString string) (bool, error) {
	if s.revocationService == nil {
		return false, nil
	}

	return s.revocationService.IsTokenRevoked(tokenString)
}
