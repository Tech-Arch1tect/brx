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
	IsTokenRevoked(jti string) (bool, error)
	RevokeToken(jti string, expiresAt time.Time) error
}

type Service struct {
	config            *config.Config
	logger            *logging.Service
	revocationService RevocationService
}

func NewService(cfg *config.Config, logger *logging.Service) *Service {
	if logger != nil {
		logger.Info("initializing JWT service",
			zap.String("algorithm", cfg.JWT.Algorithm),
			zap.Duration("access_expiry", cfg.JWT.AccessExpiry),
			zap.String("issuer", cfg.JWT.Issuer))
	}

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

func (s *Service) GenerateToken(userID uint) (string, error) {
	if s.logger != nil {
		s.logger.Debug("generating JWT access token", zap.Uint("user_id", userID))
	}

	now := time.Now()
	jti := uuid.New().String()
	expiresAt := now.Add(s.config.JWT.AccessExpiry)

	claims := Claims{
		UserID: userID,
		JTI:    jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    s.config.JWT.Issuer,
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  []string{s.config.JWT.Issuer},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.JWT.SecretKey))
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to sign JWT token",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return "", fmt.Errorf("failed to generate JWT token: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("JWT access token generated successfully",
			zap.Uint("user_id", userID),
			zap.String("jti", jti),
			zap.Time("expires_at", expiresAt))
	}

	return tokenString, nil
}

func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	if s.logger != nil {
		s.logger.Debug("validating JWT token")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() == "none" {
			if s.logger != nil {
				s.logger.Warn("JWT token validation failed: 'none' algorithm attempted")
			}
			return nil, errors.New("'none' algorithm is not allowed")
		}

		if token.Method.Alg() != "HS256" {
			if s.logger != nil {
				s.logger.Warn("JWT token validation failed: unexpected algorithm",
					zap.String("algorithm", token.Method.Alg()))
			}
			return nil, fmt.Errorf("unexpected algorithm: expected HS256, got %s", token.Method.Alg())
		}

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			if s.logger != nil {
				s.logger.Warn("JWT token validation failed: invalid algorithm family",
					zap.Any("algorithm", token.Header["alg"]))
			}
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
		if s.logger != nil {
			s.logger.Debug("JWT token parsed successfully",
				zap.Uint("user_id", claims.UserID),
				zap.String("jti", claims.JTI))
		}

		if s.revocationService != nil {
			revoked, err := s.revocationService.IsTokenRevoked(claims.JTI)
			if err != nil {
				if s.logger != nil {
					s.logger.Error("JTI revocation check failed - denying access for security",
						zap.String("jti", claims.JTI), zap.Error(err))
				}
				return nil, errors.New("token validation failed")
			}
			if revoked {
				if s.logger != nil {
					s.logger.Warn("token validation failed - token JTI has been revoked",
						zap.String("jti", claims.JTI),
						zap.Uint("user_id", claims.UserID))
				}
				return nil, ErrTokenRevoked
			}
		}

		if s.logger != nil {
			s.logger.Debug("JWT token validation successful",
				zap.Uint("user_id", claims.UserID),
				zap.String("jti", claims.JTI))
		}

		return claims, nil
	}

	if s.logger != nil {
		s.logger.Warn("JWT token validation failed: invalid token structure")
	}
	return nil, ErrInvalidToken
}

func (s *Service) GenerateTOTPToken(userID uint) (string, error) {
	if s.logger != nil {
		s.logger.Debug("generating JWT TOTP pending token", zap.Uint("user_id", userID))
	}

	now := time.Now()
	jti := uuid.New().String()
	expiresAt := now.Add(10 * time.Minute)

	claims := Claims{
		UserID:    userID,
		TokenType: "totp_pending",
		JTI:       jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    s.config.JWT.Issuer,
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  []string{s.config.JWT.Issuer},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.JWT.SecretKey))
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to sign JWT TOTP token",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return "", fmt.Errorf("failed to generate JWT TOTP token: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("JWT TOTP pending token generated successfully",
			zap.Uint("user_id", userID),
			zap.String("jti", jti),
			zap.Time("expires_at", expiresAt))
	}

	return tokenString, nil
}

func (s *Service) ExtractJTI(tokenString string) (string, error) {
	if s.logger != nil {
		s.logger.Debug("extracting JTI from token")
	}

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to parse token for JTI extraction", zap.Error(err))
		}
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && claims.JTI != "" {
		if s.logger != nil {
			s.logger.Debug("JTI extracted successfully", zap.String("jti", claims.JTI))
		}
		return claims.JTI, nil
	}

	if regClaims, ok := token.Claims.(*jwt.RegisteredClaims); ok && regClaims.ID != "" {
		if s.logger != nil {
			s.logger.Debug("JTI extracted from registered claims", zap.String("jti", regClaims.ID))
		}
		return regClaims.ID, nil
	}

	if s.logger != nil {
		s.logger.Warn("token missing JTI claim")
	}
	return "", errors.New("token missing JTI claim")
}

func (s *Service) RevokeToken(jti string, expiresAt time.Time) error {
	if s.revocationService == nil {
		if s.logger != nil {
			s.logger.Warn("token revocation by JTI requested but revocation service not available")
		}
		return nil
	}

	err := s.revocationService.RevokeToken(jti, expiresAt)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to revoke token by JTI", zap.String("jti", jti), zap.Error(err))
		}
		return fmt.Errorf("failed to revoke token by JTI: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("token revoked successfully by JTI", zap.String("jti", jti))
	}

	return nil
}

func (s *Service) IsTokenRevoked(jti string) (bool, error) {
	if s.revocationService == nil {
		if s.logger != nil {
			s.logger.Debug("revocation check requested but no revocation service available")
		}
		return false, nil
	}

	if s.logger != nil {
		s.logger.Debug("checking token revocation status", zap.String("jti", jti))
	}

	revoked, err := s.revocationService.IsTokenRevoked(jti)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to check token revocation status",
				zap.String("jti", jti),
				zap.Error(err))
		}
		return false, err
	}

	if s.logger != nil {
		s.logger.Debug("token revocation check completed",
			zap.String("jti", jti),
			zap.Bool("revoked", revoked))
	}

	return revoked, nil
}
