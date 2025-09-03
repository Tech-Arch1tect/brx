package totp

import (
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var (
	ErrTOTPDisabled    = errors.New("TOTP is disabled")
	ErrInvalidCode     = errors.New("invalid TOTP code")
	ErrSecretExists    = errors.New("TOTP secret already exists for user")
	ErrSecretNotFound  = errors.New("TOTP secret not found for user")
	ErrCodeAlreadyUsed = errors.New("TOTP code has already been used")
)

type Service struct {
	config *config.Config
	db     *gorm.DB
	logger *logging.Service
}

func NewService(cfg *config.Config, db *gorm.DB, logger *logging.Service) *Service {
	if logger != nil {
		logger.Info("initializing TOTP service",
			zap.Bool("enabled", cfg.TOTP.Enabled),
			zap.String("issuer", cfg.TOTP.Issuer))
	}

	return &Service{
		config: cfg,
		db:     db,
		logger: logger,
	}
}

func (s *Service) GenerateSecret(userID uint, accountName string) (*TOTPSecret, error) {
	if s.logger != nil {
		s.logger.Info("generating TOTP secret",
			zap.Uint("user_id", userID),
			zap.String("account_name", accountName))
	}

	if !s.config.TOTP.Enabled {
		if s.logger != nil {
			s.logger.Warn("TOTP secret generation attempted but TOTP is disabled",
				zap.Uint("user_id", userID))
		}
		return nil, ErrTOTPDisabled
	}

	var existing TOTPSecret
	if err := s.db.Where("user_id = ?", userID).First(&existing).Error; err == nil {
		if s.logger != nil {
			s.logger.Warn("TOTP secret generation failed - secret already exists",
				zap.Uint("user_id", userID))
		}
		return nil, ErrSecretExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		if s.logger != nil {
			s.logger.Error("failed to check existing TOTP secret",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return nil, fmt.Errorf("failed to check existing TOTP secret: %w", err)
	}

	secretString, err := s.generateTOTPKey(accountName)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate TOTP key",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return nil, err
	}

	var deletedSecret TOTPSecret
	if err := s.db.Unscoped().Where("user_id = ? AND deleted_at IS NOT NULL", userID).First(&deletedSecret).Error; err == nil {
		if s.logger != nil {
			s.logger.Info("restoring previously deleted TOTP secret",
				zap.Uint("user_id", userID))
		}

		deletedSecret.Secret = secretString
		deletedSecret.Enabled = false
		deletedSecret.DeletedAt = gorm.DeletedAt{}

		if err := s.db.Unscoped().Save(&deletedSecret).Error; err != nil {
			if s.logger != nil {
				s.logger.Error("failed to restore TOTP secret",
					zap.Error(err),
					zap.Uint("user_id", userID))
			}
			return nil, fmt.Errorf("failed to restore TOTP secret: %w", err)
		}

		if s.logger != nil {
			s.logger.Info("TOTP secret restored successfully",
				zap.Uint("user_id", userID))
		}
		return &deletedSecret, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		if s.logger != nil {
			s.logger.Error("failed to check deleted TOTP secret",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return nil, fmt.Errorf("failed to check deleted TOTP secret: %w", err)
	}

	totpSecret := &TOTPSecret{
		UserID:  userID,
		Secret:  secretString,
		Enabled: false,
	}

	if err := s.db.Create(totpSecret).Error; err != nil {
		if s.logger != nil {
			s.logger.Error("failed to store TOTP secret",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return nil, fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("TOTP secret generated successfully",
			zap.Uint("user_id", userID),
			zap.Uint("secret_id", totpSecret.ID))
	}

	return totpSecret, nil
}

func (s *Service) generateTOTPKey(accountName string) (string, error) {
	issuer := s.getIssuer()
	if s.logger != nil {
		s.logger.Debug("generating TOTP key",
			zap.String("issuer", issuer),
			zap.String("account_name", accountName))
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		if s.logger != nil {
			s.logger.Error("TOTP key generation failed",
				zap.Error(err),
				zap.String("account_name", accountName))
		}
		return "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	if s.logger != nil {
		s.logger.Debug("TOTP key generated successfully")
	}

	return key.Secret(), nil
}

func (s *Service) getIssuer() string {
	if s.config.TOTP.Issuer == "" {
		return "brx Application"
	}
	return s.config.TOTP.Issuer
}

func (s *Service) GetSecret(userID uint) (*TOTPSecret, error) {
	if s.logger != nil {
		s.logger.Debug("retrieving TOTP secret",
			zap.Uint("user_id", userID))
	}

	if !s.config.TOTP.Enabled {
		if s.logger != nil {
			s.logger.Warn("TOTP secret retrieval attempted but TOTP is disabled",
				zap.Uint("user_id", userID))
		}
		return nil, ErrTOTPDisabled
	}

	var secret TOTPSecret
	if err := s.db.Where("user_id = ?", userID).First(&secret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if s.logger != nil {
				s.logger.Debug("TOTP secret not found for user",
					zap.Uint("user_id", userID))
			}
			return nil, ErrSecretNotFound
		}
		if s.logger != nil {
			s.logger.Error("failed to retrieve TOTP secret",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return nil, fmt.Errorf("failed to retrieve TOTP secret: %w", err)
	}

	if s.logger != nil {
		s.logger.Debug("TOTP secret retrieved successfully",
			zap.Uint("user_id", userID),
			zap.Bool("enabled", secret.Enabled))
	}

	return &secret, nil
}

func (s *Service) EnableTOTP(userID uint, code string) error {
	if s.logger != nil {
		s.logger.Info("enabling TOTP for user",
			zap.Uint("user_id", userID))
	}

	if !s.config.TOTP.Enabled {
		if s.logger != nil {
			s.logger.Warn("TOTP enable attempted but TOTP is disabled",
				zap.Uint("user_id", userID))
		}
		return ErrTOTPDisabled
	}

	secret, err := s.GetSecret(userID)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to get TOTP secret for enable operation",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return err
	}

	if !totp.Validate(code, secret.Secret) {
		if s.logger != nil {
			s.logger.Warn("TOTP enable failed - invalid verification code",
				zap.Uint("user_id", userID))
		}
		return ErrInvalidCode
	}

	secret.Enabled = true
	if err := s.db.Save(secret).Error; err != nil {
		if s.logger != nil {
			s.logger.Error("failed to enable TOTP in database",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return fmt.Errorf("failed to enable TOTP: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("TOTP enabled successfully",
			zap.Uint("user_id", userID))
	}

	return nil
}

func (s *Service) DisableTOTP(userID uint) error {
	if s.logger != nil {
		s.logger.Info("disabling TOTP for user",
			zap.Uint("user_id", userID))
	}

	if !s.config.TOTP.Enabled {
		if s.logger != nil {
			s.logger.Warn("TOTP disable attempted but TOTP is disabled",
				zap.Uint("user_id", userID))
		}
		return ErrTOTPDisabled
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if s.logger != nil {
			s.logger.Debug("starting TOTP disable transaction",
				zap.Uint("user_id", userID))
		}

		result := tx.Where("user_id = ?", userID).Delete(&TOTPSecret{})
		if result.Error != nil {
			if s.logger != nil {
				s.logger.Error("failed to delete TOTP secret",
					zap.Error(result.Error),
					zap.Uint("user_id", userID))
			}
			return fmt.Errorf("failed to disable TOTP: %w", result.Error)
		}

		if result.RowsAffected == 0 {
			if s.logger != nil {
				s.logger.Warn("TOTP disable failed - no secret found",
					zap.Uint("user_id", userID))
			}
			return ErrSecretNotFound
		}

		usedCodesResult := tx.Where("user_id = ?", userID).Delete(&UsedCode{})
		if usedCodesResult.Error != nil {
			if s.logger != nil {
				s.logger.Error("failed to clean up used codes",
					zap.Error(usedCodesResult.Error),
					zap.Uint("user_id", userID))
			}
			return fmt.Errorf("failed to clean up used codes: %w", usedCodesResult.Error)
		}

		if s.logger != nil {
			s.logger.Info("TOTP disabled successfully",
				zap.Uint("user_id", userID),
				zap.Int64("used_codes_cleaned", usedCodesResult.RowsAffected))
		}

		return nil
	})
}

func (s *Service) GenerateProvisioningURI(secret *TOTPSecret, accountName string) (string, error) {
	if s.logger != nil {
		s.logger.Debug("generating TOTP provisioning URI",
			zap.Uint("user_id", secret.UserID),
			zap.String("account_name", accountName))
	}

	if !s.config.TOTP.Enabled {
		if s.logger != nil {
			s.logger.Warn("TOTP provisioning URI generation attempted but TOTP is disabled",
				zap.Uint("user_id", secret.UserID))
		}
		return "", ErrTOTPDisabled
	}

	issuer := s.getIssuer()

	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, accountName, secret.Secret, issuer)

	if s.logger != nil {
		s.logger.Debug("TOTP provisioning URI generated successfully",
			zap.Uint("user_id", secret.UserID))
	}

	return uri, nil
}

func (s *Service) IsUserTOTPEnabled(userID uint) bool {
	if s.logger != nil {
		s.logger.Debug("checking if user has TOTP enabled",
			zap.Uint("user_id", userID))
	}

	if !s.config.TOTP.Enabled {
		if s.logger != nil {
			s.logger.Debug("TOTP check returned false - TOTP disabled globally",
				zap.Uint("user_id", userID))
		}
		return false
	}

	secret, err := s.GetSecret(userID)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("TOTP check returned false - secret not found or error",
				zap.Uint("user_id", userID),
				zap.Error(err))
		}
		return false
	}

	if s.logger != nil {
		s.logger.Debug("TOTP enabled status check completed",
			zap.Uint("user_id", userID),
			zap.Bool("enabled", secret.Enabled))
	}

	return secret.Enabled
}

func (s *Service) VerifyUserCode(userID uint, code string) error {
	if s.logger != nil {
		s.logger.Info("verifying TOTP code",
			zap.Uint("user_id", userID))
	}

	if !s.config.TOTP.Enabled {
		if s.logger != nil {
			s.logger.Warn("TOTP verification attempted but TOTP is disabled",
				zap.Uint("user_id", userID))
		}
		return ErrTOTPDisabled
	}

	secret, err := s.GetSecret(userID)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("TOTP verification failed - could not get secret",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return err
	}

	if !secret.Enabled {
		if s.logger != nil {
			s.logger.Warn("TOTP verification failed - TOTP not enabled for user",
				zap.Uint("user_id", userID))
		}
		return ErrSecretNotFound
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if s.logger != nil {
			s.logger.Debug("starting TOTP verification transaction",
				zap.Uint("user_id", userID))
		}

		cutoff := time.Now().Unix() - 90
		var existingCode UsedCode
		if err := tx.Where("user_id = ? AND code = ? AND used_at > ?", userID, code, cutoff).First(&existingCode).Error; err == nil {
			if s.logger != nil {
				s.logger.Warn("TOTP verification failed - code already used",
					zap.Uint("user_id", userID),
					zap.Int64("used_at", existingCode.UsedAt))
			}
			return ErrCodeAlreadyUsed
		}

		if !totp.Validate(code, secret.Secret) {
			if s.logger != nil {
				s.logger.Warn("TOTP verification failed - invalid code",
					zap.Uint("user_id", userID))
			}
			return ErrInvalidCode
		}

		usedCode := &UsedCode{
			UserID: userID,
			Code:   code,
			UsedAt: time.Now().Unix(),
		}
		if err := tx.Create(usedCode).Error; err != nil {
			if s.logger != nil {
				s.logger.Error("failed to store used TOTP code",
					zap.Error(err),
					zap.Uint("user_id", userID))
			}
			return fmt.Errorf("failed to store used code: %w", err)
		}

		if s.logger != nil {
			s.logger.Info("TOTP code verified successfully",
				zap.Uint("user_id", userID))
		}

		return nil
	})
}

func (s *Service) CleanupUsedCodes() error {
	if s.logger != nil {
		s.logger.Info("starting TOTP used codes cleanup")
	}

	if !s.config.TOTP.Enabled {
		if s.logger != nil {
			s.logger.Debug("TOTP cleanup skipped - TOTP disabled")
		}
		return ErrTOTPDisabled
	}

	cutoff := time.Now().Unix() - 90
	result := s.db.Where("used_at < ?", cutoff).Delete(&UsedCode{})
	if result.Error != nil {
		if s.logger != nil {
			s.logger.Error("failed to cleanup used TOTP codes",
				zap.Error(result.Error),
				zap.Int64("cutoff", cutoff))
		}
		return result.Error
	}

	if s.logger != nil {
		s.logger.Info("TOTP used codes cleanup completed",
			zap.Int64("cleaned_count", result.RowsAffected),
			zap.Int64("cutoff", cutoff))
	}

	return nil
}
