package totp

import (
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/tech-arch1tect/brx/config"
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
}

func NewService(cfg *config.Config, db *gorm.DB) *Service {
	return &Service{
		config: cfg,
		db:     db,
	}
}

func (s *Service) GenerateSecret(userID uint, accountName string) (*TOTPSecret, error) {
	if !s.config.TOTP.Enabled {
		return nil, ErrTOTPDisabled
	}

	var existing TOTPSecret
	if err := s.db.Where("user_id = ?", userID).First(&existing).Error; err == nil {
		return nil, ErrSecretExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to check existing TOTP secret: %w", err)
	}

	secretString, err := s.generateTOTPKey(accountName)
	if err != nil {
		return nil, err
	}

	var deletedSecret TOTPSecret
	if err := s.db.Unscoped().Where("user_id = ? AND deleted_at IS NOT NULL", userID).First(&deletedSecret).Error; err == nil {

		deletedSecret.Secret = secretString
		deletedSecret.Enabled = false
		deletedSecret.DeletedAt = gorm.DeletedAt{}

		if err := s.db.Unscoped().Save(&deletedSecret).Error; err != nil {
			return nil, fmt.Errorf("failed to restore TOTP secret: %w", err)
		}

		return &deletedSecret, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to check deleted TOTP secret: %w", err)
	}

	totpSecret := &TOTPSecret{
		UserID:  userID,
		Secret:  secretString,
		Enabled: false,
	}

	if err := s.db.Create(totpSecret).Error; err != nil {
		return nil, fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	return totpSecret, nil
}

func (s *Service) generateTOTPKey(accountName string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.getIssuer(),
		AccountName: accountName,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP key: %w", err)
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
	if !s.config.TOTP.Enabled {
		return nil, ErrTOTPDisabled
	}

	var secret TOTPSecret
	if err := s.db.Where("user_id = ?", userID).First(&secret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSecretNotFound
		}
		return nil, fmt.Errorf("failed to retrieve TOTP secret: %w", err)
	}

	return &secret, nil
}

func (s *Service) EnableTOTP(userID uint, code string) error {
	if !s.config.TOTP.Enabled {
		return ErrTOTPDisabled
	}

	secret, err := s.GetSecret(userID)
	if err != nil {
		return err
	}

	if !totp.Validate(code, secret.Secret) {
		return ErrInvalidCode
	}

	secret.Enabled = true
	if err := s.db.Save(secret).Error; err != nil {
		return fmt.Errorf("failed to enable TOTP: %w", err)
	}

	return nil
}

func (s *Service) DisableTOTP(userID uint) error {
	if !s.config.TOTP.Enabled {
		return ErrTOTPDisabled
	}

	return s.db.Transaction(func(tx *gorm.DB) error {

		result := tx.Where("user_id = ?", userID).Delete(&TOTPSecret{})
		if result.Error != nil {
			return fmt.Errorf("failed to disable TOTP: %w", result.Error)
		}

		if result.RowsAffected == 0 {
			return ErrSecretNotFound
		}

		if err := tx.Where("user_id = ?", userID).Delete(&UsedCode{}).Error; err != nil {
			return fmt.Errorf("failed to clean up used codes: %w", err)
		}

		return nil
	})
}

func (s *Service) GenerateProvisioningURI(secret *TOTPSecret, accountName string) (string, error) {
	if !s.config.TOTP.Enabled {
		return "", ErrTOTPDisabled
	}

	issuer := s.getIssuer()

	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, accountName, secret.Secret, issuer)

	return uri, nil
}

func (s *Service) IsUserTOTPEnabled(userID uint) bool {
	if !s.config.TOTP.Enabled {
		return false
	}

	secret, err := s.GetSecret(userID)
	if err != nil {
		return false
	}

	return secret.Enabled
}

func (s *Service) VerifyUserCode(userID uint, code string) error {
	if !s.config.TOTP.Enabled {
		return ErrTOTPDisabled
	}

	secret, err := s.GetSecret(userID)
	if err != nil {
		return err
	}

	if !secret.Enabled {
		return ErrSecretNotFound
	}

	return s.db.Transaction(func(tx *gorm.DB) error {

		cutoff := time.Now().Unix() - 90
		var existingCode UsedCode
		if err := tx.Where("user_id = ? AND code = ? AND used_at > ?", userID, code, cutoff).First(&existingCode).Error; err == nil {
			return ErrCodeAlreadyUsed
		}

		if !totp.Validate(code, secret.Secret) {
			return ErrInvalidCode
		}

		usedCode := &UsedCode{
			UserID: userID,
			Code:   code,
			UsedAt: time.Now().Unix(),
		}
		if err := tx.Create(usedCode).Error; err != nil {
			return fmt.Errorf("failed to store used code: %w", err)
		}

		return nil
	})
}

func (s *Service) CleanupUsedCodes() error {
	if !s.config.TOTP.Enabled {
		return ErrTOTPDisabled
	}

	cutoff := time.Now().Unix() - 90
	result := s.db.Where("used_at < ?", cutoff).Delete(&UsedCode{})
	return result.Error
}
