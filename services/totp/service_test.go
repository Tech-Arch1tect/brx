package totp

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/testutils"
)

func TestNewService(t *testing.T) {
	cfg := testutils.GetTestConfig()
	db := testutils.SetupTestDB(t, &TOTPSecret{})

	service := NewService(cfg, db, nil)

	assert.NotNil(t, service)
	assert.Equal(t, cfg, service.config)
	assert.Equal(t, db, service.db)
	assert.Nil(t, service.logger)
}

func TestService_GenerateSecret(t *testing.T) {
	cfg := testutils.GetTestConfig()
	db := testutils.SetupTestDB(t, &TOTPSecret{})

	t.Run("TOTP disabled", func(t *testing.T) {
		cfg.TOTP.Enabled = false
		service := NewService(cfg, db, nil)

		secret, err := service.GenerateSecret(1, "test@example.com")

		require.Error(t, err)
		assert.Nil(t, secret)
		testutils.AssertErrorType(t, ErrTOTPDisabled, err)
	})

	t.Run("successful generation", func(t *testing.T) {
		cfg.TOTP.Enabled = true
		service := NewService(cfg, db, nil)
		userID := uint(123)
		accountName := "test@example.com"

		secret, err := service.GenerateSecret(userID, accountName)

		require.NoError(t, err)
		assert.NotNil(t, secret)
		assert.Equal(t, userID, secret.UserID)
		assert.NotEmpty(t, secret.Secret)
		assert.False(t, secret.Enabled)
		assert.NotZero(t, secret.ID)

		valid := totp.Validate("123456", secret.Secret)
		assert.False(t, valid)
	})

	t.Run("secret already exists", func(t *testing.T) {
		cfg.TOTP.Enabled = true
		service := NewService(cfg, db, nil)
		userID := uint(456)

		existingSecret := &TOTPSecret{
			UserID:  userID,
			Secret:  "JBSWY3DPEHPK3PXP",
			Enabled: false,
		}
		err := db.Create(existingSecret).Error
		require.NoError(t, err)

		secret, err := service.GenerateSecret(userID, "test@example.com")

		require.Error(t, err)
		assert.Nil(t, secret)
		testutils.AssertErrorType(t, ErrSecretExists, err)
	})

	t.Run("restore deleted secret", func(t *testing.T) {
		cfg.TOTP.Enabled = true
		service := NewService(cfg, db, nil)
		userID := uint(789)

		deletedSecret := &TOTPSecret{
			UserID:  userID,
			Secret:  "JBSWY3DPEHPK3PXP",
			Enabled: true,
		}
		err := db.Create(deletedSecret).Error
		require.NoError(t, err)

		err = db.Delete(deletedSecret).Error
		require.NoError(t, err)

		secret, err := service.GenerateSecret(userID, "test@example.com")

		require.NoError(t, err)
		assert.NotNil(t, secret)
		assert.Equal(t, userID, secret.UserID)
		assert.NotEmpty(t, secret.Secret)
		assert.False(t, secret.Enabled)
		assert.Equal(t, deletedSecret.ID, secret.ID)
	})
}

func TestService_GetSecret(t *testing.T) {
	cfg := testutils.GetTestConfig()
	db := testutils.SetupTestDB(t, &TOTPSecret{})

	t.Run("TOTP disabled", func(t *testing.T) {
		cfg.TOTP.Enabled = false
		service := NewService(cfg, db, nil)

		secret, err := service.GetSecret(1)

		require.Error(t, err)
		assert.Nil(t, secret)
		testutils.AssertErrorType(t, ErrTOTPDisabled, err)
	})

	t.Run("secret not found", func(t *testing.T) {
		cfg.TOTP.Enabled = true
		service := NewService(cfg, db, nil)

		secret, err := service.GetSecret(999)

		require.Error(t, err)
		assert.Nil(t, secret)
		testutils.AssertErrorType(t, ErrSecretNotFound, err)
	})

	t.Run("secret found", func(t *testing.T) {
		cfg.TOTP.Enabled = true
		service := NewService(cfg, db, nil)
		userID := uint(123)

		savedSecret := &TOTPSecret{
			UserID:  userID,
			Secret:  "JBSWY3DPEHPK3PXP",
			Enabled: true,
		}
		err := db.Create(savedSecret).Error
		require.NoError(t, err)

		secret, err := service.GetSecret(userID)

		require.NoError(t, err)
		assert.NotNil(t, secret)
		assert.Equal(t, userID, secret.UserID)
		assert.Equal(t, "JBSWY3DPEHPK3PXP", secret.Secret)
		assert.True(t, secret.Enabled)
	})
}

func TestService_EnableTOTP(t *testing.T) {
	cfg := testutils.GetTestConfig()
	db := testutils.SetupTestDB(t, &TOTPSecret{})

	t.Run("TOTP disabled", func(t *testing.T) {
		cfg.TOTP.Enabled = false
		service := NewService(cfg, db, nil)

		err := service.EnableTOTP(1, "123456")

		require.Error(t, err)
		testutils.AssertErrorType(t, ErrTOTPDisabled, err)
	})

	t.Run("secret not found", func(t *testing.T) {
		cfg.TOTP.Enabled = true
		service := NewService(cfg, db, nil)

		err := service.EnableTOTP(999, "123456")

		require.Error(t, err)
		testutils.AssertErrorType(t, ErrSecretNotFound, err)
	})

	t.Run("invalid code", func(t *testing.T) {
		cfg.TOTP.Enabled = true
		service := NewService(cfg, db, nil)
		userID := uint(123)

		secret := &TOTPSecret{
			UserID:  userID,
			Secret:  "JBSWY3DPEHPK3PXP",
			Enabled: false,
		}
		err := db.Create(secret).Error
		require.NoError(t, err)

		err = service.EnableTOTP(userID, "000000")

		require.Error(t, err)
		testutils.AssertErrorType(t, ErrInvalidCode, err)

		var updatedSecret TOTPSecret
		err = db.Where("user_id = ?", userID).First(&updatedSecret).Error
		require.NoError(t, err)
		assert.False(t, updatedSecret.Enabled)
	})

	t.Run("valid code enables TOTP", func(t *testing.T) {
		cfg.TOTP.Enabled = true
		service := NewService(cfg, db, nil)
		userID := uint(456)

		secret, err := service.GenerateSecret(userID, "test@example.com")
		require.NoError(t, err)

		code, err := totp.GenerateCode(secret.Secret, time.Now())
		require.NoError(t, err)

		err = service.EnableTOTP(userID, code)

		require.NoError(t, err)

		updatedSecret, err := service.GetSecret(userID)
		require.NoError(t, err)
		assert.True(t, updatedSecret.Enabled)
	})
}

func TestService_getIssuer(t *testing.T) {
	cfg := testutils.GetTestConfig()
	db := testutils.SetupTestDB(t, &TOTPSecret{})

	t.Run("custom issuer", func(t *testing.T) {
		cfg.TOTP.Issuer = "Custom App"
		service := NewService(cfg, db, nil)

		issuer := service.getIssuer()

		assert.Equal(t, "Custom App", issuer)
	})

	t.Run("default issuer when empty", func(t *testing.T) {
		cfg.TOTP.Issuer = ""
		service := NewService(cfg, db, nil)

		issuer := service.getIssuer()

		assert.Equal(t, "brx Application", issuer)
	})
}

func TestService_ValidateCode_Integration(t *testing.T) {
	cfg := testutils.GetTestConfig()
	db := testutils.SetupTestDB(t, &TOTPSecret{}, &UsedCode{})
	service := NewService(cfg, db, nil)
	userID := uint(123)

	secret, err := service.GenerateSecret(userID, "test@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret.Secret, time.Now())
	require.NoError(t, err)

	err = service.EnableTOTP(userID, code)
	require.NoError(t, err)

	t.Run("valid current code", func(t *testing.T) {

		validCode, err := totp.GenerateCode(secret.Secret, time.Now())
		require.NoError(t, err)

		isValid := totp.Validate(validCode, secret.Secret)
		assert.True(t, isValid)
	})

	t.Run("invalid code", func(t *testing.T) {
		isValid := totp.Validate("000000", secret.Secret)
		assert.False(t, isValid)
	})
}
