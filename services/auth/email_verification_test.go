package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/testutils"
)

func TestService_CreateEmailVerificationToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &EmailVerificationToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.EmailVerificationEnabled = true
	cfg.Auth.EmailVerificationExpiry = time.Hour
	cfg.Auth.EmailVerificationTokenLength = 32

	service := NewService(cfg, db, nil)
	testEmail := "test@example.com"

	t.Run("creates valid email verification token", func(t *testing.T) {
		token, err := service.CreateEmailVerificationToken(testEmail)

		require.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, testEmail, token.Email)
		assert.NotEmpty(t, token.Token)
		assert.False(t, token.Used)
		assert.Nil(t, token.UsedAt)
		assert.True(t, token.ExpiresAt.After(time.Now()))
		assert.True(t, token.ExpiresAt.Before(time.Now().Add(time.Hour+time.Minute)))

		expectedLength := cfg.Auth.EmailVerificationTokenLength * 2
		assert.Equal(t, expectedLength, len(token.Token))
	})

	t.Run("fails when email verification disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.EmailVerificationEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		token, err := serviceDisabled.CreateEmailVerificationToken(testEmail)

		assert.Nil(t, token)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationDisabled, err)
	})

	t.Run("fails when database is nil", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)

		token, err := serviceNoDB.CreateEmailVerificationToken(testEmail)

		assert.Nil(t, token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database is required")
	})

	t.Run("invalidates previous tokens when creating new token", func(t *testing.T) {

		token1, err := service.CreateEmailVerificationToken(testEmail)
		require.NoError(t, err)

		token2, err := service.CreateEmailVerificationToken(testEmail)
		require.NoError(t, err)

		assert.NotEqual(t, token1.Token, token2.Token)
		assert.Equal(t, token1.Email, token2.Email)

		_, err = service.ValidateEmailVerificationToken(token1.Token)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenUsed, err)

		_, err = service.ValidateEmailVerificationToken(token2.Token)
		require.NoError(t, err)
	})

	t.Run("tokens are stored in database", func(t *testing.T) {
		token, err := service.CreateEmailVerificationToken(testEmail)
		require.NoError(t, err)

		var dbToken EmailVerificationToken
		err = db.Where("token = ?", token.Token).First(&dbToken).Error
		require.NoError(t, err)
		assert.Equal(t, token.Email, dbToken.Email)
		assert.Equal(t, token.Token, dbToken.Token)
	})
}

func TestService_ValidateEmailVerificationToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &EmailVerificationToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.EmailVerificationEnabled = true
	cfg.Auth.EmailVerificationExpiry = time.Hour

	service := NewService(cfg, db, nil)
	testEmail := "test@example.com"

	t.Run("validates valid token", func(t *testing.T) {
		createdToken, err := service.CreateEmailVerificationToken(testEmail)
		require.NoError(t, err)

		validatedToken, err := service.ValidateEmailVerificationToken(createdToken.Token)

		require.NoError(t, err)
		assert.NotNil(t, validatedToken)
		assert.Equal(t, createdToken.Email, validatedToken.Email)
		assert.Equal(t, createdToken.Token, validatedToken.Token)
		assert.False(t, validatedToken.Used)
	})

	t.Run("fails for non-existent token", func(t *testing.T) {
		validatedToken, err := service.ValidateEmailVerificationToken("nonexistent-token")

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenInvalid, err)
	})

	t.Run("fails for expired token", func(t *testing.T) {

		expiredToken := &EmailVerificationToken{
			Email:     testEmail,
			Token:     "expired-token",
			ExpiresAt: time.Now().Add(-time.Hour),
			Used:      false,
		}
		err := db.Create(expiredToken).Error
		require.NoError(t, err)

		validatedToken, err := service.ValidateEmailVerificationToken(expiredToken.Token)

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenExpired, err)
	})

	t.Run("fails for used token", func(t *testing.T) {
		now := time.Now()
		usedToken := &EmailVerificationToken{
			Email:     testEmail,
			Token:     "used-token",
			ExpiresAt: time.Now().Add(time.Hour),
			Used:      true,
			UsedAt:    &now,
		}
		err := db.Create(usedToken).Error
		require.NoError(t, err)

		validatedToken, err := service.ValidateEmailVerificationToken(usedToken.Token)

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenUsed, err)
	})

	t.Run("fails when email verification disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.EmailVerificationEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		validatedToken, err := serviceDisabled.ValidateEmailVerificationToken("any-token")

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationDisabled, err)
	})

	t.Run("fails when database is nil", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)

		validatedToken, err := serviceNoDB.ValidateEmailVerificationToken("any-token")

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database is required")
	})
}

func TestService_UseEmailVerificationToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &EmailVerificationToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.EmailVerificationEnabled = true
	cfg.Auth.EmailVerificationExpiry = time.Hour

	service := NewService(cfg, db, nil)
	testEmail := "test@example.com"

	t.Run("marks token as used", func(t *testing.T) {
		createdToken, err := service.CreateEmailVerificationToken(testEmail)
		require.NoError(t, err)

		usedToken, err := service.UseEmailVerificationToken(createdToken.Token)
		require.NoError(t, err)
		assert.NotNil(t, usedToken)
		assert.True(t, usedToken.Used)
		assert.NotNil(t, usedToken.UsedAt)

		var dbToken EmailVerificationToken
		err = db.Where("token = ?", createdToken.Token).First(&dbToken).Error
		require.NoError(t, err)
		assert.True(t, dbToken.Used)
		assert.NotNil(t, dbToken.UsedAt)
		assert.True(t, dbToken.UsedAt.After(time.Now().Add(-time.Minute)))
	})

	t.Run("fails for already used token", func(t *testing.T) {
		createdToken, err := service.CreateEmailVerificationToken(testEmail)
		require.NoError(t, err)

		_, err = service.UseEmailVerificationToken(createdToken.Token)
		require.NoError(t, err)

		_, err = service.UseEmailVerificationToken(createdToken.Token)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenUsed, err)
	})

	t.Run("fails for non-existent token", func(t *testing.T) {
		_, err := service.UseEmailVerificationToken("nonexistent-token")
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenInvalid, err)
	})

	t.Run("fails for expired token", func(t *testing.T) {
		expiredToken := &EmailVerificationToken{
			Email:     testEmail,
			Token:     "expired-use-token",
			ExpiresAt: time.Now().Add(-time.Hour),
			Used:      false,
		}
		err := db.Create(expiredToken).Error
		require.NoError(t, err)

		_, err = service.UseEmailVerificationToken(expiredToken.Token)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenExpired, err)
	})
}

func TestService_SendEmailVerificationEmail(t *testing.T) {
	cfg := testutils.GetTestConfig()
	cfg.App.Name = "Test App"
	service := NewService(cfg, nil, nil)

	t.Run("sends email successfully", func(t *testing.T) {
		mockMail := &testutils.MockMailService{}
		service.SetMailService(mockMail)

		email := "test@example.com"
		verificationURL := "https://example.com/verify?token=abc123"
		expiry := time.Hour

		mockMail.On("SendTemplate", "email_verification", []string{email}, "Please verify your email address", map[string]any{
			"Email":           email,
			"VerificationURL": verificationURL,
			"ExpiryDuration":  expiry.String(),
			"AppName":         cfg.App.Name,
		}).Return(nil)

		err := service.SendEmailVerificationEmail(email, verificationURL, expiry)

		require.NoError(t, err)
		mockMail.AssertExpectations(t)
	})

	t.Run("fails when mail service not configured", func(t *testing.T) {
		serviceNoMail := NewService(cfg, nil, nil)

		err := serviceNoMail.SendEmailVerificationEmail("test@example.com", "https://example.com/verify", time.Hour)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "mail service is not configured")
	})
}

func TestService_RequestEmailVerification(t *testing.T) {
	db := testutils.SetupTestDB(t, &EmailVerificationToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.EmailVerificationEnabled = true
	cfg.Auth.EmailVerificationExpiry = time.Hour
	cfg.App.URL = "https://example.com"

	service := NewService(cfg, db, nil)
	mockMail := &testutils.MockMailService{}
	service.SetMailService(mockMail)

	testEmail := "test@example.com"

	t.Run("creates token and sends email", func(t *testing.T) {

		mockMail.On("SendTemplate", "email_verification", []string{testEmail}, "Please verify your email address", mock.MatchedBy(func(data map[string]any) bool {

			return data["Email"] == testEmail &&
				data["AppName"] == cfg.App.Name &&
				data["ExpiryDuration"] == cfg.Auth.EmailVerificationExpiry.String() &&
				data["VerificationURL"] != nil
		})).Return(nil)

		err := service.RequestEmailVerification(testEmail)

		require.NoError(t, err)
		mockMail.AssertExpectations(t)

		var token EmailVerificationToken
		err = db.Where("email = ?", testEmail).First(&token).Error
		require.NoError(t, err)
		assert.Equal(t, testEmail, token.Email)
		assert.False(t, token.Used)
	})

	t.Run("fails when email verification disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.EmailVerificationEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		err := serviceDisabled.RequestEmailVerification(testEmail)

		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationDisabled, err)
	})

	t.Run("fails when database not configured", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)
		serviceNoDB.SetMailService(mockMail)

		err := serviceNoDB.RequestEmailVerification(testEmail)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "database is required")
	})

	t.Run("fails when mail service not configured", func(t *testing.T) {
		serviceNoMail := NewService(cfg, db, nil)

		err := serviceNoMail.RequestEmailVerification(testEmail)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to send email verification email")
	})
}

type TestUserWithEmailVerification struct {
	ID              uint       `gorm:"primaryKey"`
	Email           string     `gorm:"uniqueIndex;not null"`
	Password        string     `gorm:"not null"`
	EmailVerifiedAt *time.Time `gorm:"default:null"`
}

func (TestUserWithEmailVerification) TableName() string {
	return "users"
}

func TestService_VerifyEmail(t *testing.T) {
	db := testutils.SetupTestDB(t, &EmailVerificationToken{}, &TestUserWithEmailVerification{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.EmailVerificationEnabled = true
	cfg.Auth.EmailVerificationExpiry = time.Hour

	service := NewService(cfg, db, nil)
	testEmail := "test@example.com"

	testUser := &TestUserWithEmailVerification{
		Email:           testEmail,
		Password:        "hashedPassword",
		EmailVerifiedAt: nil,
	}
	err := db.Create(testUser).Error
	require.NoError(t, err)

	t.Run("verifies email successfully", func(t *testing.T) {

		token, err := service.CreateEmailVerificationToken(testEmail)
		require.NoError(t, err)

		err = service.VerifyEmail(token.Token)
		require.NoError(t, err)

		var usedToken EmailVerificationToken
		err = db.Where("token = ?", token.Token).First(&usedToken).Error
		require.NoError(t, err)
		assert.True(t, usedToken.Used)
	})

	t.Run("fails for invalid token", func(t *testing.T) {
		err := service.VerifyEmail("invalid-token")
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenInvalid, err)
	})

	t.Run("fails for expired token", func(t *testing.T) {
		expiredToken := &EmailVerificationToken{
			Email:     testEmail,
			Token:     "expired-verify-token",
			ExpiresAt: time.Now().Add(-time.Hour),
			Used:      false,
		}
		err := db.Create(expiredToken).Error
		require.NoError(t, err)

		err = service.VerifyEmail(expiredToken.Token)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenExpired, err)
	})

	t.Run("fails for already used token", func(t *testing.T) {
		token, err := service.CreateEmailVerificationToken(testEmail)
		require.NoError(t, err)

		err = service.VerifyEmail(token.Token)
		require.NoError(t, err)

		err = service.VerifyEmail(token.Token)
		require.Error(t, err)
		assert.Equal(t, ErrEmailVerificationTokenUsed, err)
	})

	t.Run("fails when user does not exist", func(t *testing.T) {
		nonExistentEmail := "nonexistent@example.com"

		token, err := service.CreateEmailVerificationToken(nonExistentEmail)
		require.NoError(t, err)

		err = service.VerifyEmail(token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")

		var userCount int64
		db.Model(&TestUserWithEmailVerification{}).Where("email = ?", nonExistentEmail).Count(&userCount)
		assert.Equal(t, int64(0), userCount)
	})
}

func TestService_IsEmailVerificationRequired(t *testing.T) {
	cfg := testutils.GetTestConfig()

	t.Run("returns true when email verification enabled", func(t *testing.T) {
		cfg.Auth.EmailVerificationEnabled = true
		service := NewService(cfg, nil, nil)

		required := service.IsEmailVerificationRequired()
		assert.True(t, required)
	})

	t.Run("returns false when email verification disabled", func(t *testing.T) {
		cfg.Auth.EmailVerificationEnabled = false
		service := NewService(cfg, nil, nil)

		required := service.IsEmailVerificationRequired()
		assert.False(t, required)
	})
}

func TestService_IsEmailVerified(t *testing.T) {
	db := testutils.SetupTestDB(t, &TestUserWithEmailVerification{})
	defer testutils.CleanupTestDB(t, db)

	testEmail := "test@example.com"
	verifiedEmail := "verified@example.com"

	unverifiedUser := &TestUserWithEmailVerification{
		Email:           testEmail,
		Password:        "hashedPassword",
		EmailVerifiedAt: nil,
	}
	err := db.Create(unverifiedUser).Error
	require.NoError(t, err)

	now := time.Now()
	verifiedUser := &TestUserWithEmailVerification{
		Email:           verifiedEmail,
		Password:        "hashedPassword",
		EmailVerifiedAt: &now,
	}
	err = db.Create(verifiedUser).Error
	require.NoError(t, err)

	t.Run("returns true when email verification disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.EmailVerificationEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		verified := serviceDisabled.IsEmailVerified(testEmail)
		assert.True(t, verified)
	})

	t.Run("returns false for unverified email when verification enabled", func(t *testing.T) {
		cfgEnabled := testutils.GetTestConfig()
		cfgEnabled.Auth.EmailVerificationEnabled = true
		serviceEnabled := NewService(cfgEnabled, db, nil)

		verified := serviceEnabled.IsEmailVerified(testEmail)
		assert.False(t, verified)
	})

	t.Run("returns true for verified email when verification enabled", func(t *testing.T) {
		cfgEnabled := testutils.GetTestConfig()
		cfgEnabled.Auth.EmailVerificationEnabled = true
		serviceEnabled := NewService(cfgEnabled, db, nil)

		verified := serviceEnabled.IsEmailVerified(verifiedEmail)
		assert.True(t, verified)
	})

	t.Run("returns false for non-existent email", func(t *testing.T) {
		cfgEnabled := testutils.GetTestConfig()
		cfgEnabled.Auth.EmailVerificationEnabled = true
		serviceEnabled := NewService(cfgEnabled, db, nil)

		verified := serviceEnabled.IsEmailVerified("nonexistent@example.com")
		assert.False(t, verified)
	})

	t.Run("returns false when database is nil", func(t *testing.T) {
		cfgEnabled := testutils.GetTestConfig()
		cfgEnabled.Auth.EmailVerificationEnabled = true
		serviceNoDB := NewService(cfgEnabled, nil, nil)

		verified := serviceNoDB.IsEmailVerified(testEmail)
		assert.False(t, verified)
	})
}

func TestService_CleanupExpiredEmailVerificationTokens(t *testing.T) {
	db := testutils.SetupTestDB(t, &EmailVerificationToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.EmailVerificationEnabled = true
	service := NewService(cfg, db, nil)

	testEmail := "test@example.com"

	t.Run("removes expired email verification tokens", func(t *testing.T) {

		validToken, err := service.CreateEmailVerificationToken(testEmail)
		require.NoError(t, err)

		expiredToken := &EmailVerificationToken{
			Email:     "expired@example.com",
			Token:     "expired-token",
			ExpiresAt: time.Now().Add(-time.Hour),
			Used:      false,
		}
		db.Create(expiredToken)

		err = service.CleanupExpiredEmailVerificationTokens()
		require.NoError(t, err)

		var expiredCount int64
		db.Model(&EmailVerificationToken{}).Where("token = ?", expiredToken.Token).Count(&expiredCount)
		assert.Equal(t, int64(0), expiredCount)

		var validCount int64
		db.Model(&EmailVerificationToken{}).Where("token = ?", validToken.Token).Count(&validCount)
		assert.Equal(t, int64(1), validCount)
	})

	t.Run("fails when email verification disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.EmailVerificationEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		err := serviceDisabled.CleanupExpiredEmailVerificationTokens()

		require.Error(t, err)
		testutils.AssertErrorType(t, ErrEmailVerificationDisabled, err)
	})

	t.Run("fails when database is nil", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)

		err := serviceNoDB.CleanupExpiredEmailVerificationTokens()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "database is required")
	})
}
