package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/testutils"
)

func TestService_CreatePasswordResetToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &PasswordResetToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.PasswordResetEnabled = true
	cfg.Auth.PasswordResetExpiry = time.Hour
	cfg.Auth.PasswordResetTokenLength = 32

	service := NewService(cfg, db, nil)
	testEmail := "test@example.com"

	t.Run("creates valid password reset token", func(t *testing.T) {
		token, err := service.CreatePasswordResetToken(testEmail)

		require.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, testEmail, token.Email)
		assert.NotEmpty(t, token.Token)
		assert.False(t, token.Used)
		assert.Nil(t, token.UsedAt)
		assert.True(t, token.ExpiresAt.After(time.Now()))
		assert.True(t, token.ExpiresAt.Before(time.Now().Add(time.Hour+time.Minute)))

		expectedLength := cfg.Auth.PasswordResetTokenLength * 2
		assert.Equal(t, expectedLength, len(token.Token))
	})

	t.Run("fails when password reset disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.PasswordResetEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		token, err := serviceDisabled.CreatePasswordResetToken(testEmail)

		assert.Nil(t, token)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetDisabled, err)
	})

	t.Run("fails when database is nil", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)

		token, err := serviceNoDB.CreatePasswordResetToken(testEmail)

		assert.Nil(t, token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database is required")
	})

	t.Run("invalidates previous tokens when creating new token", func(t *testing.T) {

		token1, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		token2, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		assert.NotEqual(t, token1.Token, token2.Token)
		assert.Equal(t, token1.Email, token2.Email)

		_, err = service.ValidatePasswordResetToken(token1.Token)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenUsed, err)

		_, err = service.ValidatePasswordResetToken(token2.Token)
		require.NoError(t, err)
	})

	t.Run("tokens are stored in database", func(t *testing.T) {
		token, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		var dbToken PasswordResetToken
		err = db.Where("token = ?", token.Token).First(&dbToken).Error
		require.NoError(t, err)
		assert.Equal(t, token.Email, dbToken.Email)
		assert.Equal(t, token.Token, dbToken.Token)
	})
}

func TestService_ValidatePasswordResetToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &PasswordResetToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.PasswordResetEnabled = true
	cfg.Auth.PasswordResetExpiry = time.Hour

	service := NewService(cfg, db, nil)
	testEmail := "test@example.com"

	t.Run("validates valid token", func(t *testing.T) {
		createdToken, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		validatedToken, err := service.ValidatePasswordResetToken(createdToken.Token)

		require.NoError(t, err)
		assert.NotNil(t, validatedToken)
		assert.Equal(t, createdToken.Email, validatedToken.Email)
		assert.Equal(t, createdToken.Token, validatedToken.Token)
		assert.False(t, validatedToken.Used)
	})

	t.Run("fails for non-existent token", func(t *testing.T) {
		validatedToken, err := service.ValidatePasswordResetToken("nonexistent-token")

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenInvalid, err)
	})

	t.Run("fails for expired token", func(t *testing.T) {

		expiredToken := &PasswordResetToken{
			Email:     testEmail,
			Token:     "expired-token",
			ExpiresAt: time.Now().Add(-time.Hour),
			Used:      false,
		}
		err := db.Create(expiredToken).Error
		require.NoError(t, err)

		validatedToken, err := service.ValidatePasswordResetToken(expiredToken.Token)

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenExpired, err)
	})

	t.Run("fails for used token", func(t *testing.T) {
		now := time.Now()
		usedToken := &PasswordResetToken{
			Email:     testEmail,
			Token:     "used-token",
			ExpiresAt: time.Now().Add(time.Hour),
			Used:      true,
			UsedAt:    &now,
		}
		err := db.Create(usedToken).Error
		require.NoError(t, err)

		validatedToken, err := service.ValidatePasswordResetToken(usedToken.Token)

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenUsed, err)
	})

	t.Run("fails when password reset disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.PasswordResetEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		validatedToken, err := serviceDisabled.ValidatePasswordResetToken("any-token")

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetDisabled, err)
	})

	t.Run("fails when database is nil", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)

		validatedToken, err := serviceNoDB.ValidatePasswordResetToken("any-token")

		assert.Nil(t, validatedToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database is required")
	})
}

func TestService_UsePasswordResetToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &PasswordResetToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.PasswordResetEnabled = true
	cfg.Auth.PasswordResetExpiry = time.Hour

	service := NewService(cfg, db, nil)
	testEmail := "test@example.com"

	t.Run("marks token as used", func(t *testing.T) {
		createdToken, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		usedToken, err := service.UsePasswordResetToken(createdToken.Token)
		require.NoError(t, err)
		assert.NotNil(t, usedToken)
		assert.True(t, usedToken.Used)
		assert.NotNil(t, usedToken.UsedAt)

		var dbToken PasswordResetToken
		err = db.Where("token = ?", createdToken.Token).First(&dbToken).Error
		require.NoError(t, err)
		assert.True(t, dbToken.Used)
		assert.NotNil(t, dbToken.UsedAt)
		assert.True(t, dbToken.UsedAt.After(time.Now().Add(-time.Minute)))
	})

	t.Run("fails for already used token", func(t *testing.T) {
		createdToken, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		_, err = service.UsePasswordResetToken(createdToken.Token)
		require.NoError(t, err)

		_, err = service.UsePasswordResetToken(createdToken.Token)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenUsed, err)
	})

	t.Run("fails for non-existent token", func(t *testing.T) {
		_, err := service.UsePasswordResetToken("nonexistent-token")
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenInvalid, err)
	})

	t.Run("fails for expired token", func(t *testing.T) {
		expiredToken := &PasswordResetToken{
			Email:     testEmail,
			Token:     "expired-use-token",
			ExpiresAt: time.Now().Add(-time.Hour),
			Used:      false,
		}
		err := db.Create(expiredToken).Error
		require.NoError(t, err)

		_, err = service.UsePasswordResetToken(expiredToken.Token)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenExpired, err)
	})
}

func TestService_SendPasswordResetEmail(t *testing.T) {
	cfg := testutils.GetTestConfig()
	cfg.App.Name = "Test App"
	service := NewService(cfg, nil, nil)

	t.Run("sends email successfully", func(t *testing.T) {
		mockMail := &testutils.MockMailService{}
		service.SetMailService(mockMail)

		email := "test@example.com"
		resetURL := "https://example.com/reset?token=abc123"
		expiry := time.Hour

		mockMail.On("SendTemplate", "password_reset", []string{email}, "Password Reset Request", map[string]any{
			"Email":          email,
			"ResetURL":       resetURL,
			"ExpiryDuration": expiry.String(),
			"AppName":        cfg.App.Name,
		}).Return(nil)

		err := service.SendPasswordResetEmail(email, resetURL, expiry)

		require.NoError(t, err)
		mockMail.AssertExpectations(t)
	})

	t.Run("fails when mail service not configured", func(t *testing.T) {
		serviceNoMail := NewService(cfg, nil, nil)

		err := serviceNoMail.SendPasswordResetEmail("test@example.com", "https://example.com/reset", time.Hour)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "mail service is not configured")
	})
}

func TestService_SendPasswordResetSuccessEmail(t *testing.T) {
	cfg := testutils.GetTestConfig()
	cfg.App.Name = "Test App"
	service := NewService(cfg, nil, nil)

	t.Run("sends success email successfully", func(t *testing.T) {
		mockMail := &testutils.MockMailService{}
		service.SetMailService(mockMail)

		email := "test@example.com"

		mockMail.On("SendTemplate", "password_reset_success", []string{email}, "Password Reset Successful", map[string]any{
			"Email":   email,
			"AppName": cfg.App.Name,
		}).Return(nil)

		err := service.SendPasswordResetSuccessEmail(email)

		require.NoError(t, err)
		mockMail.AssertExpectations(t)
	})

	t.Run("fails when mail service not configured", func(t *testing.T) {
		serviceNoMail := NewService(cfg, nil, nil)

		err := serviceNoMail.SendPasswordResetSuccessEmail("test@example.com")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "mail service is not configured")
	})
}

func TestService_RequestPasswordReset(t *testing.T) {
	db := testutils.SetupTestDB(t, &PasswordResetToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.PasswordResetEnabled = true
	cfg.Auth.PasswordResetExpiry = time.Hour
	cfg.App.URL = "https://example.com"

	service := NewService(cfg, db, nil)
	mockMail := &testutils.MockMailService{}
	service.SetMailService(mockMail)

	testEmail := "test@example.com"

	t.Run("creates token and sends email", func(t *testing.T) {

		mockMail.On("SendTemplate", "password_reset", []string{testEmail}, "Password Reset Request", mock.MatchedBy(func(data map[string]any) bool {

			return data["Email"] == testEmail &&
				data["AppName"] == cfg.App.Name &&
				data["ExpiryDuration"] == cfg.Auth.PasswordResetExpiry.String() &&
				data["ResetURL"] != nil
		})).Return(nil)

		err := service.RequestPasswordReset(testEmail)

		require.NoError(t, err)
		mockMail.AssertExpectations(t)

		var token PasswordResetToken
		err = db.Where("email = ?", testEmail).First(&token).Error
		require.NoError(t, err)
		assert.Equal(t, testEmail, token.Email)
		assert.False(t, token.Used)
	})

	t.Run("fails when password reset disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.PasswordResetEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		err := serviceDisabled.RequestPasswordReset(testEmail)

		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetDisabled, err)
	})

	t.Run("fails when database not configured", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)
		serviceNoDB.SetMailService(mockMail)

		err := serviceNoDB.RequestPasswordReset(testEmail)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "database is required")
	})

	t.Run("fails when mail service not configured", func(t *testing.T) {
		serviceNoMail := NewService(cfg, db, nil)

		err := serviceNoMail.RequestPasswordReset(testEmail)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to send password reset email")
	})
}

type TestUser struct {
	ID       uint   `gorm:"primaryKey"`
	Email    string `gorm:"uniqueIndex;not null"`
	Password string `gorm:"not null"`
}

func (TestUser) TableName() string {
	return "users"
}

func TestService_ResetPassword(t *testing.T) {
	db := testutils.SetupTestDB(t, &PasswordResetToken{}, &TestUser{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.PasswordResetEnabled = true
	cfg.Auth.PasswordResetExpiry = time.Hour

	service := NewService(cfg, db, nil)
	testEmail := "test@example.com"
	newPassword := "NewPassword123"

	testUser := &TestUser{
		Email:    testEmail,
		Password: "oldPasswordHash",
	}
	err := db.Create(testUser).Error
	require.NoError(t, err)

	t.Run("resets password successfully", func(t *testing.T) {

		token, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		err = service.ResetPassword(token.Token, newPassword)
		require.NoError(t, err)

		var updatedUser TestUser
		err = db.Where("email = ?", testEmail).First(&updatedUser).Error
		require.NoError(t, err)
		assert.NotEqual(t, "oldPasswordHash", updatedUser.Password)

		err = service.VerifyPassword(updatedUser.Password, newPassword)
		assert.NoError(t, err)

		var usedToken PasswordResetToken
		err = db.Where("token = ?", token.Token).First(&usedToken).Error
		require.NoError(t, err)
		assert.True(t, usedToken.Used)
	})

	t.Run("fails for invalid token", func(t *testing.T) {
		err := service.ResetPassword("invalid-token", newPassword)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenInvalid, err)
	})

	t.Run("fails for expired token", func(t *testing.T) {
		expiredToken := &PasswordResetToken{
			Email:     testEmail,
			Token:     "expired-reset-token",
			ExpiresAt: time.Now().Add(-time.Hour),
			Used:      false,
		}
		err := db.Create(expiredToken).Error
		require.NoError(t, err)

		err = service.ResetPassword(expiredToken.Token, newPassword)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenExpired, err)
	})

	t.Run("fails for already used token", func(t *testing.T) {
		token, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		err = service.ResetPassword(token.Token, newPassword)
		require.NoError(t, err)

		err = service.ResetPassword(token.Token, "AnotherPassword123")
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenUsed, err)
	})

	t.Run("fails for invalid password", func(t *testing.T) {
		token, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		err = service.ResetPassword(token.Token, "weak")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password must be at least")
	})

	t.Run("fails when user does not exist", func(t *testing.T) {
		nonExistentEmail := "nonexistent@example.com"

		token, err := service.CreatePasswordResetToken(nonExistentEmail)
		require.NoError(t, err)

		err = service.ResetPassword(token.Token, newPassword)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")

		var userCount int64
		db.Model(&TestUser{}).Where("email = ?", nonExistentEmail).Count(&userCount)
		assert.Equal(t, int64(0), userCount)
	})
}

func TestService_CompletePasswordReset(t *testing.T) {
	db := testutils.SetupTestDB(t, &PasswordResetToken{}, &TestUser{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.PasswordResetEnabled = true
	cfg.Auth.PasswordResetExpiry = time.Hour

	service := NewService(cfg, db, nil)
	mockMail := &testutils.MockMailService{}
	service.SetMailService(mockMail)

	testEmail := "test@example.com"
	newPassword := "NewPassword123"

	testUser := &TestUser{
		Email:    testEmail,
		Password: "oldPasswordHash",
	}
	err := db.Create(testUser).Error
	require.NoError(t, err)

	t.Run("completes password reset and sends confirmation", func(t *testing.T) {

		token, err := service.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		mockMail.On("SendTemplate", "password_reset_success", []string{testEmail}, "Password Reset Successful", map[string]any{
			"Email":   testEmail,
			"AppName": cfg.App.Name,
		}).Return(nil)

		err = service.CompletePasswordReset(token.Token, newPassword)
		require.NoError(t, err)

		var updatedUser TestUser
		err = db.Where("email = ?", testEmail).First(&updatedUser).Error
		require.NoError(t, err)
		err = service.VerifyPassword(updatedUser.Password, newPassword)
		assert.NoError(t, err)

		var usedToken PasswordResetToken
		err = db.Where("token = ?", token.Token).First(&usedToken).Error
		require.NoError(t, err)
		assert.True(t, usedToken.Used)

		mockMail.AssertExpectations(t)
	})

	t.Run("resets password but reports email failure", func(t *testing.T) {

		freshService := NewService(cfg, db, nil)
		freshMock := &testutils.MockMailService{}
		freshService.SetMailService(freshMock)

		token, err := freshService.CreatePasswordResetToken(testEmail)
		require.NoError(t, err)

		freshMock.On("SendTemplate", "password_reset_success", []string{testEmail}, "Password Reset Successful", map[string]any{
			"Email":   testEmail,
			"AppName": cfg.App.Name,
		}).Return(assert.AnError)

		err = freshService.CompletePasswordReset(token.Token, newPassword)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password was reset but failed to send confirmation email")

		var updatedUser TestUser
		err = db.Where("email = ?", testEmail).First(&updatedUser).Error
		require.NoError(t, err)
		err = freshService.VerifyPassword(updatedUser.Password, newPassword)
		assert.NoError(t, err)

		freshMock.AssertExpectations(t)
	})

	t.Run("fails for invalid token", func(t *testing.T) {
		err := service.CompletePasswordReset("invalid-token", newPassword)
		require.Error(t, err)
		assert.Equal(t, ErrPasswordResetTokenInvalid, err)
	})
}
