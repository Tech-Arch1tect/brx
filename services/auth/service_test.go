package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/testutils"
	"golang.org/x/crypto/bcrypt"
)

func TestService_ValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		config   config.AuthConfig
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid password",
			password: testutils.TestPasswords.Valid,
			config: config.AuthConfig{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: false,
			},
			wantErr: false,
		},
		{
			name:     "password too short",
			password: testutils.TestPasswords.TooShort,
			config: config.AuthConfig{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: false,
			},
			wantErr: true,
			errMsg:  "password must be at least 8 characters",
		},
		{
			name:     "missing uppercase",
			password: testutils.TestPasswords.NoUpper,
			config: config.AuthConfig{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: false,
			},
			wantErr: true,
			errMsg:  "password must contain at least one uppercase letter",
		},
		{
			name:     "missing lowercase",
			password: testutils.TestPasswords.NoLower,
			config: config.AuthConfig{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: false,
			},
			wantErr: true,
			errMsg:  "password must contain at least one lowercase letter",
		},
		{
			name:     "missing number",
			password: testutils.TestPasswords.NoNumber,
			config: config.AuthConfig{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: false,
			},
			wantErr: true,
			errMsg:  "password must contain at least one number",
		},
		{
			name:     "valid with special character",
			password: testutils.TestPasswords.WithSpecial,
			config: config.AuthConfig{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: true,
			},
			wantErr: false,
		},
		{
			name:     "missing special character",
			password: testutils.TestPasswords.Valid,
			config: config.AuthConfig{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumber:  true,
				RequireSpecial: true,
			},
			wantErr: true,
			errMsg:  "password must contain at least one special character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Auth: tt.config}
			service := NewService(cfg, nil, nil)

			err := service.ValidatePassword(tt.password)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestService_HashPassword(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil, nil)

	t.Run("valid password", func(t *testing.T) {
		password := testutils.TestPasswords.Valid
		hash, err := service.HashPassword(password)

		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.NotEqual(t, password, hash)

		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		assert.NoError(t, err)
	})

	t.Run("invalid password", func(t *testing.T) {
		password := testutils.TestPasswords.TooShort
		hash, err := service.HashPassword(password)

		require.Error(t, err)
		assert.Empty(t, hash)
		assert.Contains(t, err.Error(), "password must be at least")
	})

	t.Run("uses correct bcrypt cost", func(t *testing.T) {
		password := testutils.TestPasswords.Valid
		hash, err := service.HashPassword(password)

		require.NoError(t, err)

		cost, err := bcrypt.Cost([]byte(hash))
		require.NoError(t, err)
		assert.Equal(t, cfg.Auth.BcryptCost, cost)
	})
}

func TestService_VerifyPassword(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil, nil)

	password := testutils.TestPasswords.Valid
	hash, err := service.HashPassword(password)
	require.NoError(t, err)

	t.Run("correct password", func(t *testing.T) {
		err := service.VerifyPassword(hash, password)
		assert.NoError(t, err)
	})

	t.Run("incorrect password", func(t *testing.T) {
		err := service.VerifyPassword(hash, "WrongPassword123")
		require.Error(t, err)
		testutils.AssertErrorType(t, ErrInvalidCredentials, err)
	})

	t.Run("malformed hash", func(t *testing.T) {
		err := service.VerifyPassword("invalid-hash", password)
		require.Error(t, err)
		testutils.AssertErrorType(t, ErrInvalidCredentials, err)
	})
}

func TestService_MustHashPassword(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil, nil)

	t.Run("valid password", func(t *testing.T) {
		password := testutils.TestPasswords.Valid
		hash := service.MustHashPassword(password)

		assert.NotEmpty(t, hash)
		assert.NotEqual(t, password, hash)

		err := service.VerifyPassword(hash, password)
		assert.NoError(t, err)
	})

	t.Run("invalid password panics", func(t *testing.T) {
		password := testutils.TestPasswords.TooShort

		assert.Panics(t, func() {
			service.MustHashPassword(password)
		})
	})
}

func TestNewService(t *testing.T) {
	t.Run("with valid bcrypt cost", func(t *testing.T) {
		cfg := testutils.GetTestConfig()
		cfg.Auth.BcryptCost = 10

		service := NewService(cfg, nil, nil)

		assert.NotNil(t, service)
		assert.Equal(t, 10, service.config.Auth.BcryptCost)
	})

	t.Run("with invalid bcrypt cost - too low", func(t *testing.T) {
		cfg := testutils.GetTestConfig()
		cfg.Auth.BcryptCost = 2

		service := NewService(cfg, nil, nil)

		assert.NotNil(t, service)
		assert.Equal(t, bcrypt.DefaultCost, service.config.Auth.BcryptCost)
	})

	t.Run("with invalid bcrypt cost - too high", func(t *testing.T) {
		cfg := testutils.GetTestConfig()
		cfg.Auth.BcryptCost = 50

		service := NewService(cfg, nil, nil)

		assert.NotNil(t, service)
		assert.Equal(t, bcrypt.DefaultCost, service.config.Auth.BcryptCost)
	})
}

func TestNewServiceWithDefaults(t *testing.T) {
	service := NewServiceWithDefaults()

	assert.NotNil(t, service)
	assert.NotNil(t, service.config)
	assert.Equal(t, "brx Application", service.config.App.Name)
	assert.Equal(t, 8, service.config.Auth.MinLength)
	assert.True(t, service.config.Auth.RequireUpper)
	assert.True(t, service.config.Auth.RequireLower)
	assert.True(t, service.config.Auth.RequireNumber)
	assert.False(t, service.config.Auth.RequireSpecial)
	assert.Equal(t, bcrypt.DefaultCost, service.config.Auth.BcryptCost)
}

func TestService_SetMailService(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil, nil)
	mockMail := &testutils.MockMailService{}

	assert.Nil(t, service.mailService)

	service.SetMailService(mockMail)

	assert.Equal(t, mockMail, service.mailService)
}

func TestService_generateSecureToken(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil, nil)

	t.Run("generates token of correct length", func(t *testing.T) {
		token, err := service.generateSecureToken()

		require.NoError(t, err)
		assert.NotEmpty(t, token)

		expectedLength := cfg.Auth.PasswordResetTokenLength * 2
		assert.Equal(t, expectedLength, len(token))
	})

	t.Run("generates unique tokens", func(t *testing.T) {
		token1, err1 := service.generateSecureToken()
		token2, err2 := service.generateSecureToken()

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, token1, token2)
	})
}
