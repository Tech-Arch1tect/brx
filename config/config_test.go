package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_Defaults(t *testing.T) {

	clearEnvVars(t)

	os.Setenv("JWT_SECRET_KEY", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6")
	defer os.Unsetenv("JWT_SECRET_KEY")

	var cfg Config
	err := LoadConfig(&cfg)

	require.NoError(t, err)

	assert.Equal(t, "brx Application", cfg.App.Name)
	assert.Equal(t, "http://localhost:8080", cfg.App.URL)
	assert.Equal(t, "8080", cfg.Server.Port)
	assert.Equal(t, "localhost", cfg.Server.Host)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
	assert.Equal(t, "stdout", cfg.Log.Output)
	assert.Equal(t, "sqlite", cfg.Database.Driver)
	assert.Equal(t, "app.db", cfg.Database.DSN)
	assert.True(t, cfg.Database.AutoMigrate)
	assert.Equal(t, 8, cfg.Auth.MinLength)
	assert.True(t, cfg.Auth.RequireUpper)
	assert.True(t, cfg.Auth.RequireLower)
	assert.True(t, cfg.Auth.RequireNumber)
	assert.False(t, cfg.Auth.RequireSpecial)
	assert.Equal(t, 10, cfg.Auth.BcryptCost)
	assert.Equal(t, time.Duration(15*time.Minute), cfg.JWT.AccessExpiry)
	assert.Equal(t, "HS256", cfg.JWT.Algorithm)
	assert.False(t, cfg.TOTP.Enabled)
	assert.Equal(t, "brx Application", cfg.TOTP.Issuer)
}

func TestLoadConfig_EnvironmentVariables(t *testing.T) {

	clearEnvVars(t)

	os.Setenv("APP_NAME", "Test Application")
	os.Setenv("APP_URL", "https://test.example.com")
	os.Setenv("SERVER_PORT", "9000")
	os.Setenv("SERVER_HOST", "0.0.0.0")
	os.Setenv("DATABASE_DRIVER", "postgres")
	os.Setenv("DATABASE_DSN", "postgres://user:pass@localhost/testdb")
	os.Setenv("AUTH_MIN_LENGTH", "12")
	os.Setenv("AUTH_REQUIRE_SPECIAL", "true")
	os.Setenv("JWT_SECRET_KEY", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6")
	os.Setenv("JWT_ACCESS_EXPIRY", "30m")
	os.Setenv("TOTP_ENABLED", "true")
	defer clearEnvVars(t)

	var cfg Config
	err := LoadConfig(&cfg)

	require.NoError(t, err)

	assert.Equal(t, "Test Application", cfg.App.Name)
	assert.Equal(t, "https://test.example.com", cfg.App.URL)
	assert.Equal(t, "9000", cfg.Server.Port)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, "postgres", cfg.Database.Driver)
	assert.Equal(t, "postgres://user:pass@localhost/testdb", cfg.Database.DSN)
	assert.Equal(t, 12, cfg.Auth.MinLength)
	assert.True(t, cfg.Auth.RequireSpecial)
	assert.Equal(t, "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6", cfg.JWT.SecretKey)
	assert.Equal(t, time.Duration(30*time.Minute), cfg.JWT.AccessExpiry)
	assert.True(t, cfg.TOTP.Enabled)
}

func TestLoadConfig_CommaSeparatedValues(t *testing.T) {
	clearEnvVars(t)

	os.Setenv("SERVER_TRUSTED_PROXIES", "192.168.1.1,10.0.0.1,172.16.0.1")
	os.Setenv("JWT_SECRET_KEY", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6")
	defer clearEnvVars(t)

	var cfg Config
	err := LoadConfig(&cfg)

	require.NoError(t, err)

	expectedProxies := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}
	assert.Equal(t, expectedProxies, cfg.Server.TrustedProxies)
}

func TestValidateJWTConfig(t *testing.T) {
	tests := []struct {
		name      string
		jwtConfig JWTConfig
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid JWT config",
			jwtConfig: JWTConfig{
				SecretKey: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
				Algorithm: "HS256",
			},
			wantErr: false,
		},
		{
			name: "secret key too short",
			jwtConfig: JWTConfig{
				SecretKey: "short",
				Algorithm: "HS256",
			},
			wantErr: true,
			errMsg:  "JWT secret key must be at least 32 characters long",
		},
		{
			name: "weak secret key - contains password",
			jwtConfig: JWTConfig{
				SecretKey: "this-is-a-password-based-secret-key-which-is-weak",
				Algorithm: "HS256",
			},
			wantErr: true,
			errMsg:  "JWT secret key contains weak patterns",
		},
		{
			name: "weak secret key - contains secret",
			jwtConfig: JWTConfig{
				SecretKey: "my-secret-key-for-jwt-tokens-in-production",
				Algorithm: "HS256",
			},
			wantErr: true,
			errMsg:  "JWT secret key contains weak patterns",
		},
		{
			name: "weak secret key - contains test",
			jwtConfig: JWTConfig{
				SecretKey: "test-key-for-jwt-tokens-in-development-mode",
				Algorithm: "HS256",
			},
			wantErr: true,
			errMsg:  "JWT secret key contains weak patterns",
		},
		{
			name: "weak secret key - contains example",
			jwtConfig: JWTConfig{
				SecretKey: "example-key-for-demonstration-purposes-only",
				Algorithm: "HS256",
			},
			wantErr: true,
			errMsg:  "JWT secret key contains weak patterns",
		},
		{
			name: "weak secret key - contains default",
			jwtConfig: JWTConfig{
				SecretKey: "default-secret-key-change-in-production-env",
				Algorithm: "HS256",
			},
			wantErr: true,
			errMsg:  "JWT secret key contains weak patterns",
		},
		{
			name: "weak secret key - contains change",
			jwtConfig: JWTConfig{
				SecretKey: "please-change-this-secret-key-in-production",
				Algorithm: "HS256",
			},
			wantErr: true,
			errMsg:  "JWT secret key contains weak patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJWTConfig(&tt.jwtConfig)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateRefreshTokenConfig(t *testing.T) {
	tests := []struct {
		name               string
		refreshTokenConfig RefreshTokenConfig
		wantErr            bool
		errMsg             string
	}{
		{
			name: "valid refresh token config",
			refreshTokenConfig: RefreshTokenConfig{
				TokenLength:  32,
				RotationMode: "always",
			},
			wantErr: false,
		},
		{
			name: "token length too short",
			refreshTokenConfig: RefreshTokenConfig{
				TokenLength:  8,
				RotationMode: "always",
			},
			wantErr: true,
			errMsg:  "refresh token length must be at least 16 bytes",
		},
		{
			name: "token length too long",
			refreshTokenConfig: RefreshTokenConfig{
				TokenLength:  200,
				RotationMode: "always",
			},
			wantErr: true,
			errMsg:  "refresh token length cannot exceed 128 bytes",
		},
		{
			name: "invalid rotation mode",
			refreshTokenConfig: RefreshTokenConfig{
				TokenLength:  32,
				RotationMode: "invalid",
			},
			wantErr: true,
			errMsg:  "refresh token rotation mode must be: always, conditional, or disabled",
		},
		{
			name: "valid rotation mode - conditional",
			refreshTokenConfig: RefreshTokenConfig{
				TokenLength:  32,
				RotationMode: "conditional",
			},
			wantErr: false,
		},
		{
			name: "valid rotation mode - disabled",
			refreshTokenConfig: RefreshTokenConfig{
				TokenLength:  32,
				RotationMode: "disabled",
			},
			wantErr: false,
		},
		{
			name: "minimum token length",
			refreshTokenConfig: RefreshTokenConfig{
				TokenLength:  16,
				RotationMode: "always",
			},
			wantErr: false,
		},
		{
			name: "maximum token length",
			refreshTokenConfig: RefreshTokenConfig{
				TokenLength:  128,
				RotationMode: "always",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRefreshTokenConfig(&tt.refreshTokenConfig)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLoadConfig_ValidationIntegration(t *testing.T) {
	clearEnvVars(t)

	t.Run("valid configuration passes validation", func(t *testing.T) {
		os.Setenv("JWT_SECRET_KEY", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6")
		os.Setenv("REFRESH_TOKEN_TOKEN_LENGTH", "32")
		os.Setenv("REFRESH_TOKEN_ROTATION_MODE", "always")
		defer clearEnvVars(t)

		var cfg Config
		err := LoadConfig(&cfg)

		require.NoError(t, err)
	})

	t.Run("invalid JWT secret fails validation", func(t *testing.T) {
		os.Setenv("JWT_SECRET_KEY", "short")
		defer clearEnvVars(t)

		var cfg Config
		err := LoadConfig(&cfg)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "JWT secret key must be at least 32 characters long")
	})

	t.Run("invalid refresh token config fails validation", func(t *testing.T) {
		os.Setenv("JWT_SECRET_KEY", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6")
		os.Setenv("REFRESH_TOKEN_TOKEN_LENGTH", "8")
		defer clearEnvVars(t)

		var cfg Config
		err := LoadConfig(&cfg)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token length must be at least 16 bytes")
	})
}

func TestLoadConfig_NonConfigStruct(t *testing.T) {

	type CustomConfig struct {
		Name string `env:"NAME" envDefault:"default"`
	}

	var cfg CustomConfig
	err := LoadConfig(&cfg)

	require.NoError(t, err)
	assert.Equal(t, "default", cfg.Name)
}

func TestCountingMode_Constants(t *testing.T) {

	assert.Equal(t, CountingMode("all"), CountAll)
	assert.Equal(t, CountingMode("failures"), CountFailures)
	assert.Equal(t, CountingMode("success"), CountSuccess)
}

func clearEnvVars(t *testing.T) {
	t.Helper()

	envVars := []string{
		"APP_NAME", "APP_URL",
		"SERVER_PORT", "SERVER_HOST", "SERVER_TRUSTED_PROXIES",
		"LOG_LEVEL", "LOG_FORMAT", "LOG_OUTPUT",
		"DATABASE_DRIVER", "DATABASE_DSN", "DATABASE_AUTO_MIGRATE",
		"AUTH_MIN_LENGTH", "AUTH_REQUIRE_UPPER", "AUTH_REQUIRE_LOWER",
		"AUTH_REQUIRE_NUMBER", "AUTH_REQUIRE_SPECIAL", "AUTH_BCRYPT_COST",
		"JWT_SECRET_KEY", "JWT_ACCESS_EXPIRY", "JWT_ISSUER", "JWT_ALGORITHM",
		"REFRESH_TOKEN_TOKEN_LENGTH", "REFRESH_TOKEN_EXPIRY", "REFRESH_TOKEN_ROTATION_MODE",
		"TOTP_ENABLED", "TOTP_ISSUER",
	}

	for _, envVar := range envVars {
		os.Unsetenv(envVar)
	}

	t.Cleanup(func() {
		for _, envVar := range envVars {
			os.Unsetenv(envVar)
		}
	})
}
