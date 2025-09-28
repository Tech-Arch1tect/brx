package logging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewService(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		config := Config{
			Level:      Info,
			Format:     "json",
			OutputPath: "stdout",
		}

		service, err := NewService(config)

		require.NoError(t, err)
		assert.NotNil(t, service)
		assert.NotNil(t, service.logger)
		assert.NotNil(t, service.sugar)
	})

	t.Run("console format", func(t *testing.T) {
		config := Config{
			Level:      Debug,
			Format:     "console",
			OutputPath: "stdout",
		}

		service, err := NewService(config)

		require.NoError(t, err)
		assert.NotNil(t, service)
		assert.NotNil(t, service.logger)
		assert.NotNil(t, service.sugar)
	})

	t.Run("file output", func(t *testing.T) {
		tempDir := t.TempDir()
		logFile := filepath.Join(tempDir, "test.log")

		config := Config{
			Level:      Warn,
			Format:     "json",
			OutputPath: logFile,
		}

		service, err := NewService(config)

		require.NoError(t, err)
		assert.NotNil(t, service)

		service.Info("test log entry")
		service.Sync()

		_, err = os.Stat(logFile)
		assert.NoError(t, err)
	})
}

func TestService_Logger(t *testing.T) {
	t.Run("valid service", func(t *testing.T) {
		config := Config{Level: Info, Format: "json", OutputPath: "stdout"}
		service, err := NewService(config)
		require.NoError(t, err)

		logger := service.Logger()

		assert.NotNil(t, logger)
	})

	t.Run("nil service", func(t *testing.T) {
		var service *Service

		logger := service.Logger()

		assert.Nil(t, logger)
	})
}

func TestService_Sugar(t *testing.T) {
	t.Run("valid service", func(t *testing.T) {
		config := Config{Level: Info, Format: "json", OutputPath: "stdout"}
		service, err := NewService(config)
		require.NoError(t, err)

		sugar := service.Sugar()

		assert.NotNil(t, sugar)
	})

	t.Run("nil service", func(t *testing.T) {
		var service *Service

		sugar := service.Sugar()

		assert.Nil(t, sugar)
	})
}

func TestService_LoggingMethods(t *testing.T) {
	core, recorded := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	service := &Service{
		logger: logger,
		sugar:  logger.Sugar(),
	}

	t.Run("Debug", func(t *testing.T) {
		service.Debug("debug message", zap.String("key", "value"))

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.DebugLevel, logs[0].Level)
		assert.Equal(t, "debug message", logs[0].Message)
	})

	t.Run("Info", func(t *testing.T) {
		service.Info("info message", zap.String("key", "value"))

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.InfoLevel, logs[0].Level)
		assert.Equal(t, "info message", logs[0].Message)
	})

	t.Run("Warn", func(t *testing.T) {
		service.Warn("warn message", zap.String("key", "value"))

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.WarnLevel, logs[0].Level)
		assert.Equal(t, "warn message", logs[0].Message)
	})

	t.Run("Error", func(t *testing.T) {
		service.Error("error message", zap.String("key", "value"))

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.ErrorLevel, logs[0].Level)
		assert.Equal(t, "error message", logs[0].Message)
	})
}

func TestService_FormattedLoggingMethods(t *testing.T) {
	core, recorded := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	service := &Service{
		logger: logger,
		sugar:  logger.Sugar(),
	}

	t.Run("Debugf", func(t *testing.T) {
		service.Debugf("debug %s", "formatted")

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.DebugLevel, logs[0].Level)
		assert.Equal(t, "debug formatted", logs[0].Message)
	})

	t.Run("Infof", func(t *testing.T) {
		service.Infof("info %d", 123)

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.InfoLevel, logs[0].Level)
		assert.Equal(t, "info 123", logs[0].Message)
	})

	t.Run("Warnf", func(t *testing.T) {
		service.Warnf("warn %s", "test")

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.WarnLevel, logs[0].Level)
		assert.Equal(t, "warn test", logs[0].Message)
	})

	t.Run("Errorf", func(t *testing.T) {
		service.Errorf("error %s", "message")

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.ErrorLevel, logs[0].Level)
		assert.Equal(t, "error message", logs[0].Message)
	})
}

func TestService_KeyValueLoggingMethods(t *testing.T) {
	core, recorded := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	service := &Service{
		logger: logger,
		sugar:  logger.Sugar(),
	}

	t.Run("Debugw", func(t *testing.T) {
		service.Debugw("debug message", "key", "value")

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.DebugLevel, logs[0].Level)
		assert.Equal(t, "debug message", logs[0].Message)
	})

	t.Run("Infow", func(t *testing.T) {
		service.Infow("info message", "key", "value")

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.InfoLevel, logs[0].Level)
		assert.Equal(t, "info message", logs[0].Message)
	})

	t.Run("Warnw", func(t *testing.T) {
		service.Warnw("warn message", "key", "value")

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.WarnLevel, logs[0].Level)
		assert.Equal(t, "warn message", logs[0].Message)
	})

	t.Run("Errorw", func(t *testing.T) {
		service.Errorw("error message", "key", "value")

		logs := recorded.TakeAll()
		require.Len(t, logs, 1)
		assert.Equal(t, zapcore.ErrorLevel, logs[0].Level)
		assert.Equal(t, "error message", logs[0].Message)
	})
}

func TestService_NilSafety(t *testing.T) {
	var service *Service

	t.Run("nil service methods don't panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			service.Debug("test")
			service.Info("test")
			service.Warn("test")
			service.Error("test")
			service.Debugf("test %s", "value")
			service.Infof("test %s", "value")
			service.Warnf("test %s", "value")
			service.Errorf("test %s", "value")
			service.Debugw("test", "key", "value")
			service.Infow("test", "key", "value")
			service.Warnw("test", "key", "value")
			service.Errorw("test", "key", "value")
			service.Sync()
		})
	})

	t.Run("service with nil logger", func(t *testing.T) {
		service := &Service{logger: nil, sugar: nil}

		assert.NotPanics(t, func() {
			service.Debug("test")
			service.Info("test")
			service.Warn("test")
			service.Error("test")
			service.Debugf("test %s", "value")
			service.Infof("test %s", "value")
			service.Warnf("test %s", "value")
			service.Errorf("test %s", "value")
			service.Debugw("test", "key", "value")
			service.Infow("test", "key", "value")
			service.Warnw("test", "key", "value")
			service.Errorw("test", "key", "value")
			service.Sync()
		})
	})
}

func TestService_Sync(t *testing.T) {
	t.Run("valid service", func(t *testing.T) {
		config := Config{Level: Info, Format: "json", OutputPath: "stdout"}
		service, err := NewService(config)
		require.NoError(t, err)

		err = service.Sync()

		assert.NoError(t, err)
	})

	t.Run("nil service", func(t *testing.T) {
		var service *Service

		err := service.Sync()

		assert.NoError(t, err)
	})
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    LogLevel
		expected zapcore.Level
	}{
		{Debug, zapcore.DebugLevel},
		{Info, zapcore.InfoLevel},
		{Warn, zapcore.WarnLevel},
		{Error, zapcore.ErrorLevel},
		{LogLevel("unknown"), zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := parseLogLevel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
