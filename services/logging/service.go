package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Service struct {
	logger *zap.Logger
	sugar  *zap.SugaredLogger
}

type LogLevel string

const (
	Debug LogLevel = "debug"
	Info  LogLevel = "info"
	Warn  LogLevel = "warn"
	Error LogLevel = "error"
)

type Config struct {
	Level      LogLevel `env:"LOG_LEVEL" envDefault:"info"`
	Format     string   `env:"LOG_FORMAT" envDefault:"json"`
	OutputPath string   `env:"LOG_OUTPUT" envDefault:"stdout"`
}

func NewService(config Config) (*Service, error) {
	zapConfig := zap.NewProductionConfig()

	zapConfig.Level = zap.NewAtomicLevelAt(parseLogLevel(config.Level))

	switch config.Format {
	case "console":
		zapConfig.Encoding = "console"
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	case "json":
		zapConfig.Encoding = "json"
	}

	if config.OutputPath != "stdout" {
		zapConfig.OutputPaths = []string{config.OutputPath}
	}

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	return &Service{
		logger: logger,
		sugar:  logger.Sugar(),
	}, nil
}

func (s *Service) Logger() *zap.Logger {
	if s != nil {
		return s.logger
	}
	return nil
}

func (s *Service) Sugar() *zap.SugaredLogger {
	if s != nil {
		return s.sugar
	}
	return nil
}

func (s *Service) Debug(msg string, fields ...zap.Field) {
	if s != nil && s.logger != nil {
		s.logger.Debug(msg, fields...)
	}
}

func (s *Service) Info(msg string, fields ...zap.Field) {
	if s != nil && s.logger != nil {
		s.logger.Info(msg, fields...)
	}
}

func (s *Service) Warn(msg string, fields ...zap.Field) {
	if s != nil && s.logger != nil {
		s.logger.Warn(msg, fields...)
	}
}

func (s *Service) Error(msg string, fields ...zap.Field) {
	if s != nil && s.logger != nil {
		s.logger.Error(msg, fields...)
	}
}

func (s *Service) Fatal(msg string, fields ...zap.Field) {
	if s != nil && s.logger != nil {
		s.logger.Fatal(msg, fields...)
	}
}

func (s *Service) Debugf(template string, args ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Debugf(template, args...)
	}
}

func (s *Service) Infof(template string, args ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Infof(template, args...)
	}
}

func (s *Service) Warnf(template string, args ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Warnf(template, args...)
	}
}

func (s *Service) Errorf(template string, args ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Errorf(template, args...)
	}
}

func (s *Service) Fatalf(template string, args ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Fatalf(template, args...)
	}
}

func (s *Service) Debugw(msg string, keysAndValues ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Debugw(msg, keysAndValues...)
	}
}

func (s *Service) Infow(msg string, keysAndValues ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Infow(msg, keysAndValues...)
	}
}

func (s *Service) Warnw(msg string, keysAndValues ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Warnw(msg, keysAndValues...)
	}
}

func (s *Service) Errorw(msg string, keysAndValues ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Errorw(msg, keysAndValues...)
	}
}

func (s *Service) Fatalw(msg string, keysAndValues ...any) {
	if s != nil && s.sugar != nil {
		s.sugar.Fatalw(msg, keysAndValues...)
	}
}

func (s *Service) Sync() error {
	if s != nil && s.logger != nil {
		return s.logger.Sync()
	}
	return nil
}

func parseLogLevel(level LogLevel) zapcore.Level {
	switch level {
	case Debug:
		return zapcore.DebugLevel
	case Info:
		return zapcore.InfoLevel
	case Warn:
		return zapcore.WarnLevel
	case Error:
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}
