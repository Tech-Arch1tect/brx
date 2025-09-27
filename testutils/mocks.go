package testutils

import (
	"time"

	"github.com/stretchr/testify/mock"
)

type MockMailService struct {
	mock.Mock
}

func (m *MockMailService) SendTemplate(templateName string, to []string, subject string, data map[string]any) error {
	args := m.Called(templateName, to, subject, data)
	return args.Error(0)
}

type MockRevocationService struct {
	mock.Mock
}

func (m *MockRevocationService) IsTokenRevoked(jti string) (bool, error) {
	args := m.Called(jti)
	return args.Bool(0), args.Error(1)
}

func (m *MockRevocationService) RevokeToken(jti string, expiresAt time.Time) error {
	args := m.Called(jti, expiresAt)
	return args.Error(0)
}
