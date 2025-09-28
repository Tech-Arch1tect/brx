package mail

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/wneessen/go-mail"
)

type MockMailClient struct {
	sendFunc func(msg *mail.Msg) error
	calls    []string
}

func (m *MockMailClient) DialAndSend(msg *mail.Msg) error {
	m.calls = append(m.calls, "DialAndSend")
	if m.sendFunc != nil {
		return m.sendFunc(msg)
	}
	return nil
}

func (m *MockMailClient) GetCalls() []string {
	return m.calls
}

func getTestMailConfig() *config.MailConfig {
	return &config.MailConfig{
		Host:         "localhost",
		Port:         587,
		Username:     "test@example.com",
		Password:     "password",
		Encryption:   "tls",
		FromAddress:  "test@example.com",
		FromName:     "Test App",
		TemplatesDir: "",
	}
}

func TestNewService(t *testing.T) {
	t.Run("valid configuration with mock client", func(t *testing.T) {
		cfg := getTestMailConfig()
		mockClient := &MockMailClient{}

		service, err := NewServiceWithClient(cfg, nil, mockClient)

		require.NoError(t, err)
		assert.NotNil(t, service)
		assert.Equal(t, cfg, service.config)
		assert.Equal(t, mockClient, service.client)
	})

	t.Run("with logger", func(t *testing.T) {
		cfg := getTestMailConfig()
		logConfig := logging.Config{Level: logging.Info, Format: "json", OutputPath: "stdout"}
		logger, err := logging.NewService(logConfig)
		require.NoError(t, err)

		mockClient := &MockMailClient{}
		service, err := NewServiceWithClient(cfg, logger, mockClient)

		require.NoError(t, err)
		assert.NotNil(t, service)
		assert.Equal(t, logger, service.logger)
	})

	t.Run("missing from address", func(t *testing.T) {
		cfg := getTestMailConfig()
		cfg.FromAddress = ""
		mockClient := &MockMailClient{}

		service, err := NewServiceWithClient(cfg, nil, mockClient)

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "MAIL_FROM_ADDRESS is required")
	})

	t.Run("with templates directory", func(t *testing.T) {
		tempDir := t.TempDir()
		cfg := getTestMailConfig()
		cfg.TemplatesDir = tempDir
		mockClient := &MockMailClient{}

		service, err := NewServiceWithClient(cfg, nil, mockClient)

		require.NoError(t, err)
		assert.NotNil(t, service)
	})

	t.Run("create real client when none provided", func(t *testing.T) {
		cfg := getTestMailConfig()

		service, err := NewService(cfg, nil)

		require.NoError(t, err)
		assert.NotNil(t, service)
		assert.NotNil(t, service.client)
	})
}

func TestService_loadTemplates(t *testing.T) {
	t.Run("no templates directory", func(t *testing.T) {
		cfg := getTestMailConfig()
		cfg.TemplatesDir = ""
		mockClient := &MockMailClient{}

		service := &Service{
			config: cfg,
			client: mockClient,
			logger: nil,
		}

		err := service.loadTemplates()

		assert.NoError(t, err)
		assert.Nil(t, service.htmlTemplates)
		assert.Nil(t, service.textTemplates)
	})

	t.Run("non-existent templates directory", func(t *testing.T) {
		cfg := getTestMailConfig()
		cfg.TemplatesDir = "/non/existent/path"
		mockClient := &MockMailClient{}

		service := &Service{
			config: cfg,
			client: mockClient,
			logger: nil,
		}

		err := service.loadTemplates()

		assert.NoError(t, err)
		assert.Nil(t, service.htmlTemplates)
		assert.Nil(t, service.textTemplates)
	})

	t.Run("empty templates directory", func(t *testing.T) {
		tempDir := t.TempDir()
		cfg := getTestMailConfig()
		cfg.TemplatesDir = tempDir
		mockClient := &MockMailClient{}

		service := &Service{
			config: cfg,
			client: mockClient,
			logger: nil,
		}

		err := service.loadTemplates()

		assert.NoError(t, err)
		assert.Nil(t, service.htmlTemplates)
		assert.Nil(t, service.textTemplates)
	})

	t.Run("with valid templates", func(t *testing.T) {
		tempDir := t.TempDir()

		htmlTemplate := `<html><body>Hello {{.Name}}!</body></html>`
		textTemplate := `Hello {{.Name}}!`

		err := createTestTemplate(tempDir, "welcome.html", htmlTemplate)
		require.NoError(t, err)

		err = createTestTemplate(tempDir, "welcome.txt", textTemplate)
		require.NoError(t, err)

		cfg := getTestMailConfig()
		cfg.TemplatesDir = tempDir
		mockClient := &MockMailClient{}

		service := &Service{
			config: cfg,
			client: mockClient,
			logger: nil,
		}

		err = service.loadTemplates()

		assert.NoError(t, err)
		assert.NotNil(t, service.htmlTemplates)
		assert.NotNil(t, service.textTemplates)
		assert.True(t, len(service.htmlTemplates.Templates()) > 0)
		assert.True(t, len(service.textTemplates.Templates()) > 0)
	})
}

func TestService_NewMessage(t *testing.T) {
	t.Run("basic message creation", func(t *testing.T) {
		cfg := getTestMailConfig()
		cfg.FromName = ""
		mockClient := &MockMailClient{}

		service := &Service{config: cfg, client: mockClient}

		message := service.NewMessage()

		assert.NotNil(t, message)
	})

	t.Run("message with from name", func(t *testing.T) {
		cfg := getTestMailConfig()
		cfg.FromName = "Test App"
		mockClient := &MockMailClient{}

		service := &Service{config: cfg, client: mockClient}

		message := service.NewMessage()

		assert.NotNil(t, message)
	})
}

func TestService_Send(t *testing.T) {
	t.Run("successful send", func(t *testing.T) {
		cfg := getTestMailConfig()
		mockClient := &MockMailClient{}
		service := &Service{config: cfg, client: mockClient}

		message := service.NewMessage()
		err := service.Send(message)

		assert.NoError(t, err)
		assert.Contains(t, mockClient.GetCalls(), "DialAndSend")
	})

	t.Run("send with error", func(t *testing.T) {
		cfg := getTestMailConfig()
		mockClient := &MockMailClient{
			sendFunc: func(msg *mail.Msg) error {
				return assert.AnError
			},
		}
		service := &Service{config: cfg, client: mockClient}

		message := service.NewMessage()
		err := service.Send(message)

		assert.Error(t, err)
		assert.Contains(t, mockClient.GetCalls(), "DialAndSend")
	})
}

func TestService_SendPlain(t *testing.T) {
	t.Run("valid plain text email", func(t *testing.T) {
		cfg := getTestMailConfig()
		mockClient := &MockMailClient{}
		service := &Service{config: cfg, client: mockClient}

		to := []string{"recipient@example.com"}
		subject := "Test Subject"
		body := "Test body content"

		err := service.SendPlain(to, subject, body)

		assert.NoError(t, err)
		assert.Contains(t, mockClient.GetCalls(), "DialAndSend")
	})

	t.Run("invalid recipient", func(t *testing.T) {
		cfg := getTestMailConfig()
		mockClient := &MockMailClient{}
		service := &Service{config: cfg, client: mockClient}

		to := []string{"invalid-email"}
		subject := "Test Subject"
		body := "Test body content"

		err := service.SendPlain(to, subject, body)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set TO addresses")
	})
}

func TestService_SendHTML(t *testing.T) {
	t.Run("valid HTML email", func(t *testing.T) {
		cfg := getTestMailConfig()
		mockClient := &MockMailClient{}
		service := &Service{config: cfg, client: mockClient}

		to := []string{"recipient@example.com"}
		subject := "Test Subject"
		htmlBody := "<html><body><h1>Test</h1></body></html>"

		err := service.SendHTML(to, subject, htmlBody)

		assert.NoError(t, err)
		assert.Contains(t, mockClient.GetCalls(), "DialAndSend")
	})

	t.Run("invalid recipient", func(t *testing.T) {
		cfg := getTestMailConfig()
		mockClient := &MockMailClient{}
		service := &Service{config: cfg, client: mockClient}

		to := []string{"invalid-email"}
		subject := "Test Subject"
		htmlBody := "<html><body><h1>Test</h1></body></html>"

		err := service.SendHTML(to, subject, htmlBody)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set TO addresses")
	})
}

func TestService_SendTemplate(t *testing.T) {
	t.Run("template not found", func(t *testing.T) {
		cfg := getTestMailConfig()
		tempDir := t.TempDir()
		cfg.TemplatesDir = tempDir
		mockClient := &MockMailClient{}

		service := &Service{config: cfg, client: mockClient}
		err := service.loadTemplates()
		require.NoError(t, err)

		to := []string{"recipient@example.com"}
		subject := "Test Subject"
		data := map[string]any{"Name": "John"}

		err = service.SendTemplate("nonexistent", to, subject, data)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "template 'nonexistent' not found")
	})

	t.Run("successful template send", func(t *testing.T) {
		tempDir := t.TempDir()
		htmlTemplate := `<html><body>Hello {{.Name}}!</body></html>`
		err := createTestTemplate(tempDir, "welcome.html", htmlTemplate)
		require.NoError(t, err)

		cfg := getTestMailConfig()
		cfg.TemplatesDir = tempDir
		mockClient := &MockMailClient{}

		service := &Service{config: cfg, client: mockClient}
		err = service.loadTemplates()
		require.NoError(t, err)

		to := []string{"recipient@example.com"}
		subject := "Test Subject"
		data := map[string]any{"Name": "John"}

		err = service.SendTemplate("welcome", to, subject, data)

		assert.NoError(t, err)
		assert.Contains(t, mockClient.GetCalls(), "DialAndSend")
	})

	t.Run("invalid recipient", func(t *testing.T) {
		tempDir := t.TempDir()
		htmlTemplate := `<html><body>Hello {{.Name}}!</body></html>`
		err := createTestTemplate(tempDir, "welcome.html", htmlTemplate)
		require.NoError(t, err)

		cfg := getTestMailConfig()
		cfg.TemplatesDir = tempDir
		mockClient := &MockMailClient{}

		service := &Service{config: cfg, client: mockClient}
		err = service.loadTemplates()
		require.NoError(t, err)

		to := []string{"invalid-email"}
		subject := "Test Subject"
		data := map[string]any{"Name": "John"}

		err = service.SendTemplate("welcome", to, subject, data)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set TO addresses")
	})
}

func TestService_renderTemplate(t *testing.T) {
	t.Run("HTML template only", func(t *testing.T) {
		tempDir := t.TempDir()
		htmlTemplate := `<html><body>Hello {{.Name}}!</body></html>`
		err := createTestTemplate(tempDir, "welcome.html", htmlTemplate)
		require.NoError(t, err)

		cfg := getTestMailConfig()
		cfg.TemplatesDir = tempDir
		mockClient := &MockMailClient{}

		service := &Service{config: cfg, client: mockClient}
		err = service.loadTemplates()
		require.NoError(t, err)

		message := service.NewMessage()
		data := map[string]any{"Name": "John"}

		err = service.renderTemplate("welcome", data, message)

		assert.NoError(t, err)
	})

	t.Run("text template only", func(t *testing.T) {
		tempDir := t.TempDir()
		textTemplate := `Hello {{.Name}}!`
		err := createTestTemplate(tempDir, "welcome.txt", textTemplate)
		require.NoError(t, err)

		cfg := getTestMailConfig()
		cfg.TemplatesDir = tempDir
		mockClient := &MockMailClient{}

		service := &Service{config: cfg, client: mockClient}
		err = service.loadTemplates()
		require.NoError(t, err)

		message := service.NewMessage()
		data := map[string]any{"Name": "John"}

		err = service.renderTemplate("welcome", data, message)

		assert.NoError(t, err)
	})

	t.Run("both HTML and text templates", func(t *testing.T) {
		tempDir := t.TempDir()
		htmlTemplate := `<html><body>Hello {{.Name}}!</body></html>`
		textTemplate := `Hello {{.Name}}!`

		err := createTestTemplate(tempDir, "welcome.html", htmlTemplate)
		require.NoError(t, err)

		err = createTestTemplate(tempDir, "welcome.txt", textTemplate)
		require.NoError(t, err)

		cfg := getTestMailConfig()
		cfg.TemplatesDir = tempDir
		mockClient := &MockMailClient{}

		service := &Service{config: cfg, client: mockClient}
		err = service.loadTemplates()
		require.NoError(t, err)

		message := service.NewMessage()
		data := map[string]any{"Name": "John"}

		err = service.renderTemplate("welcome", data, message)

		assert.NoError(t, err)
	})

	t.Run("template not found", func(t *testing.T) {
		cfg := getTestMailConfig()
		cfg.TemplatesDir = t.TempDir()
		mockClient := &MockMailClient{}

		service := &Service{config: cfg, client: mockClient}
		err := service.loadTemplates()
		require.NoError(t, err)

		message := service.NewMessage()
		data := map[string]any{"Name": "John"}

		err = service.renderTemplate("nonexistent", data, message)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "template 'nonexistent' not found")
	})
}

func TestGoMailClient(t *testing.T) {
	t.Run("implements MailClient interface", func(t *testing.T) {
		var _ MailClient = &GoMailClient{}
	})
}

func createTestTemplate(dir, filename, content string) error {
	filePath := filepath.Join(dir, filename)
	return os.WriteFile(filePath, []byte(content), 0644)
}
