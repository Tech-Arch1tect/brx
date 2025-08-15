package mail

import (
	"bytes"
	"fmt"
	htmlTemplate "html/template"
	"path/filepath"
	textTemplate "text/template"

	"github.com/tech-arch1tect/brx/config"
	"github.com/wneessen/go-mail"
)

type Service struct {
	config        *config.MailConfig
	client        *mail.Client
	htmlTemplates *htmlTemplate.Template
	textTemplates *textTemplate.Template
}

type TemplateData map[string]any

func NewService(cfg *config.MailConfig) (*Service, error) {
	if cfg.FromAddress == "" {
		return nil, fmt.Errorf("BRX_MAIL_FROM_ADDRESS is required")
	}

	clientOpts := []mail.Option{
		mail.WithPort(cfg.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
	}

	switch cfg.Encryption {
	case "tls", "starttls":
		clientOpts = append(clientOpts, mail.WithTLSPortPolicy(mail.TLSMandatory))
	case "ssl":
		clientOpts = append(clientOpts, mail.WithSSL())
	case "none":
		clientOpts = append(clientOpts, mail.WithTLSPortPolicy(mail.NoTLS))
	default:

		clientOpts = append(clientOpts, mail.WithTLSPortPolicy(mail.TLSMandatory))
	}

	if cfg.Username != "" {
		clientOpts = append(clientOpts, mail.WithUsername(cfg.Username))
	}
	if cfg.Password != "" {
		clientOpts = append(clientOpts, mail.WithPassword(cfg.Password))
	}

	client, err := mail.NewClient(cfg.Host, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create mail client: %w", err)
	}

	service := &Service{
		config: cfg,
		client: client,
	}

	if err := service.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load mail templates: %w", err)
	}

	return service, nil
}

func (s *Service) loadTemplates() error {
	if s.config.TemplatesDir == "" {
		return nil
	}

	htmlPattern := filepath.Join(s.config.TemplatesDir, "*.html")
	textPattern := filepath.Join(s.config.TemplatesDir, "*.txt")

	var err error
	s.htmlTemplates, err = htmlTemplate.ParseGlob(htmlPattern)
	if err != nil && err.Error() != "template: pattern matches no files: "+htmlPattern {
		return fmt.Errorf("failed to parse HTML templates: %w", err)
	}

	s.textTemplates, err = textTemplate.ParseGlob(textPattern)
	if err != nil && err.Error() != "template: pattern matches no files: "+textPattern {
		return fmt.Errorf("failed to parse text templates: %w", err)
	}

	return nil
}

func (s *Service) NewMessage() *mail.Msg {
	message := mail.NewMsg()

	fromAddr := s.config.FromAddress
	if s.config.FromName != "" {
		fromAddr = fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromAddress)
	}

	if err := message.From(fromAddr); err != nil {
		panic(fmt.Sprintf("failed to set FROM address: %s", err))
	}

	return message
}

func (s *Service) Send(message *mail.Msg) error {
	return s.client.DialAndSend(message)
}

func (s *Service) SendTemplate(templateName string, to []string, subject string, data map[string]any) error {
	message := s.NewMessage()

	if err := message.To(to...); err != nil {
		return fmt.Errorf("failed to set TO addresses: %w", err)
	}

	message.Subject(subject)

	if err := s.renderTemplate(templateName, data, message); err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	return s.Send(message)
}

func (s *Service) renderTemplate(templateName string, data map[string]any, message *mail.Msg) error {
	var hasTemplate bool

	if s.htmlTemplates != nil {
		htmlTemplate := s.htmlTemplates.Lookup(templateName + ".html")
		if htmlTemplate != nil {
			var htmlBuf bytes.Buffer
			if err := htmlTemplate.Execute(&htmlBuf, data); err != nil {
				return fmt.Errorf("failed to execute HTML template: %w", err)
			}
			message.SetBodyString(mail.TypeTextHTML, htmlBuf.String())
			hasTemplate = true
		}
	}

	if s.textTemplates != nil {
		textTemplate := s.textTemplates.Lookup(templateName + ".txt")
		if textTemplate != nil {
			var textBuf bytes.Buffer
			if err := textTemplate.Execute(&textBuf, data); err != nil {
				return fmt.Errorf("failed to execute text template: %w", err)
			}
			if hasTemplate {
				message.AddAlternativeString(mail.TypeTextPlain, textBuf.String())
			} else {
				message.SetBodyString(mail.TypeTextPlain, textBuf.String())
			}
			hasTemplate = true
		}
	}

	if !hasTemplate {
		return fmt.Errorf("template '%s' not found", templateName)
	}

	return nil
}

func (s *Service) SendPlain(to []string, subject, body string) error {
	message := s.NewMessage()

	if err := message.To(to...); err != nil {
		return fmt.Errorf("failed to set TO addresses: %w", err)
	}

	message.Subject(subject)
	message.SetBodyString(mail.TypeTextPlain, body)

	return s.Send(message)
}

func (s *Service) SendHTML(to []string, subject, htmlBody string) error {
	message := s.NewMessage()

	if err := message.To(to...); err != nil {
		return fmt.Errorf("failed to set TO addresses: %w", err)
	}

	message.Subject(subject)
	message.SetBodyString(mail.TypeTextHTML, htmlBody)

	return s.Send(message)
}
