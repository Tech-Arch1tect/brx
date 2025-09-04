package mail

import (
	"bytes"
	"fmt"
	htmlTemplate "html/template"
	"path/filepath"
	textTemplate "text/template"
	"time"

	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/wneessen/go-mail"
	"go.uber.org/zap"
)

type Service struct {
	config        *config.MailConfig
	client        *mail.Client
	htmlTemplates *htmlTemplate.Template
	textTemplates *textTemplate.Template
	logger        *logging.Service
}

type TemplateData map[string]any

func NewService(cfg *config.MailConfig, logger *logging.Service) (*Service, error) {
	if logger != nil {
		logger.Info("initializing mail service",
			zap.String("host", cfg.Host),
			zap.Int("port", cfg.Port),
			zap.String("encryption", cfg.Encryption),
			zap.String("from_address", cfg.FromAddress))
	}

	if cfg.FromAddress == "" {
		if logger != nil {
			logger.Error("mail service initialization failed: FROM_ADDRESS is required")
		}
		return nil, fmt.Errorf("MAIL_FROM_ADDRESS is required")
	}

	clientOpts := []mail.Option{
		mail.WithPort(cfg.Port),
	}

	if cfg.Username != "" {
		clientOpts = append(clientOpts, mail.WithSMTPAuth(mail.SMTPAuthPlain))
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

	if logger != nil {
		logger.Debug("creating SMTP client", zap.String("host", cfg.Host))
	}

	client, err := mail.NewClient(cfg.Host, clientOpts...)
	if err != nil {
		if logger != nil {
			logger.Error("failed to create mail client",
				zap.Error(err),
				zap.String("host", cfg.Host),
				zap.Int("port", cfg.Port))
		}
		return nil, fmt.Errorf("failed to create mail client: %w", err)
	}

	service := &Service{
		config: cfg,
		client: client,
		logger: logger,
	}

	if err := service.loadTemplates(); err != nil {
		if logger != nil {
			logger.Error("failed to load mail templates", zap.Error(err))
		}
		return nil, fmt.Errorf("failed to load mail templates: %w", err)
	}

	if logger != nil {
		logger.Info("mail service initialized successfully")
	}
	return service, nil
}

func (s *Service) loadTemplates() error {
	if s.config.TemplatesDir == "" {
		if s.logger != nil {
			s.logger.Debug("no template directory configured, skipping template loading")
		}
		return nil
	}

	if s.logger != nil {
		s.logger.Info("loading mail templates", zap.String("templates_dir", s.config.TemplatesDir))
	}

	htmlPattern := filepath.Join(s.config.TemplatesDir, "*.html")
	textPattern := filepath.Join(s.config.TemplatesDir, "*.txt")

	var err error
	s.htmlTemplates, err = htmlTemplate.ParseGlob(htmlPattern)
	if err != nil && err.Error() != "template: pattern matches no files: "+htmlPattern {
		if s.logger != nil {
			s.logger.Error("failed to parse HTML templates",
				zap.Error(err),
				zap.String("pattern", htmlPattern))
		}
		return fmt.Errorf("failed to parse HTML templates: %w", err)
	}

	s.textTemplates, err = textTemplate.ParseGlob(textPattern)
	if err != nil && err.Error() != "template: pattern matches no files: "+textPattern {
		if s.logger != nil {
			s.logger.Error("failed to parse text templates",
				zap.Error(err),
				zap.String("pattern", textPattern))
		}
		return fmt.Errorf("failed to parse text templates: %w", err)
	}

	var htmlCount, textCount int
	if s.htmlTemplates != nil {
		htmlCount = len(s.htmlTemplates.Templates())
	}
	if s.textTemplates != nil {
		textCount = len(s.textTemplates.Templates())
	}

	if s.logger != nil {
		s.logger.Info("mail templates loaded successfully",
			zap.Int("html_templates", htmlCount),
			zap.Int("text_templates", textCount))
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
	if s.logger != nil {
		s.logger.Debug("sending email message")
	}

	startTime := time.Now()
	err := s.client.DialAndSend(message)
	duration := time.Since(startTime)

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to send email",
				zap.Error(err),
				zap.Duration("attempt_duration", duration))
		}
		return err
	}

	if s.logger != nil {
		s.logger.Info("email sent successfully",
			zap.Duration("send_duration", duration))
	}
	return nil
}

func (s *Service) SendTemplate(templateName string, to []string, subject string, data map[string]any) error {
	if s.logger != nil {
		s.logger.Info("sending template email",
			zap.String("template", templateName),
			zap.Strings("recipients", to),
			zap.String("subject", subject))
	}

	message := s.NewMessage()

	if err := message.To(to...); err != nil {
		if s.logger != nil {
			s.logger.Error("failed to set TO addresses",
				zap.Error(err),
				zap.Strings("recipients", to))
		}
		return fmt.Errorf("failed to set TO addresses: %w", err)
	}

	message.Subject(subject)

	if err := s.renderTemplate(templateName, data, message); err != nil {
		if s.logger != nil {
			s.logger.Error("failed to render template",
				zap.Error(err),
				zap.String("template", templateName))
		}
		return fmt.Errorf("failed to render template: %w", err)
	}

	return s.Send(message)
}

func (s *Service) renderTemplate(templateName string, data map[string]any, message *mail.Msg) error {
	if s.logger != nil {
		s.logger.Debug("rendering email template", zap.String("template", templateName))
	}

	var hasTemplate bool
	var renderedTypes []string

	if s.htmlTemplates != nil {
		htmlTemplate := s.htmlTemplates.Lookup(templateName + ".html")
		if htmlTemplate != nil {
			var htmlBuf bytes.Buffer
			if err := htmlTemplate.Execute(&htmlBuf, data); err != nil {
				if s.logger != nil {
					s.logger.Error("failed to execute HTML template",
						zap.Error(err),
						zap.String("template", templateName+".html"))
				}
				return fmt.Errorf("failed to execute HTML template: %w", err)
			}
			message.SetBodyString(mail.TypeTextHTML, htmlBuf.String())
			hasTemplate = true
			renderedTypes = append(renderedTypes, "html")
		}
	}

	if s.textTemplates != nil {
		textTemplate := s.textTemplates.Lookup(templateName + ".txt")
		if textTemplate != nil {
			var textBuf bytes.Buffer
			if err := textTemplate.Execute(&textBuf, data); err != nil {
				if s.logger != nil {
					s.logger.Error("failed to execute text template",
						zap.Error(err),
						zap.String("template", templateName+".txt"))
				}
				return fmt.Errorf("failed to execute text template: %w", err)
			}
			if hasTemplate {
				message.AddAlternativeString(mail.TypeTextPlain, textBuf.String())
			} else {
				message.SetBodyString(mail.TypeTextPlain, textBuf.String())
			}
			hasTemplate = true
			renderedTypes = append(renderedTypes, "text")
		}
	}

	if !hasTemplate {
		if s.logger != nil {
			s.logger.Warn("template not found", zap.String("template", templateName))
		}
		return fmt.Errorf("template '%s' not found", templateName)
	}

	if s.logger != nil {
		s.logger.Debug("template rendered successfully",
			zap.String("template", templateName),
			zap.Strings("types", renderedTypes))
	}

	return nil
}

func (s *Service) SendPlain(to []string, subject, body string) error {
	if s.logger != nil {
		s.logger.Info("sending plain text email",
			zap.Strings("recipients", to),
			zap.String("subject", subject),
			zap.Int("body_length", len(body)))
	}

	message := s.NewMessage()

	if err := message.To(to...); err != nil {
		if s.logger != nil {
			s.logger.Error("failed to set TO addresses",
				zap.Error(err),
				zap.Strings("recipients", to))
		}
		return fmt.Errorf("failed to set TO addresses: %w", err)
	}

	message.Subject(subject)
	message.SetBodyString(mail.TypeTextPlain, body)

	return s.Send(message)
}

func (s *Service) SendHTML(to []string, subject, htmlBody string) error {
	if s.logger != nil {
		s.logger.Info("sending HTML email",
			zap.Strings("recipients", to),
			zap.String("subject", subject),
			zap.Int("body_length", len(htmlBody)))
	}

	message := s.NewMessage()

	if err := message.To(to...); err != nil {
		if s.logger != nil {
			s.logger.Error("failed to set TO addresses",
				zap.Error(err),
				zap.Strings("recipients", to))
		}
		return fmt.Errorf("failed to set TO addresses: %w", err)
	}

	message.Subject(subject)
	message.SetBodyString(mail.TypeTextHTML, htmlBody)

	return s.Send(message)
}
