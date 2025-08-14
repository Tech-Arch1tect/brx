package config

import (
	"log"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/joho/godotenv"
)

type Config struct {
	Server    ServerConfig    `envPrefix:"BRX_SERVER_"`
	Log       LogConfig       `envPrefix:"BRX_LOG_"`
	Templates TemplatesConfig `envPrefix:"BRX_TEMPLATES_"`
	Inertia   InertiaConfig   `envPrefix:"BRX_INERTIA_"`
	Database  DatabaseConfig  `envPrefix:"BRX_DATABASE_"`
	Session   SessionConfig   `envPrefix:"BRX_SESSION_"`
	Auth      AuthConfig      `envPrefix:"BRX_AUTH_"`
}

type ServerConfig struct {
	Port string `env:"PORT" envDefault:"8080"`
	Host string `env:"HOST" envDefault:"localhost"`
}

type LogConfig struct {
	Level string `env:"LEVEL" envDefault:"info"`
}

type TemplatesConfig struct {
	Enabled     bool   `env:"ENABLED" envDefault:"false"`
	Dir         string `env:"DIR" envDefault:"templates"`
	Extension   string `env:"EXTENSION" envDefault:".html"`
	Development bool   `env:"DEVELOPMENT" envDefault:"false"`
}

type InertiaConfig struct {
	Enabled     bool   `env:"ENABLED" envDefault:"false"`
	RootView    string `env:"ROOT_VIEW" envDefault:"app.html"`
	Version     string `env:"VERSION"`
	SSREnabled  bool   `env:"SSR_ENABLED" envDefault:"false"`
	SSRURL      string `env:"SSR_URL" envDefault:"http://127.0.0.1:13714"`
	Development bool   `env:"DEVELOPMENT" envDefault:"false"`
}

type DatabaseConfig struct {
	Driver      string `env:"DRIVER" envDefault:"sqlite"`
	DSN         string `env:"DSN" envDefault:"app.db"`
	AutoMigrate bool   `env:"AUTO_MIGRATE" envDefault:"true"`
}

type SessionConfig struct {
	Enabled  bool          `env:"ENABLED" envDefault:"false"`
	Store    string        `env:"STORE" envDefault:"memory"`
	Name     string        `env:"NAME" envDefault:"brx-session"`
	MaxAge   time.Duration `env:"MAX_AGE" envDefault:"24h"`
	Secure   bool          `env:"SECURE" envDefault:"false"`
	HttpOnly bool          `env:"HTTP_ONLY" envDefault:"true"`
	SameSite string        `env:"SAME_SITE" envDefault:"lax"`
	Path     string        `env:"PATH" envDefault:"/"`
	Domain   string        `env:"DOMAIN" envDefault:""`
}

type AuthConfig struct {
	MinLength      int  `env:"MIN_LENGTH" envDefault:"8"`
	RequireUpper   bool `env:"REQUIRE_UPPER" envDefault:"true"`
	RequireLower   bool `env:"REQUIRE_LOWER" envDefault:"true"`
	RequireNumber  bool `env:"REQUIRE_NUMBER" envDefault:"true"`
	RequireSpecial bool `env:"REQUIRE_SPECIAL" envDefault:"false"`
	BcryptCost     int  `env:"BCRYPT_COST" envDefault:"10"`
}

func LoadConfig(cfg any) error {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found: %v", err)
	}

	return env.Parse(cfg)
}
