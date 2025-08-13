package config

import (
	"log"

	"github.com/caarlos0/env/v10"
	"github.com/joho/godotenv"
)

type Config struct {
	Server    ServerConfig    `envPrefix:"BRX_SERVER_"`
	Log       LogConfig       `envPrefix:"BRX_LOG_"`
	Templates TemplatesConfig `envPrefix:"BRX_TEMPLATES_"`
	Inertia   InertiaConfig   `envPrefix:"BRX_INERTIA_"`
	Database  DatabaseConfig  `envPrefix:"BRX_DATABASE_"`
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

func LoadConfig(cfg any) error {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found: %v", err)
	}

	return env.Parse(cfg)
}
