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

func LoadConfig(cfg any) error {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found: %v", err)
	}

	return env.Parse(cfg)
}
