package config

import (
	"log"

	"github.com/caarlos0/env/v10"
	"github.com/joho/godotenv"
)

type Config struct {
	Server ServerConfig `envPrefix:"BRX_SERVER_"`
	Log    LogConfig    `envPrefix:"BRX_LOG_"`
}

type ServerConfig struct {
	Port string `env:"PORT" envDefault:"8080"`
	Host string `env:"HOST" envDefault:"localhost"`
}

type LogConfig struct {
	Level string `env:"LEVEL" envDefault:"info"`
}

func LoadConfig(cfg any) error {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found: %v", err)
	}

	return env.Parse(cfg)
}
