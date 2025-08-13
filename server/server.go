package server

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/tech-arch1tect/brx/config"
)

type Server struct {
	fiber *fiber.App
	cfg   *config.Config
}

func New(cfg *config.Config) *Server {
	fiberApp := fiber.New(fiber.Config{
		DisableStartupMessage: false,
	})

	return &Server{
		fiber: fiberApp,
		cfg:   cfg,
	}
}

func (s *Server) Start() {
	addr := fmt.Sprintf("%s:%s", s.cfg.Server.Host, s.cfg.Server.Port)
	log.Printf("Starting brx server on %s", addr)

	if err := s.fiber.Listen(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func (s *Server) Get(path string, handler fiber.Handler) {
	s.fiber.Get(path, handler)
}

func (s *Server) Post(path string, handler fiber.Handler) {
	s.fiber.Post(path, handler)
}

func (s *Server) Put(path string, handler fiber.Handler) {
	s.fiber.Put(path, handler)
}

func (s *Server) Delete(path string, handler fiber.Handler) {
	s.fiber.Delete(path, handler)
}

func (s *Server) Patch(path string, handler fiber.Handler) {
	s.fiber.Patch(path, handler)
}
