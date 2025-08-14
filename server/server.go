package server

import (
	"fmt"
	"log"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
)

type Server struct {
	echo *echo.Echo
	cfg  *config.Config
}

func New(cfg *config.Config) *Server {
	e := echo.New()
	e.HideBanner = false

	return &Server{
		echo: e,
		cfg:  cfg,
	}
}

func (s *Server) Start() {
	addr := fmt.Sprintf("%s:%s", s.cfg.Server.Host, s.cfg.Server.Port)
	log.Printf("Starting brx server on %s", addr)

	if err := s.echo.Start(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func (s *Server) Get(path string, handler echo.HandlerFunc) {
	s.echo.GET(path, handler)
}

func (s *Server) Post(path string, handler echo.HandlerFunc) {
	s.echo.POST(path, handler)
}

func (s *Server) Put(path string, handler echo.HandlerFunc) {
	s.echo.PUT(path, handler)
}

func (s *Server) Delete(path string, handler echo.HandlerFunc) {
	s.echo.DELETE(path, handler)
}

func (s *Server) Patch(path string, handler echo.HandlerFunc) {
	s.echo.PATCH(path, handler)
}

func (s *Server) Group(prefix string) *echo.Group {
	return s.echo.Group(prefix)
}

func (s *Server) SetRenderer(renderer echo.Renderer) {
	s.echo.Renderer = renderer
}

func (s *Server) Echo() *echo.Echo {
	return s.echo
}
