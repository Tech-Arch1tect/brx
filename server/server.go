package server

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"

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

	configureTrustedProxies(e, cfg.Server.TrustedProxies)

	return &Server{
		echo: e,
		cfg:  cfg,
	}
}

func configureTrustedProxies(e *echo.Echo, trustedProxies []string) {

	if len(trustedProxies) == 0 {
		e.IPExtractor = echo.ExtractIPDirect()
		log.Printf("No trusted proxies configured - using direct IP extraction (secure)")
		return
	}

	var trustOptions []echo.TrustOption
	for _, proxy := range trustedProxies {
		if proxy == "" {
			continue
		}

		var network *net.IPNet
		var err error

		if _, network, err = net.ParseCIDR(proxy); err != nil {

			if ip := net.ParseIP(proxy); ip != nil {
				if ip.To4() != nil {
					_, network, _ = net.ParseCIDR(proxy + "/32")
				} else {
					_, network, _ = net.ParseCIDR(proxy + "/128")
				}
			} else {
				log.Printf("WARNING: Invalid trusted proxy '%s' - skipping", proxy)
				continue
			}
		}

		if network != nil {
			trustOptions = append(trustOptions, echo.TrustIPRange(network))
		}
	}

	if len(trustOptions) == 0 {
		e.IPExtractor = echo.ExtractIPDirect()
		log.Printf("No valid trusted proxies - using direct IP extraction")
		return
	}

	e.IPExtractor = echo.ExtractIPFromXFFHeader(trustOptions...)
	log.Printf("Configured trusted proxies: %v", trustedProxies)
}

func (s *Server) Start() {
	addr := fmt.Sprintf("%s:%s", s.cfg.Server.Host, s.cfg.Server.Port)
	log.Printf("Starting brx server on %s", addr)

	if err := s.echo.Start(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func (s *Server) Get(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	s.echo.GET(path, handler, middleware...)
}

func (s *Server) Post(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	s.echo.POST(path, handler, middleware...)
}

func (s *Server) Put(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	s.echo.PUT(path, handler, middleware...)
}

func (s *Server) Delete(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	s.echo.DELETE(path, handler, middleware...)
}

func (s *Server) Patch(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	s.echo.PATCH(path, handler, middleware...)
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

func (s *Server) LogRoutes() {
	routes := s.echo.Routes()
	if len(routes) == 0 {
		log.Printf("No routes registered")
		return
	}

	filteredRoutes := make([]*echo.Route, 0)
	for _, route := range routes {
		if route.Name == "github.com/labstack/echo/v4.init.func1" {
			continue
		}
		filteredRoutes = append(filteredRoutes, route)
	}

	sort.Slice(filteredRoutes, func(i, j int) bool {
		if filteredRoutes[i].Path == filteredRoutes[j].Path {
			return filteredRoutes[i].Method < filteredRoutes[j].Method
		}
		return filteredRoutes[i].Path < filteredRoutes[j].Path
	})

	var output strings.Builder
	output.WriteString("\nRegistered Routes:\n")

	for _, route := range filteredRoutes {
		output.WriteString(fmt.Sprintf("  %-6s %s -> %s\n",
			route.Method,
			route.Path,
			shortenHandlerName(route.Name)))
	}

	output.WriteString("\n")
	log.Print(output.String())
}

func shortenHandlerName(name string) string {
	if slashIndex := strings.Index(name, "/"); slashIndex != -1 {
		name = name[slashIndex+1:]
	}

	if len(name) > 80 {
		parts := []rune(name)
		if len(parts) > 80 {
			return string(parts[:77]) + "..."
		}
	}
	return name
}
