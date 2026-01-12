// Package web provides the HTTP server and WebSocket support for NetFlowMap.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/RiskIdent/NetFlowMap/internal/auth"
	"github.com/RiskIdent/NetFlowMap/internal/config"
	"github.com/RiskIdent/NetFlowMap/internal/flowstore"
	"github.com/RiskIdent/NetFlowMap/internal/fortigate"
	"github.com/RiskIdent/NetFlowMap/internal/logging"
	"github.com/RiskIdent/NetFlowMap/internal/netflow"
	"github.com/RiskIdent/NetFlowMap/internal/ratelimit"
)

// Server is the HTTP server for the web interface.
type Server struct {
	router     *chi.Mux
	httpServer *http.Server
	port       int

	flowStore       *flowstore.Store
	fortigate       *fortigate.Manager
	collector       *netflow.Collector
	appConfig       *config.Config
	authService     *auth.Service
	wsHub           *WebSocketHub
	staticFiles     fs.FS
	maxDisplayFlows int
	rateLimiter     *ratelimit.Limiter
	allowedOrigins  map[string]bool
}

// Config holds configuration for the web server.
type Config struct {
	// Port is the HTTP port to listen on
	Port int
	// FlowStore is the flow data store
	FlowStore *flowstore.Store
	// FortiGate is the FortiGate manager (optional)
	FortiGate *fortigate.Manager
	// Collector is the NetFlow collector (for sampling info)
	Collector *netflow.Collector
	// AppConfig is the application configuration (for sampling fallback values)
	AppConfig *config.Config
	// AuthService is the authentication service
	AuthService *auth.Service
	// StaticFiles is the embedded or external static file system
	StaticFiles fs.FS
	// MaxDisplayFlows is the maximum number of flows to send to the browser
	MaxDisplayFlows int
}

// New creates a new web server.
func New(cfg Config) *Server {
	maxFlows := cfg.MaxDisplayFlows
	if maxFlows <= 0 {
		maxFlows = 100 // default
	}

	// Build allowed origins map
	allowedOrigins := make(map[string]bool)
	if cfg.AppConfig != nil {
		for _, origin := range cfg.AppConfig.Server.AllowedOrigins {
			allowedOrigins[strings.ToLower(origin)] = true
		}
	}

	s := &Server{
		port:            cfg.Port,
		flowStore:       cfg.FlowStore,
		fortigate:       cfg.FortiGate,
		collector:       cfg.Collector,
		appConfig:       cfg.AppConfig,
		authService:     cfg.AuthService,
		staticFiles:     cfg.StaticFiles,
		wsHub:           NewWebSocketHub(),
		maxDisplayFlows: maxFlows,
		allowedOrigins:  allowedOrigins,
	}

	// Initialize rate limiter if auth is enabled
	if cfg.AppConfig != nil && cfg.AppConfig.Auth.IsRateLimitEnabled() {
		s.rateLimiter = ratelimit.New(ratelimit.Config{
			MaxAttempts:    cfg.AppConfig.Auth.GetRateLimitMaxAttempts(),
			WindowDuration: cfg.AppConfig.Auth.GetRateLimitWindowDuration(),
			BlockDuration:  cfg.AppConfig.Auth.GetRateLimitBlockDuration(),
		})
		logging.Info("login rate limiting enabled",
			"max_attempts", cfg.AppConfig.Auth.GetRateLimitMaxAttempts(),
			"window", cfg.AppConfig.Auth.GetRateLimitWindowDuration(),
			"block_duration", cfg.AppConfig.Auth.GetRateLimitBlockDuration())
	}

	s.setupRouter()
	return s
}

// setupRouter configures the HTTP router.
func (s *Server) setupRouter() {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Security headers
	r.Use(s.securityHeadersMiddleware)

	// CORS with origin validation
	r.Use(s.corsMiddleware)

	// Auth middleware - adds user to context
	if s.authService != nil {
		r.Use(s.authService.Middleware)
		r.Use(s.sessionRotationMiddleware)
	}

	// Auth routes (no auth required)
	r.Route("/auth", func(r chi.Router) {
		r.Get("/login", s.handleLoginPage)
		r.Post("/login", s.handleLocalLogin)
		r.Post("/logout", s.handleLogout)
		r.Get("/oidc/login", s.handleOIDCLogin)
		r.Get("/callback", s.handleOIDCCallback)
		r.Get("/me", s.handleGetCurrentUser)
		r.Get("/config", s.handleAuthConfig)
	})

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Get("/sources", s.handleGetSources)
		r.Get("/flows", s.handleGetFlows)
		r.Get("/flows/{sourceID}", s.handleGetFlowsBySource)
		r.Get("/stats", s.handleGetStats)
		r.Get("/sampling", s.handleGetSampling)
		r.Get("/health", s.handleHealth)
		r.Get("/health/detailed", s.handleDetailedHealth)
	})

	// WebSocket
	r.Get("/ws", s.handleWebSocket)

	// Static files and index
	if s.staticFiles != nil {
		// Serve static assets
		r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(&subFS{s.staticFiles, "static"}))))
		
		// Serve index.html for root
		r.Get("/", s.handleIndex)
	} else {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html><html><head><title>NetFlowMap</title></head><body>
				<h1>NetFlowMap</h1>
				<p>Static files not found. Please ensure the web/ directory is present.</p>
				<p><a href="/api/health">API Health Check</a></p>
			</body></html>`))
		})
	}

	s.router = r
}

// handleIndex serves the main HTML page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	file, err := s.staticFiles.Open("templates/index.html")
	if err != nil {
		http.Error(w, "Index not found", http.StatusNotFound)
		return
	}
	defer file.Close()
	
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	
	content := make([]byte, stat.Size())
	file.Read(content)
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

// subFS is a helper to serve a subdirectory of an fs.FS
type subFS struct {
	fsys fs.FS
	dir  string
}

func (s *subFS) Open(name string) (fs.File, error) {
	return s.fsys.Open(s.dir + "/" + name)
}

// corsMiddleware returns a CORS middleware with origin validation.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Validate origin
		if origin != "" && s.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isAllowedOrigin checks if the origin is allowed.
func (s *Server) isAllowedOrigin(origin string) bool {
	// If no origins configured, allow same-origin only (no CORS headers)
	if len(s.allowedOrigins) == 0 {
		return false
	}

	// Check against allowed origins
	return s.allowedOrigins[strings.ToLower(origin)]
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start WebSocket hub
	go s.wsHub.Run()

	// Start flow subscription for WebSocket broadcast
	go s.subscribeToFlows()

	logging.Info("web server starting", "port", s.port)

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// StartAsync starts the HTTP server in a goroutine.
func (s *Server) StartAsync() {
	go func() {
		if err := s.Start(); err != nil {
			logging.Error("web server error", "error", err)
		}
	}()
}

// Stop gracefully stops the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	logging.Info("web server stopping")

	// Close WebSocket hub
	s.wsHub.Close()

	// Close rate limiter
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}

	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// subscribeToFlows periodically sends the top N flows to all WebSocket clients.
func (s *Server) subscribeToFlows() {
	if s.flowStore == nil {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.broadcastTopFlows()
		case <-s.wsHub.done:
			return
		}
	}
}

// broadcastTopFlows sends filtered top N flows to each WebSocket client individually.
func (s *Server) broadcastTopFlows() {
	clients := s.wsHub.GetClients()
	if len(clients) == 0 {
		return // No clients connected, skip
	}

	// Get all flows once
	allFlows := s.flowStore.GetAllFlows()

	// Enrich with FortiGate object names
	if s.fortigate != nil {
		for _, flow := range allFlows {
			if flow.AddressObjectName == "" {
				if name, found := s.fortigate.LookupIP(flow.SourceID, flow.RemoteIP); found {
					flow.AddressObjectName = name
				}
			}
		}
	}

	// Send filtered flows to each client
	for _, client := range clients {
		sourceID, direction, textFilter, minTraffic, maxTraffic := client.GetFilters()
		userRole := client.GetUserRole()

		// Filter flows for this client
		filteredFlows := filterFlows(allFlows, direction, textFilter)

		// Debug: Log filter results
		logging.Debug("broadcasting flows to client",
			"text_filter", textFilter,
			"direction_filter", direction,
			"source_filter", sourceID,
			"min_traffic", minTraffic,
			"max_traffic", maxTraffic,
			"flows_before_filter", len(allFlows),
			"flows_after_text_filter", len(filteredFlows))

		// Apply source filter
		if sourceID != "" {
			var sourceFiltered []*flowstore.AggregatedFlow
			for _, flow := range filteredFlows {
				if flow.SourceID == sourceID {
					sourceFiltered = append(sourceFiltered, flow)
				}
			}
			filteredFlows = sourceFiltered
		}

		// Apply traffic threshold filters (min/max) before sorting
		// This filters based on total bytes per remote IP
		if minTraffic > 0 || maxTraffic > 0 {
			filteredFlows = filterFlowsByTraffic(filteredFlows, minTraffic, maxTraffic)
		}

		totalCount := len(filteredFlows)

		// Sort and limit flows
		filteredFlows = sortAndLimitFlows(filteredFlows, s.maxDisplayFlows)

		// Apply role-based filtering (creates copies to avoid modifying original)
		roleFilteredFlows := filterFlowsForRole(filteredFlows, userRole)

		// Debug: Log final flow count
		logging.Debug("flows after all filters",
			"flows_after_source_filter", totalCount,
			"flows_to_send", len(roleFilteredFlows))

		updateData := InitialFlowsMessage{
			Flows:     roleFilteredFlows,
			Total:     totalCount,
			Displayed: len(roleFilteredFlows),
			Limited:   len(roleFilteredFlows) < totalCount,
		}

		msg := WebSocketMessage{
			Type: "update",
			Data: updateData,
		}

		jsonData, err := json.Marshal(msg)
		if err != nil {
			continue
		}

		select {
		case client.send <- jsonData:
		default:
			// Client buffer full, skip
		}
	}
}

// Router returns the HTTP router for testing.
func (s *Server) Router() http.Handler {
	return s.router
}

// Port returns the configured port.
func (s *Server) Port() int {
	return s.port
}

// securityHeadersMiddleware adds security headers to all responses.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Control referrer information
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Prevent XSS in older browsers
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		next.ServeHTTP(w, r)
	})
}

// sessionRotationMiddleware rotates session tokens when they're getting old.
func (s *Server) sessionRotationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authService == nil || !s.authService.IsEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		// Get current session
		claims, err := s.authService.SessionManager().GetSessionFromRequest(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Check if session should be rotated
		if s.authService.SessionManager().ShouldRotate(claims) {
			newToken, err := s.authService.SessionManager().RotateSession(claims)
			if err == nil {
				s.authService.SessionManager().SetSessionCookie(w, newToken)
				logging.Debug("session token rotated", "username", claims.Username)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimiter returns the rate limiter for testing.
func (s *Server) RateLimiter() *ratelimit.Limiter {
	return s.rateLimiter
}

// EmbedStaticFiles is a placeholder for embedded static files.
// In production, this would be populated with //go:embed directives.
var EmbedStaticFiles embed.FS

