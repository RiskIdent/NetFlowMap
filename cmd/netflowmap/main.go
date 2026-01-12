package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/RiskIdent/NetFlowMap/internal/auth"
	"github.com/RiskIdent/NetFlowMap/internal/config"
	"github.com/RiskIdent/NetFlowMap/internal/flowstore"
	"github.com/RiskIdent/NetFlowMap/internal/fortigate"
	"github.com/RiskIdent/NetFlowMap/internal/geoip"
	"github.com/RiskIdent/NetFlowMap/internal/logging"
	"github.com/RiskIdent/NetFlowMap/internal/netflow"
	"github.com/RiskIdent/NetFlowMap/internal/web"
	"golang.org/x/term"
)

var (
	// version is set via ldflags at build time: -ldflags="-X main.version=1.0.12"
	version    = "dev"
	configPath string
)

func main() {
	// Parse command line flags
	flag.StringVar(&configPath, "config", "config.yml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	hashPassword := flag.Bool("hash-password", false, "Generate a password hash for users.yml")
	healthCheck := flag.Bool("healthcheck", false, "Run health check and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("NetFlowMap v%s\n", version)
		os.Exit(0)
	}

	// Handle healthcheck command (for Docker HEALTHCHECK)
	if *healthCheck {
		runHealthCheck()
		return
	}

	// Handle hash-password command
	if *hashPassword {
		runHashPassword()
		return
	}

	// Banner
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║   NetFlowMap - Network Flow Visualization ║")
	fmt.Printf("║   Version %-32s ║\n", version)
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()

	// Set version for health endpoint
	web.Version = version

	// Load configuration
	logging.Info("loading configuration", "path", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		logging.Error("failed to load configuration", "error", err)
		fmt.Printf("\nError: %v\n", err)
		fmt.Printf("\nMake sure you have a config.yml file. You can copy the example:\n")
		fmt.Printf("  cp configs/config.example.yml config.yml\n\n")
		os.Exit(1)
	}

	// Setup logging
	logging.SetupFromConfig(cfg.Logging.Level)
	logging.Info("logging initialized", "level", cfg.Logging.Level)

	// Initialize GeoIP service
	logging.Info("initializing GeoIP service")
	geoIPService, err := geoip.New(geoip.Config{
		DatabasePath:       cfg.GeoIP.DatabasePath,
		UpdateIntervalDays: cfg.GeoIP.UpdateIntervalDays,
	})
	if err != nil {
		logging.Error("failed to initialize GeoIP service", "error", err)
		os.Exit(1)
	}
	defer geoIPService.Close()
	geoIPService.StartAutoUpdate()

	// Initialize flow store
	logging.Info("initializing flow store")
	store := flowstore.New(flowstore.Config{
		DisplayTimeout: cfg.DisplayTimeout(),
		GeoIP:          geoIPService,
	})
	defer store.Close()

	// Register sources
	for _, src := range cfg.Sources {
		store.RegisterSource(flowstore.SourceInfo{
			ID:        src.ID,
			Name:      src.Name,
			Latitude:  src.Latitude,
			Longitude: src.Longitude,
		})
	}

	// Initialize FortiGate manager
	fgManager := fortigate.NewManager()
	defer fgManager.Close()

	for _, src := range cfg.Sources {
		if src.HasFortiGate() {
			if err := fgManager.AddSource(src.ID, src.FortiGate); err != nil {
				logging.Warning("failed to add FortiGate source", "source", src.ID, "error", err)
			}
		}
	}

	// Initialize NetFlow collector
	logging.Info("initializing NetFlow collector", "port", cfg.Server.NetFlowPort)
	collector := netflow.NewCollector(netflow.CollectorConfig{
		Port: cfg.Server.NetFlowPort,
		Handler: func(flows []netflow.Flow) {
			// Find source by IP and add flows
			for _, flow := range flows {
				source := cfg.GetSourceByIP(flow.SourceID)
				if source != nil {
					store.AddFlows(source.ID, []netflow.Flow{flow})

					// Try to resolve FortiGate address object
					if fgManager.HasSource(source.ID) {
						// Remote IP depends on direction
						var remoteIP string
						if geoip.IsPublicIP(flow.SrcIP) {
							remoteIP = flow.SrcIP.String()
						} else if geoip.IsPublicIP(flow.DstIP) {
							remoteIP = flow.DstIP.String()
						}

						if remoteIP != "" {
							if name, found := fgManager.LookupIP(source.ID, remoteIP); found {
								store.SetAddressObjectName(source.ID, remoteIP, name)
							}
						}
					}
				} else {
					logging.Debug("received flow from unknown source", "ip", flow.SourceID)
				}
			}
		},
	})

	if err := collector.Start(); err != nil {
		logging.Error("failed to start NetFlow collector", "error", err)
		os.Exit(1)
	}
	defer collector.Stop()

	// Setup static file serving
	staticFS, err := getStaticFS()
	if err != nil {
		logging.Warning("static files not found, web UI may not work", "error", err)
	}

	// Initialize auth service
	authCtx := context.Background()
	authService, err := auth.NewService(authCtx, &cfg.Auth, cfg.Server.UseHTTPS)
	if err != nil {
		logging.Error("failed to initialize auth service", "error", err)
		os.Exit(1)
	}
	defer authService.Close()

	// Initialize web server
	logging.Info("initializing web server", "port", cfg.Server.HTTPPort, "max_display_flows", cfg.Flows.MaxDisplayFlows)
	webServer := web.New(web.Config{
		Port:            cfg.Server.HTTPPort,
		FlowStore:       store,
		FortiGate:       fgManager,
		Collector:       collector,
		AppConfig:       cfg,
		AuthService:     authService,
		StaticFiles:     staticFS,
		MaxDisplayFlows: cfg.Flows.MaxDisplayFlows,
	})

	// Start web server in background
	webServer.StartAsync()

	// Print startup info
	fmt.Println()
	logging.Info("NetFlowMap is ready!")
	logging.Info("web interface available", "url", fmt.Sprintf("http://localhost:%d", cfg.Server.HTTPPort))
	logging.Info("NetFlow collector listening", "port", cfg.Server.NetFlowPort)
	fmt.Println()

	// Start periodic stats logging
	statsCtx, statsCancel := context.WithCancel(context.Background())
	go logPeriodicStats(statsCtx, store, fgManager, collector)

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Stop stats logging
	statsCancel()

	fmt.Println()
	logging.Info("shutting down...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := webServer.Stop(ctx); err != nil {
		logging.Error("error during shutdown", "error", err)
	}

	logging.Info("goodbye!")
}

// getStaticFS returns the filesystem for static files.
// It first tries to use embedded files, then falls back to the local filesystem.
func getStaticFS() (fs.FS, error) {
	// Try local filesystem first (for development)
	webDir := "web"

	// Check if web directory exists
	if _, err := os.Stat(webDir); err == nil {
		logging.Debug("using local web directory", "path", webDir)
		return &localFS{root: webDir}, nil
	}

	// Try relative to executable
	execPath, err := os.Executable()
	if err == nil {
		webDir = filepath.Join(filepath.Dir(execPath), "web")
		if _, err := os.Stat(webDir); err == nil {
			logging.Debug("using web directory relative to executable", "path", webDir)
			return &localFS{root: webDir}, nil
		}
	}

	return nil, fmt.Errorf("web directory not found")
}

// localFS wraps a local directory as an fs.FS
type localFS struct {
	root string
}

func (l *localFS) Open(name string) (fs.File, error) {
	// Handle root path
	if name == "." || name == "/" {
		name = "templates/index.html"
	}

	// Serve index.html for root
	if name == "" {
		name = "templates/index.html"
	}

	// Security: Clean the path and ensure it doesn't escape the root
	cleanName := filepath.Clean(name)

	// Reject paths that try to escape (start with .. or are absolute)
	if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
		return nil, os.ErrNotExist
	}

	fullPath := filepath.Join(l.root, cleanName)

	// Security: Verify the resolved path is still within root
	absRoot, err := filepath.Abs(l.root)
	if err != nil {
		return nil, err
	}
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) && absPath != absRoot {
		return nil, os.ErrNotExist
	}

	// Check if file exists
	info, err := os.Stat(fullPath)
	if err != nil {
		// Try serving index.html for directory or missing files
		if os.IsNotExist(err) {
			indexPath := filepath.Join(l.root, "templates", "index.html")
			if _, indexErr := os.Stat(indexPath); indexErr == nil {
				return os.Open(indexPath)
			}
		}
		return nil, err
	}

	// If it's a directory, serve index.html
	if info.IsDir() {
		indexPath := filepath.Join(l.root, "templates", "index.html")
		return os.Open(indexPath)
	}

	return os.Open(fullPath)
}

// Custom handler for serving static files with proper routing
func init() {
	// Override the default static file handler in the web package
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// This is a fallback, the actual routing is done by chi
	})
}

// logPeriodicStats logs memory and flow statistics periodically.
func logPeriodicStats(ctx context.Context, store *flowstore.Store, fgManager *fortigate.Manager, collector *netflow.Collector) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			logStats(store, fgManager, collector)
		}
	}
}

// logStats logs current memory and flow statistics.
func logStats(store *flowstore.Store, fgManager *fortigate.Manager, collector *netflow.Collector) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Get flow store stats
	storeStats := store.Stats()

	// Get collector stats
	collectorStats := collector.Stats()

	// Get FortiGate stats
	fgSourceCount := 0
	fgObjectCount := 0
	if fgManager != nil {
		fgSourceCount = fgManager.SourceCount()
		fgObjectCount = fgManager.TotalObjectCount()
	}

	logging.Debug("system stats",
		"flows_in_memory", storeStats.FlowCount,
		"flow_sources", storeStats.SourceCount,
		"websocket_clients", storeStats.SubscriberCount,
		"netflow_packets_total", collectorStats.PacketsReceived,
		"netflow_flows_total", collectorStats.FlowsReceived,
		"netflow_templates", collectorStats.TemplateCount,
		"fortigate_sources", fgSourceCount,
		"fortigate_objects", fgObjectCount,
		"memory_alloc_mb", fmt.Sprintf("%.1f", float64(memStats.Alloc)/1024/1024),
		"memory_sys_mb", fmt.Sprintf("%.1f", float64(memStats.Sys)/1024/1024),
		"goroutines", runtime.NumGoroutine(),
	)
}

// runHealthCheck performs a health check against the local server.
func runHealthCheck() {
	resp, err := http.Get("http://localhost:8080/api/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Health check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Health check failed: status %d\n", resp.StatusCode)
		os.Exit(1)
	}

	os.Exit(0)
}

// runHashPassword interactively generates a password hash.
func runHashPassword() {
	fmt.Println("Password Hash Generator")
	fmt.Println("=======================")
	fmt.Println()
	fmt.Print("Enter password: ")

	// Read password from stdin without echoing
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Add newline after hidden input

	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}

	password := string(passwordBytes)

	if password == "" {
		fmt.Println("Error: Password cannot be empty")
		os.Exit(1)
	}

	// Confirm password
	fmt.Print("Confirm password: ")
	confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()

	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}

	if password != string(confirmBytes) {
		fmt.Println("Error: Passwords do not match")
		os.Exit(1)
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Printf("Error generating hash: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("Add this to your users.yml:")
	fmt.Println()
	fmt.Printf("  - username: YOUR_USERNAME\n")
	fmt.Printf("    role: user  # or 'admin'\n")
	fmt.Printf("    password_hash: \"%s\"\n", hash)
	fmt.Println()
}
