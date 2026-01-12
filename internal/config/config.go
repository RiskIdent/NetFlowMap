// Package config provides configuration structures and loading functionality
// for NetFlowMap.
package config

import "time"

// Config represents the complete application configuration.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Logging LoggingConfig `yaml:"logging"`
	GeoIP   GeoIPConfig   `yaml:"geoip"`
	Flows   FlowConfig    `yaml:"flows"`
	Auth    AuthConfig    `yaml:"auth"`
	Sources []Source      `yaml:"sources"`
}

// AuthConfig contains authentication configuration.
type AuthConfig struct {
	// Enabled indicates whether authentication is enabled (default: false)
	Enabled bool `yaml:"enabled"`
	// SessionSecret is the secret key for signing JWT tokens (required if auth is enabled)
	SessionSecret string `yaml:"session_secret"`
	// SessionDuration is how long a session is valid (default: 12h)
	SessionDuration time.Duration `yaml:"session_duration"`
	// OIDC contains OpenID Connect configuration
	OIDC *OIDCConfig `yaml:"oidc,omitempty"`
	// Local contains local authentication configuration
	Local *LocalAuthConfig `yaml:"local,omitempty"`
	// RateLimit contains rate limiting configuration for login attempts
	RateLimit *RateLimitConfig `yaml:"rate_limit,omitempty"`
}

// RateLimitConfig contains rate limiting configuration.
type RateLimitConfig struct {
	// Enabled indicates whether rate limiting is enabled (default: true when auth is enabled)
	Enabled *bool `yaml:"enabled,omitempty"`
	// MaxAttempts is the maximum number of login attempts per window (default: 5)
	MaxAttempts int `yaml:"max_attempts,omitempty"`
	// WindowDuration is the time window for rate limiting (default: 15m)
	WindowDuration time.Duration `yaml:"window_duration,omitempty"`
	// BlockDuration is how long to block after exceeding max attempts (default: 15m)
	BlockDuration time.Duration `yaml:"block_duration,omitempty"`
}

// OIDCConfig contains OpenID Connect configuration.
type OIDCConfig struct {
	// Enabled indicates whether OIDC is enabled
	Enabled bool `yaml:"enabled"`
	// IssuerURL is the OIDC issuer URL (e.g., https://auth.example.com/realms/main)
	IssuerURL string `yaml:"issuer_url"`
	// ClientID is the OIDC client ID
	ClientID string `yaml:"client_id"`
	// ClientSecret is the OIDC client secret
	ClientSecret string `yaml:"client_secret"`
	// RedirectURL is the callback URL (e.g., http://localhost:8080/auth/callback)
	RedirectURL string `yaml:"redirect_url"`
	// AdminUsers is a list of usernames that are granted admin access
	AdminUsers []string `yaml:"admin_users"`
}

// LocalAuthConfig contains local authentication configuration.
type LocalAuthConfig struct {
	// Enabled indicates whether local authentication is enabled
	Enabled bool `yaml:"enabled"`
	// UsersFile is the path to the users.yml file (default: users.yml)
	UsersFile string `yaml:"users_file"`
}

// ServerConfig contains server-related configuration.
type ServerConfig struct {
	// HTTPPort is the port for the web interface (default: 8080)
	HTTPPort int `yaml:"http_port"`
	// NetFlowPort is the UDP port for receiving NetFlow data (default: 2055)
	NetFlowPort int `yaml:"netflow_port"`
	// UseHTTPS indicates whether the server is behind HTTPS (enables Secure cookie flag)
	UseHTTPS bool `yaml:"use_https,omitempty"`
	// AllowedOrigins is a list of allowed origins for CORS and WebSocket
	// If empty, only same-origin requests are allowed in production
	AllowedOrigins []string `yaml:"allowed_origins,omitempty"`
}

// LoggingConfig contains logging-related configuration.
type LoggingConfig struct {
	// Level is the log level: debug, info, warning, error (default: info)
	Level string `yaml:"level"`
}

// GeoIPConfig contains GeoIP database configuration.
type GeoIPConfig struct {
	// DatabasePath is the directory to store the GeoIP database (default: ./data)
	DatabasePath string `yaml:"database_path"`
	// UpdateIntervalDays is how often to check for database updates (default: 30)
	UpdateIntervalDays int `yaml:"update_interval_days"`
}

// FlowConfig contains flow display configuration.
type FlowConfig struct {
	// DisplayTimeoutSeconds is how long flows remain visible after last update (default: 60)
	DisplayTimeoutSeconds int `yaml:"display_timeout_seconds"`
	// MaxDisplayFlows is the maximum number of flows to send to the browser (default: 100)
	MaxDisplayFlows int `yaml:"max_display_flows"`
}

// Source represents a NetFlow source device.
type Source struct {
	// ID is a unique identifier for this source
	ID string `yaml:"id"`
	// Name is a human-readable name for this source
	Name string `yaml:"name"`
	// SourceIP is the IP address of the device sending NetFlow data
	SourceIP string `yaml:"source_ip"`
	// Latitude is the geographic latitude of this source
	Latitude float64 `yaml:"latitude"`
	// Longitude is the geographic longitude of this source
	Longitude float64 `yaml:"longitude"`
	// SamplingInterval is the NetFlow sampling rate (e.g., 100 means 1:100 sampling)
	// If set, this value is used as fallback when no Options Template is received.
	// Default: 1 (no sampling)
	SamplingInterval int `yaml:"sampling_interval,omitempty"`
	// Filters contains optional traffic filter rules
	Filters *SourceFilters `yaml:"filters,omitempty"`
	// FortiGate contains optional FortiGate API configuration
	FortiGate *FortiGateConfig `yaml:"fortigate,omitempty"`
}

// GetSamplingInterval returns the configured sampling interval, defaulting to 1.
func (s *Source) GetSamplingInterval() int {
	if s.SamplingInterval <= 0 {
		return 1
	}
	return s.SamplingInterval
}

// SourceFilters contains traffic filter rules for a source.
type SourceFilters struct {
	// IncludeNetworks is a list of networks to include (CIDR notation)
	IncludeNetworks []string `yaml:"include_networks,omitempty"`
	// ExcludeNetworks is a list of networks to exclude (CIDR notation)
	ExcludeNetworks []string `yaml:"exclude_networks,omitempty"`
}

// FortiGateConfig contains FortiGate API configuration.
type FortiGateConfig struct {
	// Host is the FortiGate API URL (e.g., https://192.168.1.1)
	Host string `yaml:"host"`
	// Token is the FortiGate API token
	Token string `yaml:"token"`
	// VerifySSL indicates whether to verify SSL certificates (default: true)
	VerifySSL *bool `yaml:"verify_ssl,omitempty"`
}

// Defaults returns a Config with default values.
func Defaults() Config {
	return Config{
		Server: ServerConfig{
			HTTPPort:    8080,
			NetFlowPort: 2055,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
		GeoIP: GeoIPConfig{
			DatabasePath:       "./data",
			UpdateIntervalDays: 30,
		},
		Flows: FlowConfig{
			DisplayTimeoutSeconds: 60,
			MaxDisplayFlows:       100,
		},
		Auth: AuthConfig{
			Enabled:         false,
			SessionDuration: 12 * time.Hour,
		},
		Sources: []Source{},
	}
}

// DisplayTimeout returns the flow display timeout as a time.Duration.
func (c *Config) DisplayTimeout() time.Duration {
	return time.Duration(c.Flows.DisplayTimeoutSeconds) * time.Second
}

// GeoIPUpdateInterval returns the GeoIP update interval as a time.Duration.
func (c *Config) GeoIPUpdateInterval() time.Duration {
	return time.Duration(c.GeoIP.UpdateIntervalDays) * 24 * time.Hour
}

// GetSourceByIP returns the source configuration for a given IP address.
// Returns nil if no source matches.
func (c *Config) GetSourceByIP(ip string) *Source {
	for i := range c.Sources {
		if c.Sources[i].SourceIP == ip {
			return &c.Sources[i]
		}
	}
	return nil
}

// GetSourceByID returns the source configuration for a given ID.
// Returns nil if no source matches.
func (c *Config) GetSourceByID(id string) *Source {
	for i := range c.Sources {
		if c.Sources[i].ID == id {
			return &c.Sources[i]
		}
	}
	return nil
}

// HasFortiGate returns true if this source has FortiGate integration configured.
func (s *Source) HasFortiGate() bool {
	return s.FortiGate != nil && s.FortiGate.Host != "" && s.FortiGate.Token != ""
}

// IsOIDCEnabled returns true if OIDC authentication is enabled and configured.
func (a *AuthConfig) IsOIDCEnabled() bool {
	return a.Enabled && a.OIDC != nil && a.OIDC.Enabled && a.OIDC.IssuerURL != ""
}

// IsLocalEnabled returns true if local authentication is enabled.
func (a *AuthConfig) IsLocalEnabled() bool {
	return a.Enabled && a.Local != nil && a.Local.Enabled
}

// GetUsersFile returns the users file path with default.
func (a *AuthConfig) GetUsersFile() string {
	if a.Local != nil && a.Local.UsersFile != "" {
		return a.Local.UsersFile
	}
	return "users.yml"
}

// GetSessionDuration returns the session duration with default.
func (a *AuthConfig) GetSessionDuration() time.Duration {
	if a.SessionDuration <= 0 {
		return 12 * time.Hour
	}
	return a.SessionDuration
}

// IsRateLimitEnabled returns whether rate limiting is enabled.
func (a *AuthConfig) IsRateLimitEnabled() bool {
	if !a.Enabled {
		return false
	}
	if a.RateLimit == nil || a.RateLimit.Enabled == nil {
		return true // Default: enabled when auth is enabled
	}
	return *a.RateLimit.Enabled
}

// GetRateLimitMaxAttempts returns the max login attempts with default.
func (a *AuthConfig) GetRateLimitMaxAttempts() int {
	if a.RateLimit == nil || a.RateLimit.MaxAttempts <= 0 {
		return 5
	}
	return a.RateLimit.MaxAttempts
}

// GetRateLimitWindowDuration returns the rate limit window duration with default.
func (a *AuthConfig) GetRateLimitWindowDuration() time.Duration {
	if a.RateLimit == nil || a.RateLimit.WindowDuration <= 0 {
		return 15 * time.Minute
	}
	return a.RateLimit.WindowDuration
}

// GetRateLimitBlockDuration returns the block duration with default.
func (a *AuthConfig) GetRateLimitBlockDuration() time.Duration {
	if a.RateLimit == nil || a.RateLimit.BlockDuration <= 0 {
		return 15 * time.Minute
	}
	return a.RateLimit.BlockDuration
}

// ShouldVerifySSL returns whether SSL verification is enabled for FortiGate.
// Defaults to true if not explicitly set.
func (fg *FortiGateConfig) ShouldVerifySSL() bool {
	if fg.VerifySSL == nil {
		return true
	}
	return *fg.VerifySSL
}

