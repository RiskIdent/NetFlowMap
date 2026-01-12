package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// envVarPattern matches ${VAR_NAME} or $VAR_NAME patterns
var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}|\$([A-Z_][A-Z0-9_]*)`)

// Load reads and parses a configuration file from the given path.
// It applies default values and validates the configuration.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return Parse(data)
}

// Parse parses configuration from YAML data.
// It applies default values and validates the configuration.
// Supports environment variable substitution with ${VAR_NAME} or $VAR_NAME syntax.
func Parse(data []byte) (*Config, error) {
	// Substitute environment variables before parsing
	data = substituteEnvVars(data)

	// Start with defaults
	cfg := Defaults()

	// Parse YAML
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Apply defaults for zero values
	applyDefaults(&cfg)

	// Validate
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// substituteEnvVars replaces ${VAR_NAME} and $VAR_NAME patterns with environment variable values.
func substituteEnvVars(data []byte) []byte {
	result := envVarPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		// Extract variable name from ${VAR} or $VAR
		matchStr := string(match)
		var varName string
		if strings.HasPrefix(matchStr, "${") {
			varName = matchStr[2 : len(matchStr)-1]
		} else {
			varName = matchStr[1:]
		}

		// Get environment variable value
		if value, exists := os.LookupEnv(varName); exists {
			return []byte(value)
		}

		// Return original if not found (will cause validation error if required)
		return match
	})
	return result
}

// applyDefaults ensures all required fields have sensible default values.
func applyDefaults(cfg *Config) {
	defaults := Defaults()

	if cfg.Server.HTTPPort == 0 {
		cfg.Server.HTTPPort = defaults.Server.HTTPPort
	}
	if cfg.Server.NetFlowPort == 0 {
		cfg.Server.NetFlowPort = defaults.Server.NetFlowPort
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = defaults.Logging.Level
	}
	if cfg.GeoIP.DatabasePath == "" {
		cfg.GeoIP.DatabasePath = defaults.GeoIP.DatabasePath
	}
	if cfg.GeoIP.UpdateIntervalDays == 0 {
		cfg.GeoIP.UpdateIntervalDays = defaults.GeoIP.UpdateIntervalDays
	}
	if cfg.Flows.DisplayTimeoutSeconds == 0 {
		cfg.Flows.DisplayTimeoutSeconds = defaults.Flows.DisplayTimeoutSeconds
	}
	if cfg.Flows.MaxDisplayFlows == 0 {
		cfg.Flows.MaxDisplayFlows = defaults.Flows.MaxDisplayFlows
	}
	if cfg.Auth.SessionDuration == 0 {
		cfg.Auth.SessionDuration = defaults.Auth.SessionDuration
	}
	if cfg.Auth.Local != nil && cfg.Auth.Local.UsersFile == "" {
		cfg.Auth.Local.UsersFile = "users.yml"
	}
}

// validate checks the configuration for errors.
func validate(cfg *Config) error {
	var errors []string

	// Validate server config
	if cfg.Server.HTTPPort < 1 || cfg.Server.HTTPPort > 65535 {
		errors = append(errors, fmt.Sprintf("invalid http_port: %d (must be 1-65535)", cfg.Server.HTTPPort))
	}
	if cfg.Server.NetFlowPort < 1 || cfg.Server.NetFlowPort > 65535 {
		errors = append(errors, fmt.Sprintf("invalid netflow_port: %d (must be 1-65535)", cfg.Server.NetFlowPort))
	}

	// Validate log level
	validLevels := map[string]bool{"debug": true, "info": true, "warning": true, "error": true}
	if !validLevels[strings.ToLower(cfg.Logging.Level)] {
		errors = append(errors, fmt.Sprintf("invalid log level: %s (must be debug, info, warning, or error)", cfg.Logging.Level))
	}

	// Validate GeoIP config
	if cfg.GeoIP.UpdateIntervalDays < 1 {
		errors = append(errors, fmt.Sprintf("invalid update_interval_days: %d (must be >= 1)", cfg.GeoIP.UpdateIntervalDays))
	}

	// Validate flows config
	if cfg.Flows.DisplayTimeoutSeconds < 1 {
		errors = append(errors, fmt.Sprintf("invalid display_timeout_seconds: %d (must be >= 1)", cfg.Flows.DisplayTimeoutSeconds))
	}

	// Validate auth config
	if cfg.Auth.Enabled {
		if cfg.Auth.SessionSecret == "" {
			errors = append(errors, "auth.session_secret is required when auth is enabled")
		} else if len(cfg.Auth.SessionSecret) < 16 {
			errors = append(errors, "auth.session_secret must be at least 16 characters")
		}

		// At least one auth method must be enabled
		oidcEnabled := cfg.Auth.OIDC != nil && cfg.Auth.OIDC.Enabled
		localEnabled := cfg.Auth.Local != nil && cfg.Auth.Local.Enabled

		if !oidcEnabled && !localEnabled {
			errors = append(errors, "auth is enabled but no authentication method (oidc or local) is configured")
		}

		// Validate OIDC config
		if cfg.Auth.OIDC != nil && cfg.Auth.OIDC.Enabled {
			if cfg.Auth.OIDC.IssuerURL == "" {
				errors = append(errors, "auth.oidc.issuer_url is required")
			}
			if cfg.Auth.OIDC.ClientID == "" {
				errors = append(errors, "auth.oidc.client_id is required")
			}
			if cfg.Auth.OIDC.ClientSecret == "" {
				errors = append(errors, "auth.oidc.client_secret is required")
			}
			if cfg.Auth.OIDC.RedirectURL == "" {
				errors = append(errors, "auth.oidc.redirect_url is required")
			}
		}
	}

	// Validate sources
	sourceIDs := make(map[string]bool)
	sourceIPs := make(map[string]bool)

	for i, src := range cfg.Sources {
		prefix := fmt.Sprintf("source[%d]", i)

		if src.ID == "" {
			errors = append(errors, fmt.Sprintf("%s: id is required", prefix))
		} else if sourceIDs[src.ID] {
			errors = append(errors, fmt.Sprintf("%s: duplicate id '%s'", prefix, src.ID))
		} else {
			sourceIDs[src.ID] = true
		}

		if src.Name == "" {
			errors = append(errors, fmt.Sprintf("%s: name is required", prefix))
		}

		if src.SourceIP == "" {
			errors = append(errors, fmt.Sprintf("%s: source_ip is required", prefix))
		} else if net.ParseIP(src.SourceIP) == nil {
			errors = append(errors, fmt.Sprintf("%s: invalid source_ip '%s'", prefix, src.SourceIP))
		} else if sourceIPs[src.SourceIP] {
			errors = append(errors, fmt.Sprintf("%s: duplicate source_ip '%s'", prefix, src.SourceIP))
		} else {
			sourceIPs[src.SourceIP] = true
		}

		if src.Latitude < -90 || src.Latitude > 90 {
			errors = append(errors, fmt.Sprintf("%s: invalid latitude %f (must be -90 to 90)", prefix, src.Latitude))
		}

		if src.Longitude < -180 || src.Longitude > 180 {
			errors = append(errors, fmt.Sprintf("%s: invalid longitude %f (must be -180 to 180)", prefix, src.Longitude))
		}

		// Validate filters
		if src.Filters != nil {
			for j, network := range src.Filters.IncludeNetworks {
				if _, _, err := net.ParseCIDR(network); err != nil {
					errors = append(errors, fmt.Sprintf("%s.filters.include_networks[%d]: invalid CIDR '%s'", prefix, j, network))
				}
			}
			for j, network := range src.Filters.ExcludeNetworks {
				if _, _, err := net.ParseCIDR(network); err != nil {
					errors = append(errors, fmt.Sprintf("%s.filters.exclude_networks[%d]: invalid CIDR '%s'", prefix, j, network))
				}
			}
		}

		// Validate FortiGate config
		if src.FortiGate != nil {
			if src.FortiGate.Host == "" {
				errors = append(errors, fmt.Sprintf("%s.fortigate: host is required", prefix))
			}
			if src.FortiGate.Token == "" {
				errors = append(errors, fmt.Sprintf("%s.fortigate: token is required", prefix))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}

	return nil
}

