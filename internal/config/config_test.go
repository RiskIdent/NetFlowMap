package config

import (
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Server.HTTPPort != 8080 {
		t.Errorf("expected HTTPPort 8080, got %d", cfg.Server.HTTPPort)
	}
	if cfg.Server.NetFlowPort != 2055 {
		t.Errorf("expected NetFlowPort 2055, got %d", cfg.Server.NetFlowPort)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected log level 'info', got '%s'", cfg.Logging.Level)
	}
	if cfg.GeoIP.DatabasePath != "./data" {
		t.Errorf("expected database path './data', got '%s'", cfg.GeoIP.DatabasePath)
	}
	if cfg.GeoIP.UpdateIntervalDays != 30 {
		t.Errorf("expected update interval 30 days, got %d", cfg.GeoIP.UpdateIntervalDays)
	}
	if cfg.Flows.DisplayTimeoutSeconds != 60 {
		t.Errorf("expected display timeout 60 seconds, got %d", cfg.Flows.DisplayTimeoutSeconds)
	}
}

func TestParseValidConfig(t *testing.T) {
	yaml := `
server:
  http_port: 9090
  netflow_port: 2056
logging:
  level: debug
geoip:
  database_path: /tmp/geoip
  update_interval_days: 7
flows:
  display_timeout_seconds: 120
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 13.405
`

	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.HTTPPort != 9090 {
		t.Errorf("expected HTTPPort 9090, got %d", cfg.Server.HTTPPort)
	}
	if cfg.Server.NetFlowPort != 2056 {
		t.Errorf("expected NetFlowPort 2056, got %d", cfg.Server.NetFlowPort)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected log level 'debug', got '%s'", cfg.Logging.Level)
	}
	if cfg.GeoIP.DatabasePath != "/tmp/geoip" {
		t.Errorf("expected database path '/tmp/geoip', got '%s'", cfg.GeoIP.DatabasePath)
	}
	if len(cfg.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(cfg.Sources))
	}
	if cfg.Sources[0].ID != "fw-test" {
		t.Errorf("expected source ID 'fw-test', got '%s'", cfg.Sources[0].ID)
	}
}

func TestParseWithFortiGate(t *testing.T) {
	yaml := `
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 13.405
    fortigate:
      host: https://192.168.1.1
      token: test-token
      verify_ssl: false
`

	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(cfg.Sources))
	}

	src := cfg.Sources[0]
	if !src.HasFortiGate() {
		t.Error("expected source to have FortiGate config")
	}
	if src.FortiGate.Host != "https://192.168.1.1" {
		t.Errorf("expected FortiGate host 'https://192.168.1.1', got '%s'", src.FortiGate.Host)
	}
	if src.FortiGate.Token != "test-token" {
		t.Errorf("expected FortiGate token 'test-token', got '%s'", src.FortiGate.Token)
	}
	if src.FortiGate.ShouldVerifySSL() {
		t.Error("expected verify_ssl to be false")
	}
}

func TestParseWithFilters(t *testing.T) {
	yaml := `
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 13.405
    filters:
      include_networks:
        - 0.0.0.0/0
      exclude_networks:
        - 10.0.0.0/8
        - 172.16.0.0/12
`

	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	src := cfg.Sources[0]
	if src.Filters == nil {
		t.Fatal("expected source to have filters")
	}
	if len(src.Filters.IncludeNetworks) != 1 {
		t.Errorf("expected 1 include network, got %d", len(src.Filters.IncludeNetworks))
	}
	if len(src.Filters.ExcludeNetworks) != 2 {
		t.Errorf("expected 2 exclude networks, got %d", len(src.Filters.ExcludeNetworks))
	}
}

func TestParseAppliesDefaults(t *testing.T) {
	yaml := `
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 13.405
`

	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that defaults were applied
	if cfg.Server.HTTPPort != 8080 {
		t.Errorf("expected default HTTPPort 8080, got %d", cfg.Server.HTTPPort)
	}
	if cfg.Server.NetFlowPort != 2055 {
		t.Errorf("expected default NetFlowPort 2055, got %d", cfg.Server.NetFlowPort)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected default log level 'info', got '%s'", cfg.Logging.Level)
	}
}

func TestParseInvalidLogLevel(t *testing.T) {
	yaml := `
logging:
  level: invalid
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 13.405
`

	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
	if !strings.Contains(err.Error(), "invalid log level") {
		t.Errorf("expected error about log level, got: %v", err)
	}
}

func TestParseInvalidSourceIP(t *testing.T) {
	yaml := `
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: not-an-ip
    latitude: 52.52
    longitude: 13.405
`

	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid source IP")
	}
	if !strings.Contains(err.Error(), "invalid source_ip") {
		t.Errorf("expected error about source_ip, got: %v", err)
	}
}

func TestParseDuplicateSourceID(t *testing.T) {
	yaml := `
sources:
  - id: fw-test
    name: Test Firewall 1
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 13.405
  - id: fw-test
    name: Test Firewall 2
    source_ip: 192.168.1.2
    latitude: 48.13
    longitude: 11.58
`

	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for duplicate source ID")
	}
	if !strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("expected error about duplicate id, got: %v", err)
	}
}

func TestParseDuplicateSourceIP(t *testing.T) {
	yaml := `
sources:
  - id: fw-test-1
    name: Test Firewall 1
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 13.405
  - id: fw-test-2
    name: Test Firewall 2
    source_ip: 192.168.1.1
    latitude: 48.13
    longitude: 11.58
`

	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for duplicate source IP")
	}
	if !strings.Contains(err.Error(), "duplicate source_ip") {
		t.Errorf("expected error about duplicate source_ip, got: %v", err)
	}
}

func TestParseInvalidLatitude(t *testing.T) {
	yaml := `
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: 192.168.1.1
    latitude: 100.0
    longitude: 13.405
`

	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid latitude")
	}
	if !strings.Contains(err.Error(), "invalid latitude") {
		t.Errorf("expected error about latitude, got: %v", err)
	}
}

func TestParseInvalidLongitude(t *testing.T) {
	yaml := `
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 200.0
`

	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid longitude")
	}
	if !strings.Contains(err.Error(), "invalid longitude") {
		t.Errorf("expected error about longitude, got: %v", err)
	}
}

func TestParseInvalidCIDR(t *testing.T) {
	yaml := `
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 13.405
    filters:
      exclude_networks:
        - not-a-cidr
`

	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("expected error about CIDR, got: %v", err)
	}
}

func TestParseFortiGateMissingHost(t *testing.T) {
	yaml := `
sources:
  - id: fw-test
    name: Test Firewall
    source_ip: 192.168.1.1
    latitude: 52.52
    longitude: 13.405
    fortigate:
      token: test-token
`

	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing FortiGate host")
	}
	if !strings.Contains(err.Error(), "host is required") {
		t.Errorf("expected error about host, got: %v", err)
	}
}

func TestGetSourceByIP(t *testing.T) {
	cfg := &Config{
		Sources: []Source{
			{ID: "fw-1", SourceIP: "192.168.1.1"},
			{ID: "fw-2", SourceIP: "192.168.1.2"},
		},
	}

	src := cfg.GetSourceByIP("192.168.1.1")
	if src == nil {
		t.Fatal("expected to find source")
	}
	if src.ID != "fw-1" {
		t.Errorf("expected source ID 'fw-1', got '%s'", src.ID)
	}

	src = cfg.GetSourceByIP("192.168.1.99")
	if src != nil {
		t.Error("expected nil for unknown IP")
	}
}

func TestGetSourceByID(t *testing.T) {
	cfg := &Config{
		Sources: []Source{
			{ID: "fw-1", SourceIP: "192.168.1.1"},
			{ID: "fw-2", SourceIP: "192.168.1.2"},
		},
	}

	src := cfg.GetSourceByID("fw-2")
	if src == nil {
		t.Fatal("expected to find source")
	}
	if src.SourceIP != "192.168.1.2" {
		t.Errorf("expected source IP '192.168.1.2', got '%s'", src.SourceIP)
	}

	src = cfg.GetSourceByID("fw-unknown")
	if src != nil {
		t.Error("expected nil for unknown ID")
	}
}

func TestDisplayTimeout(t *testing.T) {
	cfg := &Config{
		Flows: FlowConfig{DisplayTimeoutSeconds: 120},
	}

	timeout := cfg.DisplayTimeout()
	if timeout.Seconds() != 120 {
		t.Errorf("expected 120 seconds, got %f", timeout.Seconds())
	}
}

func TestFortiGateShouldVerifySSLDefault(t *testing.T) {
	fg := &FortiGateConfig{
		Host:  "https://example.com",
		Token: "token",
	}

	if !fg.ShouldVerifySSL() {
		t.Error("expected ShouldVerifySSL to default to true")
	}
}

func TestHasFortiGate(t *testing.T) {
	tests := []struct {
		name     string
		source   Source
		expected bool
	}{
		{
			name:     "no fortigate",
			source:   Source{ID: "test"},
			expected: false,
		},
		{
			name: "empty fortigate",
			source: Source{
				ID:        "test",
				FortiGate: &FortiGateConfig{},
			},
			expected: false,
		},
		{
			name: "fortigate with host only",
			source: Source{
				ID:        "test",
				FortiGate: &FortiGateConfig{Host: "https://example.com"},
			},
			expected: false,
		},
		{
			name: "complete fortigate",
			source: Source{
				ID: "test",
				FortiGate: &FortiGateConfig{
					Host:  "https://example.com",
					Token: "token",
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.source.HasFortiGate(); got != tt.expected {
				t.Errorf("HasFortiGate() = %v, want %v", got, tt.expected)
			}
		})
	}
}


