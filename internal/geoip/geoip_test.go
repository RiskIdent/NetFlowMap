package geoip

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip       string
		isPublic bool
	}{
		// Private IPv4
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.0.1", false},
		{"192.168.255.255", false},

		// Loopback
		{"127.0.0.1", false},
		{"127.255.255.255", false},

		// Link-local
		{"169.254.0.1", false},
		{"169.254.255.255", false},

		// Multicast
		{"224.0.0.1", false},
		{"239.255.255.255", false},

		// Reserved
		{"240.0.0.1", false},
		{"255.255.255.255", false},

		// CGNAT
		{"100.64.0.1", false},
		{"100.127.255.255", false},

		// Test networks
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},

		// Public IPv4
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"142.250.185.78", true},
		{"151.101.1.140", true},
		{"20.112.52.29", true},

		// Private IPv6
		{"::1", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"fd00::1", false},
		{"ff02::1", false},

		// Public IPv6
		{"2607:f8b0:4004:800::200e", true},
		{"2001:4860:4860::8888", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}

			result := IsPublicIP(ip)
			if result != tt.isPublic {
				t.Errorf("IsPublicIP(%s) = %v, want %v", tt.ip, result, tt.isPublic)
			}
		})
	}
}

func TestIsPublicIPNil(t *testing.T) {
	if IsPublicIP(nil) {
		t.Error("IsPublicIP(nil) should return false")
	}
}

func TestNewServiceCreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "geoip-test")

	// Directory should not exist yet
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("directory should not exist before test")
	}

	// Creating service should fail (no database), but directory should be created
	_, err := New(Config{
		DatabasePath:       dbPath,
		UpdateIntervalDays: 30,
	})

	// Directory should now exist
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("directory should have been created")
	}

	// Service creation will fail because there's no database to download in test
	// That's expected behavior
	_ = err
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{}

	// These will be set by New()
	if cfg.DatabasePath != "" {
		t.Error("DatabasePath should be empty by default")
	}
	if cfg.UpdateIntervalDays != 0 {
		t.Error("UpdateIntervalDays should be 0 by default")
	}
}

func TestLocationStruct(t *testing.T) {
	loc := Location{
		IP:          "8.8.8.8",
		City:        "Mountain View",
		Country:     "United States",
		CountryCode: "US",
		Latitude:    37.4056,
		Longitude:   -122.0775,
		Found:       true,
	}

	if loc.IP != "8.8.8.8" {
		t.Errorf("expected IP 8.8.8.8, got %s", loc.IP)
	}
	if loc.City != "Mountain View" {
		t.Errorf("expected City Mountain View, got %s", loc.City)
	}
	if loc.CountryCode != "US" {
		t.Errorf("expected CountryCode US, got %s", loc.CountryCode)
	}
	if !loc.Found {
		t.Error("expected Found to be true")
	}
}

func TestMustParseCIDR(t *testing.T) {
	// Valid CIDRs should not panic
	validCIDRs := []string{
		"10.0.0.0/8",
		"192.168.0.0/16",
		"0.0.0.0/0",
		"::/0",
		"fe80::/10",
	}

	for _, cidr := range validCIDRs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("mustParseCIDR(%s) panicked: %v", cidr, r)
				}
			}()
			network := mustParseCIDR(cidr)
			if network == nil {
				t.Errorf("mustParseCIDR(%s) returned nil", cidr)
			}
		}()
	}
}

func TestMustParseCIDRPanics(t *testing.T) {
	invalidCIDRs := []string{
		"invalid",
		"256.0.0.0/8",
		"10.0.0.0/33",
	}

	for _, cidr := range invalidCIDRs {
		t.Run(cidr, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("mustParseCIDR(%s) should have panicked", cidr)
				}
			}()
			mustParseCIDR(cidr)
		})
	}
}

// TestServiceWithMockDatabase tests the service with a mock database
// This test is skipped if no database is available
func TestLookupInvalidIP(t *testing.T) {
	tmpDir := t.TempDir()

	s := &Service{
		dbPath:   tmpDir,
		stopChan: make(chan struct{}),
	}

	// Lookup should fail with invalid IP
	_, err := s.Lookup("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestLookupWithoutDatabase(t *testing.T) {
	tmpDir := t.TempDir()

	s := &Service{
		dbPath:   tmpDir,
		db:       nil, // No database loaded
		stopChan: make(chan struct{}),
	}

	// Lookup should fail when database is not loaded
	_, err := s.Lookup("8.8.8.8")
	if err == nil {
		t.Error("expected error when database not loaded")
	}
}

func TestIsLoaded(t *testing.T) {
	s := &Service{
		db:       nil,
		stopChan: make(chan struct{}),
	}

	if s.IsLoaded() {
		t.Error("IsLoaded should return false when db is nil")
	}
}

func TestDatabaseFilePath(t *testing.T) {
	s := &Service{
		dbPath: "/tmp/geoip",
	}

	expected := "/tmp/geoip/dbip-city-lite.mmdb"
	if s.databaseFile() != expected {
		t.Errorf("databaseFile() = %s, want %s", s.databaseFile(), expected)
	}
}

func TestMetadataFilePath(t *testing.T) {
	s := &Service{
		dbPath: "/tmp/geoip",
	}

	expected := "/tmp/geoip/.geoip-metadata"
	if s.metadataFile() != expected {
		t.Errorf("metadataFile() = %s, want %s", s.metadataFile(), expected)
	}
}

func TestNeedsUpdateNoMetadata(t *testing.T) {
	tmpDir := t.TempDir()

	s := &Service{
		dbPath:     tmpDir,
		updateDays: 30,
	}

	// Should need update when no metadata file exists
	if !s.needsUpdate() {
		t.Error("needsUpdate should return true when no metadata file exists")
	}
}

func TestNeedsUpdateWithRecentMetadata(t *testing.T) {
	tmpDir := t.TempDir()

	s := &Service{
		dbPath:     tmpDir,
		updateDays: 30,
	}

	// Create a recent metadata file
	metaFile := s.metadataFile()
	if err := os.WriteFile(metaFile, []byte("2099-01-01T00:00:00Z"), 0644); err != nil {
		t.Fatalf("failed to create metadata file: %v", err)
	}

	// Should not need update (date is in the future)
	if s.needsUpdate() {
		t.Error("needsUpdate should return false for recent metadata")
	}
}

func TestNeedsUpdateWithOldMetadata(t *testing.T) {
	tmpDir := t.TempDir()

	s := &Service{
		dbPath:     tmpDir,
		updateDays: 30,
	}

	// Create an old metadata file
	metaFile := s.metadataFile()
	if err := os.WriteFile(metaFile, []byte("2020-01-01T00:00:00Z"), 0644); err != nil {
		t.Fatalf("failed to create metadata file: %v", err)
	}

	// Should need update (date is old)
	if !s.needsUpdate() {
		t.Error("needsUpdate should return true for old metadata")
	}
}

func TestNeedsUpdateWithInvalidMetadata(t *testing.T) {
	tmpDir := t.TempDir()

	s := &Service{
		dbPath:     tmpDir,
		updateDays: 30,
	}

	// Create an invalid metadata file
	metaFile := s.metadataFile()
	if err := os.WriteFile(metaFile, []byte("invalid-date"), 0644); err != nil {
		t.Fatalf("failed to create metadata file: %v", err)
	}

	// Should need update when metadata is invalid
	if !s.needsUpdate() {
		t.Error("needsUpdate should return true for invalid metadata")
	}
}

func TestSaveMetadata(t *testing.T) {
	tmpDir := t.TempDir()

	s := &Service{
		dbPath: tmpDir,
	}

	// Save metadata
	if err := s.saveMetadata(); err != nil {
		t.Fatalf("saveMetadata failed: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(s.metadataFile()); os.IsNotExist(err) {
		t.Error("metadata file should exist after save")
	}

	// LastUpdated should be set
	if s.lastUpdated.IsZero() {
		t.Error("lastUpdated should be set after save")
	}
}

func TestClose(t *testing.T) {
	s := &Service{
		db:       nil,
		stopChan: make(chan struct{}),
	}

	// Close should not panic even without a database
	if err := s.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}


