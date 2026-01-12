// Package geoip provides IP geolocation services using the DB-IP Lite database.
package geoip

import (
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/RiskIdent/NetFlowMap/internal/logging"
	"github.com/oschwald/maxminddb-golang"
)

// Location represents geographic location data for an IP address.
type Location struct {
	// IP is the queried IP address
	IP string
	// City name (empty if unknown)
	City string
	// Country name (empty if unknown)
	Country string
	// CountryCode is the ISO 3166-1 alpha-2 country code
	CountryCode string
	// Latitude coordinate
	Latitude float64
	// Longitude coordinate
	Longitude float64
	// ASN is the Autonomous System Number
	ASN uint32
	// ASOrganization is the name of the organization owning the AS
	ASOrganization string
	// Found indicates whether the IP was found in the database
	Found bool
}

// dbRecord represents the structure of DB-IP MMDB records.
type dbRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		Names   map[string]string `maxminddb:"names"`
		ISOCode string            `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// asnRecord represents the structure of DB-IP ASN MMDB records.
type asnRecord struct {
	AutonomousSystemNumber       uint32 `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// Service provides IP geolocation functionality.
type Service struct {
	mu           sync.RWMutex
	db           *maxminddb.Reader
	asnDB        *maxminddb.Reader
	dbPath       string
	updateDays   int
	lastUpdated  time.Time
	stopChan     chan struct{}
	updateTicker *time.Ticker
}

// Config holds configuration for the GeoIP service.
type Config struct {
	// DatabasePath is the directory to store the database file
	DatabasePath string
	// UpdateIntervalDays is how often to check for updates
	UpdateIntervalDays int
}

// New creates a new GeoIP service.
func New(cfg Config) (*Service, error) {
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = "./data"
	}
	if cfg.UpdateIntervalDays <= 0 {
		cfg.UpdateIntervalDays = 30
	}

	s := &Service{
		dbPath:     cfg.DatabasePath,
		updateDays: cfg.UpdateIntervalDays,
		stopChan:   make(chan struct{}),
	}

	// Ensure database directory exists
	if err := os.MkdirAll(cfg.DatabasePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Try to load existing database or download a new one
	if err := s.ensureDatabase(); err != nil {
		return nil, err
	}

	return s, nil
}

// databaseFile returns the path to the GeoIP database file.
func (s *Service) databaseFile() string {
	return filepath.Join(s.dbPath, "dbip-city-lite.mmdb")
}

// asnDatabaseFile returns the path to the ASN database file.
func (s *Service) asnDatabaseFile() string {
	return filepath.Join(s.dbPath, "dbip-asn-lite.mmdb")
}

// metadataFile returns the path to the metadata file that tracks last update.
func (s *Service) metadataFile() string {
	return filepath.Join(s.dbPath, ".geoip-metadata")
}

// ensureDatabase makes sure we have valid databases, downloading if necessary.
func (s *Service) ensureDatabase() error {
	// GeoIP City database
	dbFile := s.databaseFile()
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		logging.Info("GeoIP database not found, downloading...")
		if err := s.downloadDatabase("city"); err != nil {
			return fmt.Errorf("failed to download GeoIP database: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check database file: %w", err)
	}

	// ASN database
	asnFile := s.asnDatabaseFile()
	if _, err := os.Stat(asnFile); os.IsNotExist(err) {
		logging.Info("ASN database not found, downloading...")
		if err := s.downloadDatabase("asn"); err != nil {
			// ASN is optional, just log warning
			logging.Warning("failed to download ASN database", "error", err)
		}
	}

	// Check if update is needed
	if s.needsUpdate() {
		logging.Info("GeoIP databases are outdated, updating...")
		if err := s.downloadDatabase("city"); err != nil {
			logging.Warning("failed to update GeoIP database, using existing", "error", err)
		}
		if err := s.downloadDatabase("asn"); err != nil {
			logging.Warning("failed to update ASN database", "error", err)
		}
	}

	// Load the databases
	return s.loadDatabase()
}

// needsUpdate checks if the database needs to be updated.
func (s *Service) needsUpdate() bool {
	metaFile := s.metadataFile()

	data, err := os.ReadFile(metaFile)
	if err != nil {
		// No metadata file, assume update needed
		return true
	}

	lastUpdate, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		return true
	}

	s.lastUpdated = lastUpdate
	return time.Since(lastUpdate) > time.Duration(s.updateDays)*24*time.Hour
}

// saveMetadata saves the last update time.
func (s *Service) saveMetadata() error {
	s.lastUpdated = time.Now()
	return os.WriteFile(s.metadataFile(), []byte(s.lastUpdated.Format(time.RFC3339)), 0644)
}

// downloadDatabase downloads the latest DB-IP Lite database.
// dbType can be "city" or "asn".
func (s *Service) downloadDatabase(dbType string) error {
	now := time.Now()
	
	var urlPattern, destFile, logName string
	switch dbType {
	case "asn":
		urlPattern = "https://download.db-ip.com/free/dbip-asn-lite-%d-%02d.mmdb.gz"
		destFile = s.asnDatabaseFile()
		logName = "ASN"
	default: // "city"
		urlPattern = "https://download.db-ip.com/free/dbip-city-lite-%d-%02d.mmdb.gz"
		destFile = s.databaseFile()
		logName = "GeoIP"
	}

	url := fmt.Sprintf(urlPattern, now.Year(), now.Month())
	logging.Info("downloading database", "type", logName, "url", url)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Try previous month if current month's database isn't available yet
		prevMonth := now.AddDate(0, -1, 0)
		url = fmt.Sprintf(urlPattern, prevMonth.Year(), prevMonth.Month())

		logging.Debug("current month not available, trying previous month", "url", url)

		resp.Body.Close()
		resp, err = http.Get(url)
		if err != nil {
			return fmt.Errorf("failed to download: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download failed with status: %s", resp.Status)
		}
	}

	// Decompress gzip
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Write to temporary file first
	tmpFile := destFile + ".tmp"
	out, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	_, err = io.Copy(out, gzReader)
	out.Close()
	if err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to write database: %w", err)
	}

	// Verify the database is valid
	testDb, err := maxminddb.Open(tmpFile)
	if err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("downloaded database is invalid: %w", err)
	}
	testDb.Close()

	// Move to final location
	if err := os.Rename(tmpFile, destFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to move database file: %w", err)
	}

	// Save metadata
	if err := s.saveMetadata(); err != nil {
		logging.Warning("failed to save metadata", "error", err)
	}

	logging.Info("database downloaded successfully", "type", logName)
	return nil
}

// loadDatabase loads the MMDB databases into memory.
func (s *Service) loadDatabase() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close existing databases if open
	if s.db != nil {
		s.db.Close()
	}
	if s.asnDB != nil {
		s.asnDB.Close()
	}

	// Load GeoIP City database
	db, err := maxminddb.Open(s.databaseFile())
	if err != nil {
		return fmt.Errorf("failed to open GeoIP database: %w", err)
	}
	s.db = db
	logging.Info("GeoIP database loaded successfully")

	// Load ASN database (optional)
	asnDB, err := maxminddb.Open(s.asnDatabaseFile())
	if err != nil {
		logging.Warning("ASN database not available, organization names will not be shown", "error", err)
	} else {
		s.asnDB = asnDB
		logging.Info("ASN database loaded successfully")
	}

	return nil
}

// Lookup returns geographic information for an IP address.
func (s *Service) Lookup(ipStr string) (*Location, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	return s.LookupIP(ip)
}

// LookupIP returns geographic information for a net.IP address.
func (s *Service) LookupIP(ip net.IP) (*Location, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("database not loaded")
	}

	var record dbRecord
	err := s.db.Lookup(ip, &record)
	if err != nil {
		return nil, fmt.Errorf("lookup failed: %w", err)
	}

	loc := &Location{
		IP:          ip.String(),
		CountryCode: record.Country.ISOCode,
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
		Found:       record.Location.Latitude != 0 || record.Location.Longitude != 0,
	}

	// Get English names, fall back to first available
	if names := record.City.Names; len(names) > 0 {
		if name, ok := names["en"]; ok {
			loc.City = name
		} else {
			for _, name := range names {
				loc.City = name
				break
			}
		}
	}

	if names := record.Country.Names; len(names) > 0 {
		if name, ok := names["en"]; ok {
			loc.Country = name
		} else {
			for _, name := range names {
				loc.Country = name
				break
			}
		}
	}

	// Lookup ASN information if database is available
	if s.asnDB != nil {
		var asnRecord asnRecord
		if err := s.asnDB.Lookup(ip, &asnRecord); err == nil {
			loc.ASN = asnRecord.AutonomousSystemNumber
			loc.ASOrganization = asnRecord.AutonomousSystemOrganization
		}
	}

	return loc, nil
}

// IsPublicIP checks if an IP address is a public (globally routable) address.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for IPv4
	if ip4 := ip.To4(); ip4 != nil {
		// Private ranges
		private := []struct {
			network *net.IPNet
		}{
			{mustParseCIDR("10.0.0.0/8")},
			{mustParseCIDR("172.16.0.0/12")},
			{mustParseCIDR("192.168.0.0/16")},
			{mustParseCIDR("127.0.0.0/8")},     // Loopback
			{mustParseCIDR("169.254.0.0/16")},  // Link-local
			{mustParseCIDR("224.0.0.0/4")},     // Multicast
			{mustParseCIDR("240.0.0.0/4")},     // Reserved
			{mustParseCIDR("0.0.0.0/8")},       // Current network
			{mustParseCIDR("100.64.0.0/10")},   // Shared address space (CGNAT)
			{mustParseCIDR("192.0.0.0/24")},    // IETF Protocol Assignments
			{mustParseCIDR("192.0.2.0/24")},    // TEST-NET-1
			{mustParseCIDR("198.51.100.0/24")}, // TEST-NET-2
			{mustParseCIDR("203.0.113.0/24")},  // TEST-NET-3
			{mustParseCIDR("192.88.99.0/24")},  // 6to4 Relay Anycast
			{mustParseCIDR("198.18.0.0/15")},   // Benchmarking
		}

		for _, p := range private {
			if p.network.Contains(ip4) {
				return false
			}
		}
		return true
	}

	// Check for IPv6
	if ip6 := ip.To16(); ip6 != nil {
		private := []struct {
			network *net.IPNet
		}{
			{mustParseCIDR("::1/128")},        // Loopback
			{mustParseCIDR("::/128")},         // Unspecified
			{mustParseCIDR("fc00::/7")},       // Unique local
			{mustParseCIDR("fe80::/10")},      // Link-local
			{mustParseCIDR("ff00::/8")},       // Multicast
			{mustParseCIDR("2001:db8::/32")},  // Documentation
			{mustParseCIDR("2001:10::/28")},   // ORCHID
			{mustParseCIDR("2002::/16")},      // 6to4
			{mustParseCIDR("::ffff:0:0/96")},  // IPv4-mapped (check the IPv4 part separately)
			{mustParseCIDR("64:ff9b::/96")},   // IPv4/IPv6 translation
			{mustParseCIDR("100::/64")},       // Discard prefix
			{mustParseCIDR("2001::/32")},      // Teredo
		}

		for _, p := range private {
			if p.network.Contains(ip6) {
				return false
			}
		}
		return true
	}

	return false
}

func mustParseCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR: %s", s))
	}
	return network
}

// StartAutoUpdate starts a background goroutine that periodically checks for updates.
func (s *Service) StartAutoUpdate() {
	interval := time.Duration(s.updateDays) * 24 * time.Hour
	s.updateTicker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-s.updateTicker.C:
				logging.Info("checking for GeoIP database updates")
				if err := s.downloadDatabase("city"); err != nil {
					logging.Warning("failed to update GeoIP database", "error", err)
				}
				if err := s.downloadDatabase("asn"); err != nil {
					logging.Warning("failed to update ASN database", "error", err)
				}
				if err := s.loadDatabase(); err != nil {
					logging.Error("failed to reload databases", "error", err)
				}
			case <-s.stopChan:
				return
			}
		}
	}()

	logging.Info("GeoIP auto-update started", "interval_days", s.updateDays)
}

// Close closes the GeoIP service and releases resources.
func (s *Service) Close() error {
	// Stop auto-update
	if s.updateTicker != nil {
		s.updateTicker.Stop()
	}
	close(s.stopChan)

	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	if s.asnDB != nil {
		if asnErr := s.asnDB.Close(); asnErr != nil && err == nil {
			err = asnErr
		}
	}
	return err
}

// LastUpdated returns when the database was last updated.
func (s *Service) LastUpdated() time.Time {
	return s.lastUpdated
}

// IsLoaded returns true if the database is loaded and ready.
func (s *Service) IsLoaded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db != nil
}

