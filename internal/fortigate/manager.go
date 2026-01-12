package fortigate

import (
	"sync"

	"github.com/kai/netflowmap/internal/config"
	"github.com/kai/netflowmap/internal/logging"
)

// Manager manages multiple FortiGate caches, one per configured source.
type Manager struct {
	mu     sync.RWMutex
	caches map[string]*Cache // keyed by source ID
}

// NewManager creates a new FortiGate manager.
func NewManager() *Manager {
	return &Manager{
		caches: make(map[string]*Cache),
	}
}

// AddSource adds a FortiGate source and starts its cache.
func (m *Manager) AddSource(sourceID string, cfg *config.FortiGateConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already exists
	if _, exists := m.caches[sourceID]; exists {
		logging.Warning("FortiGate cache already exists", "source", sourceID)
		return nil
	}

	// Create client
	client := NewClient(ClientConfig{
		Host:      cfg.Host,
		Token:     cfg.Token,
		VerifySSL: cfg.ShouldVerifySSL(),
	})

	// Test connection
	if err := client.TestConnection(); err != nil {
		logging.Warning("FortiGate connection test failed", "source", sourceID, "error", err)
		// Continue anyway - might work later
	}

	// Create and start cache
	cache := NewCache(CacheConfig{
		Client:   client,
		SourceID: sourceID,
	})

	if err := cache.Start(); err != nil {
		return err
	}

	m.caches[sourceID] = cache
	logging.Info("FortiGate source added", "source", sourceID, "host", cfg.Host)

	return nil
}

// RemoveSource removes a FortiGate source and stops its cache.
func (m *Manager) RemoveSource(sourceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cache, exists := m.caches[sourceID]
	if !exists {
		return
	}

	cache.Stop()
	delete(m.caches, sourceID)
	logging.Info("FortiGate source removed", "source", sourceID)
}

// LookupIP looks up an IP address in the cache for a specific source.
// Returns the object name and true if found.
func (m *Manager) LookupIP(sourceID, ip string) (string, bool) {
	m.mu.RLock()
	cache, exists := m.caches[sourceID]
	m.mu.RUnlock()

	if !exists {
		return "", false
	}

	return cache.LookupIP(ip)
}

// GetCache returns the cache for a specific source.
func (m *Manager) GetCache(sourceID string) *Cache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.caches[sourceID]
}

// HasSource returns true if a cache exists for the source.
func (m *Manager) HasSource(sourceID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.caches[sourceID]
	return exists
}

// SourceCount returns the number of FortiGate sources.
func (m *Manager) SourceCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.caches)
}

// Close stops all caches and releases resources.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cache := range m.caches {
		cache.Stop()
	}
	m.caches = make(map[string]*Cache)

	logging.Info("FortiGate manager closed")
}

// RefreshAll forces a refresh of all caches.
func (m *Manager) RefreshAll() {
	m.mu.RLock()
	caches := make([]*Cache, 0, len(m.caches))
	for _, cache := range m.caches {
		caches = append(caches, cache)
	}
	m.mu.RUnlock()

	for _, cache := range caches {
		if err := cache.Refresh(); err != nil {
			logging.Warning("cache refresh failed", "source", cache.SourceID(), "error", err)
		}
	}
}

// TotalObjectCount returns the total number of cached address objects across all sources.
func (m *Manager) TotalObjectCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := 0
	for _, cache := range m.caches {
		total += cache.ObjectCount()
	}
	return total
}

// ObjectCount returns the number of cached address objects for a specific source.
func (m *Manager) ObjectCount(sourceID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if cache, ok := m.caches[sourceID]; ok {
		return cache.ObjectCount()
	}
	return 0
}
