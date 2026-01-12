package fortigate

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/kai/netflowmap/internal/logging"
)

// Cache stores FortiGate address objects with automatic refresh.
type Cache struct {
	mu sync.RWMutex

	// client is the FortiGate API client
	client *Client

	// sourceID identifies which NetFlow source this cache belongs to
	sourceID string

	// objects maps object name to AddressObject
	objects map[string]*AddressObject

	// groups maps group name to AddressGroup
	groups map[string]*AddressGroup

	// refreshInterval is how often to refresh the cache
	refreshInterval time.Duration

	// lastRefresh is when the cache was last refreshed
	lastRefresh time.Time

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// CacheConfig holds configuration for the cache.
type CacheConfig struct {
	// Client is the FortiGate API client
	Client *Client
	// SourceID identifies which NetFlow source this cache belongs to
	SourceID string
	// RefreshInterval is how often to refresh (default: 30 minutes)
	RefreshInterval time.Duration
}

// NewCache creates a new address object cache.
func NewCache(cfg CacheConfig) *Cache {
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 30 * time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := &Cache{
		client:          cfg.Client,
		sourceID:        cfg.SourceID,
		objects:         make(map[string]*AddressObject),
		groups:          make(map[string]*AddressGroup),
		refreshInterval: cfg.RefreshInterval,
		ctx:             ctx,
		cancel:          cancel,
	}

	return c
}

// Start begins the cache refresh loop.
func (c *Cache) Start() error {
	// Initial refresh
	if err := c.Refresh(); err != nil {
		logging.Warning("initial cache refresh failed", "source", c.sourceID, "error", err)
		// Continue anyway, will retry on next interval
	}

	// Start refresh loop
	c.wg.Add(1)
	go c.refreshLoop()

	logging.Info("FortiGate cache started", "source", c.sourceID, "refresh_interval", c.refreshInterval)
	return nil
}

// Stop stops the cache refresh loop.
func (c *Cache) Stop() {
	c.cancel()
	c.wg.Wait()
	logging.Info("FortiGate cache stopped", "source", c.sourceID)
}

// refreshLoop periodically refreshes the cache.
func (c *Cache) refreshLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.Refresh(); err != nil {
				logging.Warning("cache refresh failed", "source", c.sourceID, "error", err)
			}
		}
	}
}

// Refresh fetches the latest data from the FortiGate API.
func (c *Cache) Refresh() error {
	logging.Debug("refreshing FortiGate cache", "source", c.sourceID)

	// Fetch address objects
	objects, err := c.client.GetAddressObjects()
	if err != nil {
		return err
	}

	// Fetch address groups
	groups, err := c.client.GetAddressGroups()
	if err != nil {
		// Log but continue - groups are optional
		logging.Warning("failed to fetch address groups", "source", c.sourceID, "error", err)
		groups = nil
	}

	// Update cache
	c.mu.Lock()
	defer c.mu.Unlock()

	c.objects = make(map[string]*AddressObject, len(objects))
	skipped := 0
	for i := range objects {
		// Skip overly generic objects that would match everything
		if isGenericAddress(&objects[i]) {
			skipped++
			continue
		}
		c.objects[objects[i].Name] = &objects[i]
	}

	if skipped > 0 {
		logging.Debug("skipped generic address objects", "source", c.sourceID, "count", skipped)
	}

	if groups != nil {
		c.groups = make(map[string]*AddressGroup, len(groups))
		for i := range groups {
			c.groups[groups[i].Name] = &groups[i]
		}
	}

	c.lastRefresh = time.Now()

	logging.Info("FortiGate cache refreshed",
		"source", c.sourceID,
		"objects", len(c.objects),
		"groups", len(c.groups))

	return nil
}

// LookupIP finds the address object that matches an IP address.
// Returns the object name and true if found, empty string and false otherwise.
func (c *Cache) LookupIP(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// First, try exact IP match
	for _, obj := range c.objects {
		if obj.IP != nil && obj.IP.Equal(ip) {
			return obj.Name, true
		}
	}

	// Then, try network match
	for _, obj := range c.objects {
		if obj.Network != nil && obj.Network.Contains(ip) {
			return obj.Name, true
		}
	}

	// Finally, try IP range match
	for _, obj := range c.objects {
		if obj.Type == "iprange" && obj.StartIP != "" && obj.EndIP != "" {
			startIP := net.ParseIP(obj.StartIP)
			endIP := net.ParseIP(obj.EndIP)
			if startIP != nil && endIP != nil {
				if ipInRange(ip, startIP, endIP) {
					return obj.Name, true
				}
			}
		}
	}

	return "", false
}

// isGenericAddress checks if an address object is too generic to be useful.
// Objects like 0.0.0.0/0 or ::/0 would match everything and are skipped.
func isGenericAddress(obj *AddressObject) bool {
	if obj == nil {
		return true
	}

	// Check for "all" or "any" type objects
	if obj.Type == "all" {
		return true
	}

	// Check network objects for 0.0.0.0/0 or ::/0
	if obj.Network != nil {
		ones, bits := obj.Network.Mask.Size()
		// /0 network matches everything
		if ones == 0 {
			return true
		}
		// Check if it's 0.0.0.0/0
		if obj.Network.IP.Equal(net.IPv4zero) && ones == 0 {
			return true
		}
		// Check if it's ::/0
		if obj.Network.IP.Equal(net.IPv6zero) && ones == 0 {
			return true
		}
		// Very large networks (e.g., /1, /2) are also too generic
		if bits == 32 && ones <= 4 { // IPv4 /4 or larger
			return true
		}
		if bits == 128 && ones <= 8 { // IPv6 /8 or larger
			return true
		}
	}

	// Check for 0.0.0.0 as single IP
	if obj.IP != nil && (obj.IP.Equal(net.IPv4zero) || obj.IP.IsUnspecified()) {
		return true
	}

	// Check IP ranges that span everything
	if obj.Type == "iprange" && obj.StartIP == "0.0.0.0" {
		return true
	}

	return false
}

// ipInRange checks if an IP is within a range.
func ipInRange(ip, start, end net.IP) bool {
	// Normalize to 16-byte representation
	ip = ip.To16()
	start = start.To16()
	end = end.To16()

	if ip == nil || start == nil || end == nil {
		return false
	}

	// Compare bytes
	for i := 0; i < 16; i++ {
		if ip[i] < start[i] {
			return false
		}
		if ip[i] > end[i] {
			return false
		}
	}

	return true
}

// GetObject returns an address object by name.
func (c *Cache) GetObject(name string) (*AddressObject, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	obj, ok := c.objects[name]
	return obj, ok
}

// GetGroup returns an address group by name.
func (c *Cache) GetGroup(name string) (*AddressGroup, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	grp, ok := c.groups[name]
	return grp, ok
}

// ObjectCount returns the number of cached objects.
func (c *Cache) ObjectCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.objects)
}

// GroupCount returns the number of cached groups.
func (c *Cache) GroupCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.groups)
}

// LastRefresh returns when the cache was last refreshed.
func (c *Cache) LastRefresh() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastRefresh
}

// SourceID returns the source ID this cache belongs to.
func (c *Cache) SourceID() string {
	return c.sourceID
}

// AllObjects returns all cached address objects.
func (c *Cache) AllObjects() []*AddressObject {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*AddressObject, 0, len(c.objects))
	for _, obj := range c.objects {
		result = append(result, obj)
	}
	return result
}


