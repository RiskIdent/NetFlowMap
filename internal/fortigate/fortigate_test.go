package fortigate

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseAddressObjectIPMask(t *testing.T) {
	obj := &AddressObject{
		Name:   "internal-net",
		Type:   "ipmask",
		Subnet: "192.168.1.0 255.255.255.0",
	}

	parseAddressObject(obj)

	if obj.Network == nil {
		t.Fatal("expected network to be parsed")
	}

	if !obj.Network.IP.Equal(net.ParseIP("192.168.1.0")) {
		t.Errorf("expected IP 192.168.1.0, got %s", obj.Network.IP)
	}

	// Test that an IP in the network matches
	testIP := net.ParseIP("192.168.1.100")
	if !obj.Network.Contains(testIP) {
		t.Error("expected 192.168.1.100 to be in network")
	}

	// Test that an IP outside the network doesn't match
	testIP = net.ParseIP("192.168.2.100")
	if obj.Network.Contains(testIP) {
		t.Error("expected 192.168.2.100 to not be in network")
	}
}

func TestParseAddressObjectCIDR(t *testing.T) {
	obj := &AddressObject{
		Name:   "internal-net",
		Type:   "ipmask",
		Subnet: "10.0.0.0/8",
	}

	parseAddressObject(obj)

	if obj.Network == nil {
		t.Fatal("expected network to be parsed")
	}

	testIP := net.ParseIP("10.1.2.3")
	if !obj.Network.Contains(testIP) {
		t.Error("expected 10.1.2.3 to be in network")
	}
}

func TestParseAddressObjectIPRange(t *testing.T) {
	obj := &AddressObject{
		Name:    "ip-range",
		Type:    "iprange",
		StartIP: "192.168.1.100",
		EndIP:   "192.168.1.200",
	}

	parseAddressObject(obj)

	if obj.IP == nil {
		t.Fatal("expected IP to be parsed")
	}

	if !obj.IP.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("expected start IP 192.168.1.100, got %s", obj.IP)
	}
}

func TestIPInRange(t *testing.T) {
	tests := []struct {
		ip       string
		start    string
		end      string
		expected bool
	}{
		{"192.168.1.150", "192.168.1.100", "192.168.1.200", true},
		{"192.168.1.100", "192.168.1.100", "192.168.1.200", true},
		{"192.168.1.200", "192.168.1.100", "192.168.1.200", true},
		{"192.168.1.50", "192.168.1.100", "192.168.1.200", false},
		{"192.168.1.250", "192.168.1.100", "192.168.1.200", false},
		{"192.168.2.150", "192.168.1.100", "192.168.1.200", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		start := net.ParseIP(tt.start)
		end := net.ParseIP(tt.end)

		result := ipInRange(ip, start, end)
		if result != tt.expected {
			t.Errorf("ipInRange(%s, %s, %s) = %v, want %v",
				tt.ip, tt.start, tt.end, result, tt.expected)
		}
	}
}

func TestCacheLookupIP(t *testing.T) {
	// Create a cache with some objects
	cache := &Cache{
		objects: make(map[string]*AddressObject),
	}

	// Add a network object
	netObj := &AddressObject{
		Name:   "internal-net",
		Type:   "ipmask",
		Subnet: "192.168.1.0 255.255.255.0",
	}
	parseAddressObject(netObj)
	cache.objects["internal-net"] = netObj

	// Add a single IP object
	ipObj := &AddressObject{
		Name:   "server1",
		Type:   "ipmask",
		Subnet: "10.0.0.1 255.255.255.255",
	}
	parseAddressObject(ipObj)
	cache.objects["server1"] = ipObj

	// Test lookups
	tests := []struct {
		ip       string
		expected string
		found    bool
	}{
		{"192.168.1.100", "internal-net", true},
		{"10.0.0.1", "server1", true},
		{"8.8.8.8", "", false},
	}

	for _, tt := range tests {
		name, found := cache.LookupIP(tt.ip)
		if found != tt.found {
			t.Errorf("LookupIP(%s) found = %v, want %v", tt.ip, found, tt.found)
		}
		if name != tt.expected {
			t.Errorf("LookupIP(%s) name = %s, want %s", tt.ip, name, tt.expected)
		}
	}
}

func TestCacheLookupIPRange(t *testing.T) {
	cache := &Cache{
		objects: make(map[string]*AddressObject),
	}

	// Add an IP range object
	rangeObj := &AddressObject{
		Name:    "dhcp-range",
		Type:    "iprange",
		StartIP: "192.168.1.100",
		EndIP:   "192.168.1.200",
	}
	parseAddressObject(rangeObj)
	cache.objects["dhcp-range"] = rangeObj

	// Test lookups
	name, found := cache.LookupIP("192.168.1.150")
	if !found {
		t.Error("expected to find IP in range")
	}
	if name != "dhcp-range" {
		t.Errorf("expected name 'dhcp-range', got '%s'", name)
	}

	_, found = cache.LookupIP("192.168.1.50")
	if found {
		t.Error("expected to not find IP outside range")
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient(ClientConfig{
		Host:      "https://192.168.1.1",
		Token:     "test-token",
		VerifySSL: false,
	})

	if client.host != "https://192.168.1.1" {
		t.Errorf("expected host 'https://192.168.1.1', got '%s'", client.host)
	}
}

func TestClientHostNormalization(t *testing.T) {
	client := NewClient(ClientConfig{
		Host:  "https://192.168.1.1/",
		Token: "test-token",
	})

	// Trailing slash should be removed
	if client.host != "https://192.168.1.1" {
		t.Errorf("expected host without trailing slash, got '%s'", client.host)
	}
}

func TestClientWithMockServer(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/api/v2/cmdb/firewall/address":
			response := AddressResponse{
				Status:     "success",
				HTTPStatus: 200,
				Results: []AddressObject{
					{Name: "internal-net", Type: "ipmask", Subnet: "192.168.1.0 255.255.255.0"},
					{Name: "google-dns", Type: "ipmask", Subnet: "8.8.8.8 255.255.255.255"},
				},
			}
			json.NewEncoder(w).Encode(response)

		case "/api/v2/cmdb/firewall/addrgrp":
			response := AddressGroupResponse{
				Status:     "success",
				HTTPStatus: 200,
				Results: []AddressGroup{
					{Name: "internal-group", Members: []GroupMember{{Name: "internal-net"}}},
				},
			}
			json.NewEncoder(w).Encode(response)

		case "/api/v2/cmdb/system/status":
			w.Write([]byte(`{"status": "success"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client with mock server
	client := NewClient(ClientConfig{
		Host:      server.URL,
		Token:     "test-token",
		VerifySSL: false,
	})

	// Test connection
	err := client.TestConnection()
	if err != nil {
		t.Fatalf("TestConnection failed: %v", err)
	}

	// Test GetAddressObjects
	objects, err := client.GetAddressObjects()
	if err != nil {
		t.Fatalf("GetAddressObjects failed: %v", err)
	}

	if len(objects) != 2 {
		t.Errorf("expected 2 objects, got %d", len(objects))
	}

	// Check that objects are parsed
	found := false
	for _, obj := range objects {
		if obj.Name == "internal-net" && obj.Network != nil {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected internal-net to have parsed network")
	}

	// Test GetAddressGroups
	groups, err := client.GetAddressGroups()
	if err != nil {
		t.Fatalf("GetAddressGroups failed: %v", err)
	}

	if len(groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(groups))
	}
}

func TestCacheWithMockServer(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/cmdb/firewall/address":
			response := AddressResponse{
				Status:     "success",
				HTTPStatus: 200,
				Results: []AddressObject{
					{Name: "internal-net", Type: "ipmask", Subnet: "192.168.1.0 255.255.255.0"},
				},
			}
			json.NewEncoder(w).Encode(response)

		case "/api/v2/cmdb/firewall/addrgrp":
			response := AddressGroupResponse{
				Status:     "success",
				HTTPStatus: 200,
				Results:    []AddressGroup{},
			}
			json.NewEncoder(w).Encode(response)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		Host:      server.URL,
		Token:     "test-token",
		VerifySSL: false,
	})

	cache := NewCache(CacheConfig{
		Client:          client,
		SourceID:        "test-fw",
		RefreshInterval: 1 * time.Hour,
	})

	// Manual refresh (don't start the loop)
	err := cache.Refresh()
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	if cache.ObjectCount() != 1 {
		t.Errorf("expected 1 object, got %d", cache.ObjectCount())
	}

	// Test lookup
	name, found := cache.LookupIP("192.168.1.100")
	if !found {
		t.Error("expected to find IP")
	}
	if name != "internal-net" {
		t.Errorf("expected name 'internal-net', got '%s'", name)
	}

	// Test GetObject
	obj, found := cache.GetObject("internal-net")
	if !found {
		t.Error("expected to find object")
	}
	if obj.Name != "internal-net" {
		t.Errorf("expected object name 'internal-net', got '%s'", obj.Name)
	}
}

func TestManager(t *testing.T) {
	manager := NewManager()
	defer manager.Close()

	if manager.SourceCount() != 0 {
		t.Errorf("expected 0 sources, got %d", manager.SourceCount())
	}

	if manager.HasSource("test-fw") {
		t.Error("expected no source initially")
	}
}

func TestCacheSourceID(t *testing.T) {
	cache := NewCache(CacheConfig{
		SourceID:        "fw-main",
		RefreshInterval: time.Hour,
	})

	if cache.SourceID() != "fw-main" {
		t.Errorf("expected source ID 'fw-main', got '%s'", cache.SourceID())
	}
}

func TestCacheLastRefresh(t *testing.T) {
	cache := &Cache{
		objects:     make(map[string]*AddressObject),
		groups:      make(map[string]*AddressGroup),
		lastRefresh: time.Now().Add(-1 * time.Hour),
	}

	lastRefresh := cache.LastRefresh()
	if time.Since(lastRefresh) < 59*time.Minute {
		t.Error("expected last refresh to be about 1 hour ago")
	}
}

func TestAddressObjectTypes(t *testing.T) {
	// Test FQDN type (should not parse network)
	obj := &AddressObject{
		Name: "google",
		Type: "fqdn",
		FQDN: "www.google.com",
	}
	parseAddressObject(obj)

	if obj.Network != nil {
		t.Error("FQDN type should not have network")
	}

	// Test geography type (should not parse network)
	obj = &AddressObject{
		Name:    "germany",
		Type:    "geography",
		Country: "DE",
	}
	parseAddressObject(obj)

	if obj.Network != nil {
		t.Error("geography type should not have network")
	}
}

func TestCacheAllObjects(t *testing.T) {
	cache := &Cache{
		objects: map[string]*AddressObject{
			"obj1": {Name: "obj1"},
			"obj2": {Name: "obj2"},
		},
	}

	objects := cache.AllObjects()
	if len(objects) != 2 {
		t.Errorf("expected 2 objects, got %d", len(objects))
	}
}


