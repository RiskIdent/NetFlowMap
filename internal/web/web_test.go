package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kai/netflowmap/internal/config"
	"github.com/kai/netflowmap/internal/flowstore"
)

func TestHealthEndpoint(t *testing.T) {
	server := New(Config{
		Port: 8080,
	})

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response APIResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !response.Success {
		t.Error("expected success to be true")
	}
}

func TestGetSourcesEmpty(t *testing.T) {
	store := flowstore.New(flowstore.Config{
		DisplayTimeout: time.Minute,
	})
	defer store.Close()

	server := New(Config{
		Port:      8080,
		FlowStore: store,
	})

	req := httptest.NewRequest("GET", "/api/sources", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response APIResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !response.Success {
		t.Error("expected success to be true")
	}

	// Data should be an empty array
	data, ok := response.Data.([]interface{})
	if !ok {
		t.Fatalf("expected data to be array, got %T", response.Data)
	}

	if len(data) != 0 {
		t.Errorf("expected 0 sources, got %d", len(data))
	}
}

func TestGetSourcesWithData(t *testing.T) {
	store := flowstore.New(flowstore.Config{
		DisplayTimeout: time.Minute,
	})
	defer store.Close()

	store.RegisterSource(flowstore.SourceInfo{
		ID:        "fw-main",
		Name:      "Main Firewall",
		Latitude:  52.52,
		Longitude: 13.405,
	})

	server := New(Config{
		Port:      8080,
		FlowStore: store,
	})

	req := httptest.NewRequest("GET", "/api/sources", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response APIResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	data, ok := response.Data.([]interface{})
	if !ok {
		t.Fatalf("expected data to be array, got %T", response.Data)
	}

	if len(data) != 1 {
		t.Errorf("expected 1 source, got %d", len(data))
	}
}

func TestGetFlowsEmpty(t *testing.T) {
	store := flowstore.New(flowstore.Config{
		DisplayTimeout: time.Minute,
	})
	defer store.Close()

	server := New(Config{
		Port:      8080,
		FlowStore: store,
	})

	req := httptest.NewRequest("GET", "/api/flows", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestGetFlowsBySource(t *testing.T) {
	store := flowstore.New(flowstore.Config{
		DisplayTimeout: time.Minute,
	})
	defer store.Close()

	store.RegisterSource(flowstore.SourceInfo{
		ID:   "fw-main",
		Name: "Main Firewall",
	})

	server := New(Config{
		Port:      8080,
		FlowStore: store,
	})

	req := httptest.NewRequest("GET", "/api/flows/fw-main", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestGetStats(t *testing.T) {
	store := flowstore.New(flowstore.Config{
		DisplayTimeout: time.Minute,
	})
	defer store.Close()

	store.RegisterSource(flowstore.SourceInfo{
		ID:   "fw-main",
		Name: "Main Firewall",
	})

	server := New(Config{
		Port:      8080,
		FlowStore: store,
	})

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response APIResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !response.Success {
		t.Error("expected success to be true")
	}

	data, ok := response.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected data to be object, got %T", response.Data)
	}

	if sources, ok := data["sources"].(float64); !ok || sources != 1 {
		t.Errorf("expected sources to be 1, got %v", data["sources"])
	}
}

func TestFilterFlowsByDirection(t *testing.T) {
	flows := []*flowstore.AggregatedFlow{
		{Key: "1", Inbound: true},
		{Key: "2", Inbound: false},
		{Key: "3", Inbound: true},
		{Key: "4", Inbound: false},
	}

	// Filter inbound
	inbound := filterFlows(flows, "in", "")
	if len(inbound) != 2 {
		t.Errorf("expected 2 inbound flows, got %d", len(inbound))
	}
	for _, f := range inbound {
		if !f.Inbound {
			t.Error("expected all filtered flows to be inbound")
		}
	}

	// Filter outbound
	outbound := filterFlows(flows, "out", "")
	if len(outbound) != 2 {
		t.Errorf("expected 2 outbound flows, got %d", len(outbound))
	}
	for _, f := range outbound {
		if f.Inbound {
			t.Error("expected all filtered flows to be outbound")
		}
	}
}

func TestFilterFlowsByText(t *testing.T) {
	flows := []*flowstore.AggregatedFlow{
		{Key: "1", RemoteIP: "8.8.8.8", RemoteCountry: "United States"},
		{Key: "2", RemoteIP: "1.1.1.1", RemoteCountry: "Australia"},
		{Key: "3", RemoteIP: "8.8.4.4", RemoteCountry: "United States"},
	}

	// Filter by IP
	filtered := filterFlows(flows, "", "8.8")
	if len(filtered) != 2 {
		t.Errorf("expected 2 flows matching '8.8', got %d", len(filtered))
	}

	// Filter by country
	filtered = filterFlows(flows, "", "australia")
	if len(filtered) != 1 {
		t.Errorf("expected 1 flow matching 'australia', got %d", len(filtered))
	}
}

func TestMatchesFilter(t *testing.T) {
	flow := &flowstore.AggregatedFlow{
		LocalIP:           "192.168.1.100",
		RemoteIP:          "8.8.8.8",
		RemoteCity:        "Mountain View",
		RemoteCountry:     "United States",
		ProtocolName:      "TCP",
		AddressObjectName: "Google-DNS",
		SourceName:        "Main Firewall",
	}

	tests := []struct {
		filter   string
		expected bool
	}{
		{"8.8.8.8", true},
		{"192.168", true},
		{"mountain", true},
		{"united", true},
		{"tcp", true},
		{"google", true},
		{"main", true},
		{"xyz123", false},
	}

	for _, tt := range tests {
		result := matchesFilter(flow, tt.filter)
		if result != tt.expected {
			t.Errorf("matchesFilter(flow, %q) = %v, want %v", tt.filter, result, tt.expected)
		}
	}
}

func TestCORSMiddleware(t *testing.T) {
	// Test with allowed origins configured
	cfg := &config.Config{
		Server: config.ServerConfig{
			AllowedOrigins: []string{"https://example.com"},
		},
	}
	server := New(Config{
		Port:      8080,
		AppConfig: cfg,
	})

	// Test with allowed origin
	req := httptest.NewRequest("OPTIONS", "/api/health", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 for OPTIONS, got %d", w.Code)
	}

	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("expected CORS header for allowed origin, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}

	// Test with disallowed origin - should not set CORS header
	req2 := httptest.NewRequest("OPTIONS", "/api/health", nil)
	req2.Header.Set("Origin", "https://malicious.com")
	w2 := httptest.NewRecorder()

	server.Router().ServeHTTP(w2, req2)

	if w2.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no CORS header for disallowed origin")
	}

	// Test without configured origins (same-origin only)
	serverNoOrigins := New(Config{
		Port: 8080,
	})

	req3 := httptest.NewRequest("OPTIONS", "/api/health", nil)
	req3.Header.Set("Origin", "https://external.com")
	w3 := httptest.NewRecorder()

	serverNoOrigins.Router().ServeHTTP(w3, req3)

	if w3.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no CORS header when no origins configured and origin is external")
	}
}

func TestWebSocketHub(t *testing.T) {
	hub := NewWebSocketHub()

	// Start hub
	go hub.Run()
	defer hub.Close()

	// Initially no clients
	if hub.ClientCount() != 0 {
		t.Errorf("expected 0 clients, got %d", hub.ClientCount())
	}
}

func TestAPIResponseFormat(t *testing.T) {
	server := New(Config{
		Port: 8080,
	})

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected Content-Type to contain 'application/json', got '%s'", contentType)
	}
}

func TestNoFlowStoreReturnsError(t *testing.T) {
	server := New(Config{
		Port: 8080,
		// No FlowStore
	})

	req := httptest.NewRequest("GET", "/api/sources", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}

	var response APIResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Success {
		t.Error("expected success to be false")
	}

	if response.Error == "" {
		t.Error("expected error message")
	}
}

func TestServerPort(t *testing.T) {
	server := New(Config{
		Port: 9090,
	})

	if server.Port() != 9090 {
		t.Errorf("expected port 9090, got %d", server.Port())
	}
}

func TestFlowsWithDirectionFilter(t *testing.T) {
	store := flowstore.New(flowstore.Config{
		DisplayTimeout: time.Minute,
	})
	defer store.Close()

	server := New(Config{
		Port:      8080,
		FlowStore: store,
	})

	// Test with direction parameter
	req := httptest.NewRequest("GET", "/api/flows?direction=in", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestFlowsWithTextFilter(t *testing.T) {
	store := flowstore.New(flowstore.Config{
		DisplayTimeout: time.Minute,
	})
	defer store.Close()

	server := New(Config{
		Port:      8080,
		FlowStore: store,
	})

	// Test with filter parameter
	req := httptest.NewRequest("GET", "/api/flows?filter=google", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}


