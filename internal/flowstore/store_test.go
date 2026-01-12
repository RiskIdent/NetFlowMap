package flowstore

import (
	"net"
	"testing"
	"time"

	"github.com/kai/netflowmap/internal/netflow"
)

func TestNewStore(t *testing.T) {
	store := New(Config{
		DisplayTimeout: 60 * time.Second,
	})
	defer store.Close()

	if store == nil {
		t.Fatal("expected non-nil store")
	}

	stats := store.Stats()
	if stats.FlowCount != 0 {
		t.Errorf("expected 0 flows, got %d", stats.FlowCount)
	}
	if stats.SourceCount != 0 {
		t.Errorf("expected 0 sources, got %d", stats.SourceCount)
	}
}

func TestRegisterSource(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{
		ID:        "fw-main",
		Name:      "Main Firewall",
		Latitude:  52.52,
		Longitude: 13.405,
	})

	sources := store.GetSources()
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}

	if sources[0].ID != "fw-main" {
		t.Errorf("expected source ID 'fw-main', got '%s'", sources[0].ID)
	}
	if sources[0].Name != "Main Firewall" {
		t.Errorf("expected source name 'Main Firewall', got '%s'", sources[0].Name)
	}
}

func TestAddFlowsOutbound(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{
		ID:        "fw-main",
		Name:      "Main Firewall",
		Latitude:  52.52,
		Longitude: 13.405,
	})

	// Add an outbound flow (private -> public)
	flows := []netflow.Flow{
		{
			SourceID:  "fw-main",
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.100"), // Private
			DstIP:     net.ParseIP("8.8.8.8"),       // Public
			SrcPort:   12345,
			DstPort:   443,
			Protocol:  netflow.ProtocolTCP,
			Bytes:     1500,
			Packets:   10,
		},
	}

	store.AddFlows("fw-main", flows)

	storedFlows := store.GetFlows("fw-main")
	if len(storedFlows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(storedFlows))
	}

	flow := storedFlows[0]
	if flow.Inbound {
		t.Error("expected outbound flow")
	}
	if flow.LocalIP != "192.168.1.100" {
		t.Errorf("expected local IP 192.168.1.100, got %s", flow.LocalIP)
	}
	if flow.RemoteIP != "8.8.8.8" {
		t.Errorf("expected remote IP 8.8.8.8, got %s", flow.RemoteIP)
	}
	if flow.Bytes != 1500 {
		t.Errorf("expected 1500 bytes, got %d", flow.Bytes)
	}
}

func TestAddFlowsInbound(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{
		ID:        "fw-main",
		Name:      "Main Firewall",
		Latitude:  52.52,
		Longitude: 13.405,
	})

	// Add an inbound flow (public -> private)
	flows := []netflow.Flow{
		{
			SourceID:  "fw-main",
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("1.2.3.4"),       // Public
			DstIP:     net.ParseIP("10.0.0.50"),    // Private
			SrcPort:   443,
			DstPort:   54321,
			Protocol:  netflow.ProtocolTCP,
			Bytes:     2000,
			Packets:   15,
		},
	}

	store.AddFlows("fw-main", flows)

	storedFlows := store.GetFlows("fw-main")
	if len(storedFlows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(storedFlows))
	}

	flow := storedFlows[0]
	if !flow.Inbound {
		t.Error("expected inbound flow")
	}
	if flow.LocalIP != "10.0.0.50" {
		t.Errorf("expected local IP 10.0.0.50, got %s", flow.LocalIP)
	}
	if flow.RemoteIP != "1.2.3.4" {
		t.Errorf("expected remote IP 1.2.3.4, got %s", flow.RemoteIP)
	}
}

func TestFlowAggregation(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{
		ID:   "fw-main",
		Name: "Main Firewall",
	})

	// Add same flow multiple times
	for i := 0; i < 5; i++ {
		flows := []netflow.Flow{
			{
				SourceID:  "fw-main",
				Timestamp: time.Now(),
				SrcIP:     net.ParseIP("192.168.1.100"),
				DstIP:     net.ParseIP("8.8.8.8"),
				SrcPort:   12345,
				DstPort:   443,
				Protocol:  netflow.ProtocolTCP,
				Bytes:     1000,
				Packets:   5,
			},
		}
		store.AddFlows("fw-main", flows)
	}

	storedFlows := store.GetFlows("fw-main")
	if len(storedFlows) != 1 {
		t.Fatalf("expected 1 aggregated flow, got %d", len(storedFlows))
	}

	flow := storedFlows[0]
	if flow.Bytes != 5000 {
		t.Errorf("expected 5000 bytes (aggregated), got %d", flow.Bytes)
	}
	if flow.Packets != 25 {
		t.Errorf("expected 25 packets (aggregated), got %d", flow.Packets)
	}
	if flow.PacketCount != 5 {
		t.Errorf("expected packet count 5, got %d", flow.PacketCount)
	}
}

func TestPrivateToPrivateSkipped(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{
		ID:   "fw-main",
		Name: "Main Firewall",
	})

	// Private to private flow should be skipped
	flows := []netflow.Flow{
		{
			SourceID:  "fw-main",
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.100"),
			DstIP:     net.ParseIP("192.168.1.200"),
			SrcPort:   12345,
			DstPort:   80,
			Protocol:  netflow.ProtocolTCP,
			Bytes:     1000,
			Packets:   5,
		},
	}

	store.AddFlows("fw-main", flows)

	storedFlows := store.GetFlows("fw-main")
	if len(storedFlows) != 0 {
		t.Errorf("expected 0 flows (private-to-private skipped), got %d", len(storedFlows))
	}
}

func TestPublicToPublicSkipped(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{
		ID:   "fw-main",
		Name: "Main Firewall",
	})

	// Public to public flow should be skipped
	flows := []netflow.Flow{
		{
			SourceID:  "fw-main",
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("8.8.8.8"),
			DstIP:     net.ParseIP("1.1.1.1"),
			SrcPort:   12345,
			DstPort:   80,
			Protocol:  netflow.ProtocolTCP,
			Bytes:     1000,
			Packets:   5,
		},
	}

	store.AddFlows("fw-main", flows)

	storedFlows := store.GetFlows("fw-main")
	if len(storedFlows) != 0 {
		t.Errorf("expected 0 flows (public-to-public skipped), got %d", len(storedFlows))
	}
}

func TestGetAllFlows(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{ID: "fw-1", Name: "Firewall 1"})
	store.RegisterSource(SourceInfo{ID: "fw-2", Name: "Firewall 2"})

	store.AddFlows("fw-1", []netflow.Flow{
		{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.1"),
			DstIP:     net.ParseIP("8.8.8.8"),
			Protocol:  netflow.ProtocolTCP,
			Bytes:     1000,
		},
	})

	store.AddFlows("fw-2", []netflow.Flow{
		{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("10.0.0.1"),
			DstIP:     net.ParseIP("1.1.1.1"),
			Protocol:  netflow.ProtocolUDP,
			Bytes:     2000,
		},
	})

	allFlows := store.GetAllFlows()
	if len(allFlows) != 2 {
		t.Errorf("expected 2 flows, got %d", len(allFlows))
	}
}

func TestFlowCount(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{ID: "fw-main", Name: "Main"})

	if store.FlowCount("fw-main") != 0 {
		t.Error("expected 0 flows initially")
	}

	store.AddFlows("fw-main", []netflow.Flow{
		{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.1"),
			DstIP:     net.ParseIP("8.8.8.8"),
			Protocol:  netflow.ProtocolTCP,
		},
	})

	if store.FlowCount("fw-main") != 1 {
		t.Errorf("expected 1 flow, got %d", store.FlowCount("fw-main"))
	}

	if store.TotalFlowCount() != 1 {
		t.Errorf("expected total 1 flow, got %d", store.TotalFlowCount())
	}
}

func TestSubscribeUnsubscribe(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{ID: "fw-main", Name: "Main"})

	// Subscribe
	ch := store.Subscribe()

	stats := store.Stats()
	if stats.SubscriberCount != 1 {
		t.Errorf("expected 1 subscriber, got %d", stats.SubscriberCount)
	}

	// Add a flow
	store.AddFlows("fw-main", []netflow.Flow{
		{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.1"),
			DstIP:     net.ParseIP("8.8.8.8"),
			Protocol:  netflow.ProtocolTCP,
		},
	})

	// Should receive the flow
	select {
	case flow := <-ch:
		if flow.RemoteIP != "8.8.8.8" {
			t.Errorf("expected remote IP 8.8.8.8, got %s", flow.RemoteIP)
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for flow notification")
	}

	// Unsubscribe
	store.Unsubscribe(ch)

	stats = store.Stats()
	if stats.SubscriberCount != 0 {
		t.Errorf("expected 0 subscribers, got %d", stats.SubscriberCount)
	}
}

func TestFlowExpiry(t *testing.T) {
	store := New(Config{
		DisplayTimeout: 50 * time.Millisecond, // Very short for testing
	})
	defer store.Close()

	store.RegisterSource(SourceInfo{ID: "fw-main", Name: "Main"})

	store.AddFlows("fw-main", []netflow.Flow{
		{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.1"),
			DstIP:     net.ParseIP("8.8.8.8"),
			Protocol:  netflow.ProtocolTCP,
		},
	})

	if store.FlowCount("fw-main") != 1 {
		t.Error("expected 1 flow initially")
	}

	// Wait for expiry and cleanup
	time.Sleep(100 * time.Millisecond)
	store.cleanup() // Manually trigger cleanup

	if store.FlowCount("fw-main") != 0 {
		t.Errorf("expected 0 flows after expiry, got %d", store.FlowCount("fw-main"))
	}
}

func TestSetAddressObjectName(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{ID: "fw-main", Name: "Main"})

	store.AddFlows("fw-main", []netflow.Flow{
		{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.1"),
			DstIP:     net.ParseIP("8.8.8.8"),
			Protocol:  netflow.ProtocolTCP,
		},
	})

	store.SetAddressObjectName("fw-main", "8.8.8.8", "Google-DNS")

	flows := store.GetFlows("fw-main")
	if len(flows) != 1 {
		t.Fatal("expected 1 flow")
	}

	if flows[0].AddressObjectName != "Google-DNS" {
		t.Errorf("expected address object name 'Google-DNS', got '%s'", flows[0].AddressObjectName)
	}
}

func TestStoreStats(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{ID: "fw-1", Name: "FW1"})
	store.RegisterSource(SourceInfo{ID: "fw-2", Name: "FW2"})

	store.AddFlows("fw-1", []netflow.Flow{
		{Timestamp: time.Now(), SrcIP: net.ParseIP("192.168.1.1"), DstIP: net.ParseIP("8.8.8.8"), Protocol: netflow.ProtocolTCP},
		{Timestamp: time.Now(), SrcIP: net.ParseIP("192.168.1.2"), DstIP: net.ParseIP("1.1.1.1"), Protocol: netflow.ProtocolUDP},
	})

	stats := store.Stats()

	if stats.SourceCount != 2 {
		t.Errorf("expected 2 sources, got %d", stats.SourceCount)
	}
	if stats.FlowCount != 2 {
		t.Errorf("expected 2 flows, got %d", stats.FlowCount)
	}
}

func TestProtocolName(t *testing.T) {
	store := New(Config{DisplayTimeout: 60 * time.Second})
	defer store.Close()

	store.RegisterSource(SourceInfo{ID: "fw-main", Name: "Main"})

	store.AddFlows("fw-main", []netflow.Flow{
		{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP("192.168.1.1"),
			DstIP:     net.ParseIP("8.8.8.8"),
			Protocol:  netflow.ProtocolUDP,
		},
	})

	flows := store.GetFlows("fw-main")
	if len(flows) != 1 {
		t.Fatal("expected 1 flow")
	}

	if flows[0].ProtocolName != "UDP" {
		t.Errorf("expected protocol name 'UDP', got '%s'", flows[0].ProtocolName)
	}
}


