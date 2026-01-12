package netflow

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestTemplateCacheSetGet(t *testing.T) {
	cache := NewTemplateCache()

	tmpl := &Template{
		ID: 256,
		Fields: []TemplateField{
			{Type: FieldIPv4SrcAddr, Length: 4},
			{Type: FieldIPv4DstAddr, Length: 4},
		},
		TotalLength: 8,
	}

	cache.Set("192.168.1.1", tmpl)

	// Should be able to retrieve it
	retrieved := cache.Get("192.168.1.1", 256)
	if retrieved == nil {
		t.Fatal("expected to retrieve template")
	}
	if retrieved.ID != 256 {
		t.Errorf("expected template ID 256, got %d", retrieved.ID)
	}
	if len(retrieved.Fields) != 2 {
		t.Errorf("expected 2 fields, got %d", len(retrieved.Fields))
	}

	// Should not find template for different source
	notFound := cache.Get("192.168.1.2", 256)
	if notFound != nil {
		t.Error("should not find template for different source")
	}

	// Should not find different template ID
	notFound = cache.Get("192.168.1.1", 257)
	if notFound != nil {
		t.Error("should not find different template ID")
	}
}

func TestTemplateCacheDelete(t *testing.T) {
	cache := NewTemplateCache()

	tmpl := &Template{ID: 256, TotalLength: 8}
	cache.Set("192.168.1.1", tmpl)

	cache.Delete("192.168.1.1", 256)

	retrieved := cache.Get("192.168.1.1", 256)
	if retrieved != nil {
		t.Error("template should be deleted")
	}
}

func TestTemplateCacheCount(t *testing.T) {
	cache := NewTemplateCache()

	if cache.Count() != 0 {
		t.Errorf("expected count 0, got %d", cache.Count())
	}

	cache.Set("192.168.1.1", &Template{ID: 256})
	cache.Set("192.168.1.1", &Template{ID: 257})
	cache.Set("192.168.1.2", &Template{ID: 256})

	if cache.Count() != 3 {
		t.Errorf("expected count 3, got %d", cache.Count())
	}
}

func TestTemplateCacheCountForSource(t *testing.T) {
	cache := NewTemplateCache()

	cache.Set("192.168.1.1", &Template{ID: 256})
	cache.Set("192.168.1.1", &Template{ID: 257})
	cache.Set("192.168.1.2", &Template{ID: 256})

	count := cache.CountForSource("192.168.1.1")
	if count != 2 {
		t.Errorf("expected count 2 for source 192.168.1.1, got %d", count)
	}

	count = cache.CountForSource("192.168.1.2")
	if count != 1 {
		t.Errorf("expected count 1 for source 192.168.1.2, got %d", count)
	}
}

func TestParserParseHeader(t *testing.T) {
	parser := NewParser(NewTemplateCache())

	// Create a valid NetFlow v9 header
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:], 9)          // Version
	binary.BigEndian.PutUint16(header[2:], 2)          // Count
	binary.BigEndian.PutUint32(header[4:], 12345678)   // SysUptime
	binary.BigEndian.PutUint32(header[8:], 1704067200) // UnixSecs (2024-01-01)
	binary.BigEndian.PutUint32(header[12:], 100)       // Sequence
	binary.BigEndian.PutUint32(header[16:], 1)         // SourceID

	parsed, err := parser.parseHeader(header)
	if err != nil {
		t.Fatalf("parseHeader failed: %v", err)
	}

	if parsed.Version != 9 {
		t.Errorf("expected version 9, got %d", parsed.Version)
	}
	if parsed.Count != 2 {
		t.Errorf("expected count 2, got %d", parsed.Count)
	}
	if parsed.SysUptime != 12345678 {
		t.Errorf("expected sysuptime 12345678, got %d", parsed.SysUptime)
	}
	if parsed.Sequence != 100 {
		t.Errorf("expected sequence 100, got %d", parsed.Sequence)
	}
}

func TestParserParsePacketTooShort(t *testing.T) {
	parser := NewParser(NewTemplateCache())

	_, err := parser.ParsePacket([]byte{1, 2, 3}, "192.168.1.1")
	if err == nil {
		t.Error("expected error for short packet")
	}
}

func TestParserParsePacketWrongVersion(t *testing.T) {
	parser := NewParser(NewTemplateCache())

	// Create a NetFlow v5 header
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:], 5) // Version 5

	_, err := parser.ParsePacket(header, "192.168.1.1")
	if err == nil {
		t.Error("expected error for wrong version")
	}
}

func TestParseUint(t *testing.T) {
	tests := []struct {
		data     []byte
		expected uint64
	}{
		{[]byte{0x12}, 0x12},
		{[]byte{0x12, 0x34}, 0x1234},
		{[]byte{0x12, 0x34, 0x56, 0x78}, 0x12345678},
		{[]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}, 0x123456789abcdef0},
		{[]byte{0x01, 0x02, 0x03}, 0x010203}, // 3 bytes (non-standard)
	}

	for _, tt := range tests {
		result := parseUint(tt.data)
		if result != tt.expected {
			t.Errorf("parseUint(%v) = %d, want %d", tt.data, result, tt.expected)
		}
	}
}

func TestProtocolName(t *testing.T) {
	tests := []struct {
		proto    uint8
		expected string
	}{
		{ProtocolICMP, "ICMP"},
		{ProtocolTCP, "TCP"},
		{ProtocolUDP, "UDP"},
		{99, "OTHER"},
	}

	for _, tt := range tests {
		result := ProtocolName(tt.proto)
		if result != tt.expected {
			t.Errorf("ProtocolName(%d) = %s, want %s", tt.proto, result, tt.expected)
		}
	}
}

func TestFlowStruct(t *testing.T) {
	flow := Flow{
		SourceID:  "192.168.1.1",
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("8.8.8.8"),
		SrcPort:   12345,
		DstPort:   443,
		Protocol:  ProtocolTCP,
		Bytes:     1500,
		Packets:   10,
		Inbound:   false,
	}

	if flow.SourceID != "192.168.1.1" {
		t.Errorf("expected SourceID 192.168.1.1, got %s", flow.SourceID)
	}
	if !flow.SrcIP.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("expected SrcIP 10.0.0.1, got %s", flow.SrcIP)
	}
	if flow.Protocol != ProtocolTCP {
		t.Errorf("expected Protocol TCP, got %d", flow.Protocol)
	}
}

func TestCollectorConfig(t *testing.T) {
	handler := func(flows []Flow) {
		// Handler for testing
	}

	cfg := CollectorConfig{
		Port:    2055,
		Handler: handler,
	}

	collector := NewCollector(cfg)

	if collector.Port() != 2055 {
		t.Errorf("expected port 2055, got %d", collector.Port())
	}

	if collector.IsRunning() {
		t.Error("collector should not be running before Start")
	}
}

func TestCollectorStats(t *testing.T) {
	collector := NewCollector(CollectorConfig{Port: 12345})

	stats := collector.Stats()
	if stats.PacketsReceived != 0 {
		t.Errorf("expected 0 packets received, got %d", stats.PacketsReceived)
	}
	if stats.FlowsReceived != 0 {
		t.Errorf("expected 0 flows received, got %d", stats.FlowsReceived)
	}
}

func TestParserWithTemplateAndData(t *testing.T) {
	templates := NewTemplateCache()
	parser := NewParser(templates)

	sourceIP := "192.168.1.1"

	// Create a template FlowSet
	templateData := make([]byte, 0)
	// Template ID
	templateData = append(templateData, 0x01, 0x00) // Template ID 256
	// Field Count
	templateData = append(templateData, 0x00, 0x05) // 5 fields

	// Field 1: IPv4 Src Addr (type 8, length 4)
	templateData = append(templateData, 0x00, 0x08, 0x00, 0x04)
	// Field 2: IPv4 Dst Addr (type 12, length 4)
	templateData = append(templateData, 0x00, 0x0c, 0x00, 0x04)
	// Field 3: L4 Src Port (type 7, length 2)
	templateData = append(templateData, 0x00, 0x07, 0x00, 0x02)
	// Field 4: L4 Dst Port (type 11, length 2)
	templateData = append(templateData, 0x00, 0x0b, 0x00, 0x02)
	// Field 5: Protocol (type 4, length 1)
	templateData = append(templateData, 0x00, 0x04, 0x00, 0x01)

	err := parser.parseTemplateFlowSet(templateData, sourceIP)
	if err != nil {
		t.Fatalf("parseTemplateFlowSet failed: %v", err)
	}

	// Check template was stored
	tmpl := templates.Get(sourceIP, 256)
	if tmpl == nil {
		t.Fatal("template not found in cache")
	}
	if tmpl.TotalLength != 13 { // 4+4+2+2+1
		t.Errorf("expected total length 13, got %d", tmpl.TotalLength)
	}

	// Now parse a data record using this template
	header := &Header{
		Version:   9,
		Count:     1,
		SysUptime: 1000000,
		UnixSecs:  1704067200,
		Sequence:  1,
		SourceID:  1,
	}

	dataRecord := make([]byte, 13)
	copy(dataRecord[0:4], net.ParseIP("10.0.0.1").To4())  // Src IP
	copy(dataRecord[4:8], net.ParseIP("8.8.8.8").To4())   // Dst IP
	binary.BigEndian.PutUint16(dataRecord[8:10], 12345)   // Src Port
	binary.BigEndian.PutUint16(dataRecord[10:12], 443)    // Dst Port
	dataRecord[12] = ProtocolTCP                          // Protocol

	flows, err := parser.parseDataFlowSet(dataRecord, sourceIP, 256, header)
	if err != nil {
		t.Fatalf("parseDataFlowSet failed: %v", err)
	}

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	flow := flows[0]
	if !flow.SrcIP.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("expected SrcIP 10.0.0.1, got %s", flow.SrcIP)
	}
	if !flow.DstIP.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("expected DstIP 8.8.8.8, got %s", flow.DstIP)
	}
	if flow.SrcPort != 12345 {
		t.Errorf("expected SrcPort 12345, got %d", flow.SrcPort)
	}
	if flow.DstPort != 443 {
		t.Errorf("expected DstPort 443, got %d", flow.DstPort)
	}
	if flow.Protocol != ProtocolTCP {
		t.Errorf("expected Protocol TCP (6), got %d", flow.Protocol)
	}
}

func TestCollectorStartStop(t *testing.T) {
	// Use a random high port to avoid conflicts
	collector := NewCollector(CollectorConfig{Port: 19999})

	// Start collector
	err := collector.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !collector.IsRunning() {
		t.Error("collector should be running after Start")
	}

	// Starting again should fail
	err = collector.Start()
	if err == nil {
		t.Error("expected error when starting already running collector")
	}

	// Stop collector
	err = collector.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if collector.IsRunning() {
		t.Error("collector should not be running after Stop")
	}
}

func TestTemplateExpiry(t *testing.T) {
	cache := &TemplateCache{
		templates: make(map[string]*Template),
		maxAge:    1 * time.Millisecond, // Very short for testing
	}

	tmpl := &Template{ID: 256}
	cache.Set("192.168.1.1", tmpl)

	// Should be available immediately
	if cache.Get("192.168.1.1", 256) == nil {
		t.Error("template should be available immediately")
	}

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	// Should be expired now
	if cache.Get("192.168.1.1", 256) != nil {
		t.Error("template should be expired")
	}
}

func TestTemplateCacheCleanup(t *testing.T) {
	cache := &TemplateCache{
		templates: make(map[string]*Template),
		maxAge:    1 * time.Millisecond,
	}

	cache.Set("192.168.1.1", &Template{ID: 256})
	cache.Set("192.168.1.1", &Template{ID: 257})

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	removed := cache.Cleanup()
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}

	if cache.Count() != 0 {
		t.Errorf("expected count 0 after cleanup, got %d", cache.Count())
	}
}

