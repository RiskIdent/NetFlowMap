// Package flowstore provides in-memory storage for network flows.
package flowstore

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kai/netflowmap/internal/geoip"
	"github.com/kai/netflowmap/internal/logging"
	"github.com/kai/netflowmap/internal/netflow"
)

// AggregatedFlow represents a flow with geographic information and aggregated stats.
type AggregatedFlow struct {
	// Key uniquely identifies this flow
	Key string `json:"key"`

	// Source information
	SourceID   string  `json:"source_id"`
	SourceName string  `json:"source_name"`
	SourceLat  float64 `json:"source_lat"`
	SourceLon  float64 `json:"source_lon"`

	// Local endpoint (internal IP)
	LocalIP   string `json:"local_ip"`
	LocalPort uint16 `json:"local_port"`

	// Remote endpoint (external IP with geo info)
	RemoteIP           string  `json:"remote_ip"`
	RemotePort         uint16  `json:"remote_port"`
	RemoteCity         string  `json:"remote_city,omitempty"`
	RemoteCountry      string  `json:"remote_country,omitempty"`
	RemoteLat          float64 `json:"remote_lat"`
	RemoteLon          float64 `json:"remote_lon"`
	RemoteASN          uint32  `json:"remote_asn,omitempty"`
	RemoteOrganization string  `json:"remote_organization,omitempty"`

	// Protocol
	Protocol     uint8  `json:"protocol"`
	ProtocolName string `json:"protocol_name"`

	// Traffic stats
	Bytes           uint64  `json:"bytes"`
	Packets         uint64  `json:"packets"`
	BytesPerSec     uint64  `json:"bytes_per_sec"`
	PacketCount     int     `json:"packet_count"`      // Number of flow records aggregated
	LastSampleBytes uint64  `json:"last_sample_bytes"` // Bytes from the last received sample
	SampleDuration  float64 `json:"sample_duration"`   // Duration in seconds over which BytesPerSec was calculated

	// Direction: true = inbound, false = outbound
	Inbound bool `json:"inbound"`

	// Timestamps
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// FortiGate address object name (if resolved)
	AddressObjectName string `json:"address_object_name,omitempty"`
}

// SourceInfo contains information about a NetFlow source.
type SourceInfo struct {
	ID        string
	Name      string
	Latitude  float64
	Longitude float64
}

// Store manages in-memory flow storage.
type Store struct {
	mu sync.RWMutex

	// flows maps source ID to a map of flow key to aggregated flow
	flows map[string]map[string]*AggregatedFlow

	// sources maps source ID to source info
	sources map[string]*SourceInfo

	// geoIP service for IP lookups
	geoIP *geoip.Service

	// displayTimeout is how long flows remain visible after last update
	displayTimeout time.Duration

	// Cleanup control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Subscribers for real-time updates
	subscribersMu sync.RWMutex
	subscribers   map[chan *AggregatedFlow]struct{}
}

// Config holds configuration for the store.
type Config struct {
	// DisplayTimeout is how long flows remain visible
	DisplayTimeout time.Duration
	// GeoIP is the GeoIP service for IP lookups
	GeoIP *geoip.Service
}

// New creates a new flow store.
func New(cfg Config) *Store {
	if cfg.DisplayTimeout == 0 {
		cfg.DisplayTimeout = 60 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Store{
		flows:          make(map[string]map[string]*AggregatedFlow),
		sources:        make(map[string]*SourceInfo),
		geoIP:          cfg.GeoIP,
		displayTimeout: cfg.DisplayTimeout,
		ctx:            ctx,
		cancel:         cancel,
		subscribers:    make(map[chan *AggregatedFlow]struct{}),
	}

	// Start cleanup goroutine
	s.wg.Add(1)
	go s.cleanupLoop()

	return s
}

// RegisterSource registers a NetFlow source.
func (s *Store) RegisterSource(info SourceInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sources[info.ID] = &info
	if _, exists := s.flows[info.ID]; !exists {
		s.flows[info.ID] = make(map[string]*AggregatedFlow)
	}

	logging.Info("registered flow source", "id", info.ID, "name", info.Name)
}

// AddFlows adds flows to the store.
func (s *Store) AddFlows(sourceID string, flows []netflow.Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sourceInfo := s.sources[sourceID]
	if sourceInfo == nil {
		// Try to find source by IP
		for _, info := range s.sources {
			if info.ID == sourceID {
				sourceInfo = info
				break
			}
		}
	}

	sourceFlows, exists := s.flows[sourceID]
	if !exists {
		sourceFlows = make(map[string]*AggregatedFlow)
		s.flows[sourceID] = sourceFlows
	}

	for _, flow := range flows {
		aggFlow := s.processFlow(flow, sourceInfo)
		if aggFlow == nil {
			continue
		}

		existing, exists := sourceFlows[aggFlow.Key]
		if exists {
			// Calculate bandwidth - prefer flow duration from NetFlow record if available
			if flow.DurationMs > 0 {
				// Use flow duration from NetFlow record (more accurate)
				existing.BytesPerSec = (aggFlow.Bytes * 1000) / uint64(flow.DurationMs)
				existing.SampleDuration = float64(flow.DurationMs) / 1000.0
			} else {
				// Fallback: Calculate delta-based bandwidth
				timeSinceLastSample := aggFlow.LastSeen.Sub(existing.LastSeen).Seconds()
				if timeSinceLastSample > 0 {
					existing.BytesPerSec = uint64(float64(aggFlow.Bytes) / timeSinceLastSample)
					existing.SampleDuration = timeSinceLastSample
				}
			}
			existing.LastSampleBytes = aggFlow.Bytes

			// Update existing flow
			existing.Bytes += aggFlow.Bytes
			existing.Packets += aggFlow.Packets
			existing.PacketCount++
			existing.LastSeen = aggFlow.LastSeen

			s.notifySubscribers(existing)
		} else {
			// New flow - calculate bandwidth from flow duration if available
			aggFlow.PacketCount = 1
			aggFlow.LastSampleBytes = aggFlow.Bytes

			if flow.DurationMs > 0 {
				// Use flow duration from NetFlow record
				aggFlow.BytesPerSec = (aggFlow.Bytes * 1000) / uint64(flow.DurationMs)
				aggFlow.SampleDuration = float64(flow.DurationMs) / 1000.0
			} else {
				// No duration available yet
				aggFlow.SampleDuration = 0
			}

			sourceFlows[aggFlow.Key] = aggFlow
			s.notifySubscribers(aggFlow)
		}
	}
}

// processFlow converts a netflow.Flow to an AggregatedFlow with geo info.
func (s *Store) processFlow(flow netflow.Flow, sourceInfo *SourceInfo) *AggregatedFlow {
	// Determine local and remote IPs
	var localIP, remoteIP net.IP
	var localPort, remotePort uint16
	var inbound bool

	srcPublic := geoip.IsPublicIP(flow.SrcIP)
	dstPublic := geoip.IsPublicIP(flow.DstIP)

	if srcPublic && !dstPublic {
		// Inbound: public source to private destination
		remoteIP = flow.SrcIP
		remotePort = flow.SrcPort
		localIP = flow.DstIP
		localPort = flow.DstPort
		inbound = true
	} else if !srcPublic && dstPublic {
		// Outbound: private source to public destination
		localIP = flow.SrcIP
		localPort = flow.SrcPort
		remoteIP = flow.DstIP
		remotePort = flow.DstPort
		inbound = false
	} else {
		// Both public or both private - skip for map visualization
		// (we can't meaningfully display this on the map)
		return nil
	}

	// Create flow key
	key := flowKey(sourceInfo.ID, localIP, localPort, remoteIP, remotePort, flow.Protocol, inbound)

	aggFlow := &AggregatedFlow{
		Key:          key,
		LocalIP:      localIP.String(),
		LocalPort:    localPort,
		RemoteIP:     remoteIP.String(),
		RemotePort:   remotePort,
		Protocol:     flow.Protocol,
		ProtocolName: netflow.ProtocolName(flow.Protocol),
		Bytes:        flow.Bytes,
		Packets:      flow.Packets,
		Inbound:      inbound,
		FirstSeen:    flow.Timestamp,
		LastSeen:     flow.Timestamp,
	}

	// Add source info
	if sourceInfo != nil {
		aggFlow.SourceID = sourceInfo.ID
		aggFlow.SourceName = sourceInfo.Name
		aggFlow.SourceLat = sourceInfo.Latitude
		aggFlow.SourceLon = sourceInfo.Longitude
	}

	// Lookup geo info for remote IP
	if s.geoIP != nil {
		loc, err := s.geoIP.Lookup(remoteIP.String())
		if err == nil && loc.Found {
			aggFlow.RemoteCity = loc.City
			aggFlow.RemoteCountry = loc.Country
			aggFlow.RemoteLat = loc.Latitude
			aggFlow.RemoteLon = loc.Longitude
			aggFlow.RemoteASN = loc.ASN
			aggFlow.RemoteOrganization = loc.ASOrganization
		}
	}

	return aggFlow
}

// flowKey generates a unique key for a flow.
func flowKey(sourceID string, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16, protocol uint8, inbound bool) string {
	direction := "out"
	if inbound {
		direction = "in"
	}
	return fmt.Sprintf("%s|%s:%d|%s:%d|%d|%s",
		sourceID, localIP.String(), localPort,
		remoteIP.String(), remotePort, protocol, direction)
}

// GetFlows returns all active flows for a source.
func (s *Store) GetFlows(sourceID string) []*AggregatedFlow {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sourceFlows, exists := s.flows[sourceID]
	if !exists {
		return nil
	}

	result := make([]*AggregatedFlow, 0, len(sourceFlows))
	for _, flow := range sourceFlows {
		result = append(result, flow)
	}

	return result
}

// GetAllFlows returns all active flows from all sources.
func (s *Store) GetAllFlows() []*AggregatedFlow {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*AggregatedFlow
	for _, sourceFlows := range s.flows {
		for _, flow := range sourceFlows {
			result = append(result, flow)
		}
	}

	return result
}

// GetSources returns all registered sources.
func (s *Store) GetSources() []SourceInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]SourceInfo, 0, len(s.sources))
	for _, info := range s.sources {
		result = append(result, *info)
	}

	return result
}

// Subscribe returns a channel that receives flow updates.
func (s *Store) Subscribe() chan *AggregatedFlow {
	ch := make(chan *AggregatedFlow, 100)

	s.subscribersMu.Lock()
	s.subscribers[ch] = struct{}{}
	s.subscribersMu.Unlock()

	return ch
}

// Unsubscribe removes a subscriber.
func (s *Store) Unsubscribe(ch chan *AggregatedFlow) {
	s.subscribersMu.Lock()
	defer s.subscribersMu.Unlock()

	// Only close if still registered (not already closed by Close())
	if _, exists := s.subscribers[ch]; exists {
		delete(s.subscribers, ch)
		close(ch)
	}
}

// notifySubscribers sends a flow update to all subscribers.
func (s *Store) notifySubscribers(flow *AggregatedFlow) {
	s.subscribersMu.RLock()
	defer s.subscribersMu.RUnlock()

	for ch := range s.subscribers {
		select {
		case ch <- flow:
		default:
			// Channel full, skip
		}
	}
}

// cleanupLoop periodically removes expired flows.
func (s *Store) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

// cleanup removes expired flows.
func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	totalRemoved := 0

	for sourceID, sourceFlows := range s.flows {
		for key, flow := range sourceFlows {
			if now.Sub(flow.LastSeen) > s.displayTimeout {
				delete(sourceFlows, key)
				totalRemoved++
			}
		}

		// Clean up empty source maps
		if len(sourceFlows) == 0 {
			delete(s.flows, sourceID)
		}
	}

	if totalRemoved > 0 {
		logging.Debug("cleaned up expired flows", "count", totalRemoved)
	}
}

// Stats returns store statistics.
func (s *Store) Stats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := StoreStats{
		SourceCount: len(s.sources),
	}

	for _, sourceFlows := range s.flows {
		stats.FlowCount += len(sourceFlows)
	}

	s.subscribersMu.RLock()
	stats.SubscriberCount = len(s.subscribers)
	s.subscribersMu.RUnlock()

	return stats
}

// StoreStats holds store statistics.
type StoreStats struct {
	SourceCount     int
	FlowCount       int
	SubscriberCount int
}

// Close stops the store and releases resources.
func (s *Store) Close() {
	s.cancel()
	s.wg.Wait()

	// Close all subscriber channels
	s.subscribersMu.Lock()
	for ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = make(map[chan *AggregatedFlow]struct{})
	s.subscribersMu.Unlock()

	logging.Info("flow store closed")
}

// SetAddressObjectName sets the FortiGate address object name for a flow.
func (s *Store) SetAddressObjectName(sourceID, remoteIP, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sourceFlows, exists := s.flows[sourceID]
	if !exists {
		return
	}

	for _, flow := range sourceFlows {
		if flow.RemoteIP == remoteIP {
			flow.AddressObjectName = name
		}
	}
}

// FlowCount returns the number of flows for a source.
func (s *Store) FlowCount(sourceID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if sourceFlows, exists := s.flows[sourceID]; exists {
		return len(sourceFlows)
	}
	return 0
}

// TotalFlowCount returns the total number of flows across all sources.
func (s *Store) TotalFlowCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := 0
	for _, sourceFlows := range s.flows {
		total += len(sourceFlows)
	}
	return total
}

