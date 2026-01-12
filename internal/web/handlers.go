package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/kai/netflowmap/internal/auth"
	"github.com/kai/netflowmap/internal/flowstore"
	"github.com/kai/netflowmap/internal/logging"
	"github.com/kai/netflowmap/internal/netflow"
)

// APIResponse is a generic API response wrapper.
type APIResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// SourceResponse represents a NetFlow source in API responses.
type SourceResponse struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	FlowCount int     `json:"flow_count"`
}

// StatsResponse represents system statistics.
type StatsResponse struct {
	Sources         int `json:"sources"`
	TotalFlows      int `json:"total_flows"`
	DisplayedFlows  int `json:"displayed_flows"`
	WebSocketConns  int `json:"websocket_connections"`
	FortiGateCaches int `json:"fortigate_caches"`
}

// FlowsResponse wraps flows with metadata.
type FlowsResponse struct {
	Flows      []*flowstore.AggregatedFlow `json:"flows"`
	Total      int                         `json:"total"`
	Displayed  int                         `json:"displayed"`
	Limited    bool                        `json:"limited"`
	MaxDisplay int                         `json:"max_display"`
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeSuccess writes a successful JSON response.
func writeSuccess(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

// writeError writes an error JSON response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, APIResponse{
		Success: false,
		Error:   message,
	})
}

// handleHealth returns a simple health check response.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeSuccess(w, map[string]string{"status": "ok"})
}

// handleGetSources returns all registered NetFlow sources.
func (s *Server) handleGetSources(w http.ResponseWriter, r *http.Request) {
	if s.flowStore == nil {
		writeError(w, http.StatusServiceUnavailable, "flow store not available")
		return
	}

	sources := s.flowStore.GetSources()
	response := make([]SourceResponse, 0, len(sources))

	for _, src := range sources {
		response = append(response, SourceResponse{
			ID:        src.ID,
			Name:      src.Name,
			Latitude:  src.Latitude,
			Longitude: src.Longitude,
			FlowCount: s.flowStore.FlowCount(src.ID),
		})
	}

	writeSuccess(w, response)
}

// handleGetFlows returns flows, optionally filtered.
func (s *Server) handleGetFlows(w http.ResponseWriter, r *http.Request) {
	if s.flowStore == nil {
		writeError(w, http.StatusServiceUnavailable, "flow store not available")
		return
	}

	// Get user role from context
	user := auth.GetUserFromContext(r.Context())

	// Parse query parameters
	sourceID := r.URL.Query().Get("source")
	direction := r.URL.Query().Get("direction") // "in", "out", or "" for all
	filter := r.URL.Query().Get("filter")       // IP/subnet filter

	var flows []*flowstore.AggregatedFlow

	if sourceID != "" {
		flows = s.flowStore.GetFlows(sourceID)
	} else {
		flows = s.flowStore.GetAllFlows()
	}

	// Apply filters
	flows = filterFlows(flows, direction, filter)
	totalCount := len(flows)

	// Enrich with FortiGate object names
	if s.fortigate != nil {
		for _, flow := range flows {
			if flow.AddressObjectName == "" {
				if name, found := s.fortigate.LookupIP(flow.SourceID, flow.RemoteIP); found {
					flow.AddressObjectName = name
				}
			}
		}
	}

	// Sort by traffic (bytes_per_sec) descending and limit
	flows = sortAndLimitFlows(flows, s.maxDisplayFlows)

	// Apply role-based filtering
	flows = filterFlowsForRole(flows, user.Role)

	response := FlowsResponse{
		Flows:      flows,
		Total:      totalCount,
		Displayed:  len(flows),
		Limited:    len(flows) < totalCount,
		MaxDisplay: s.maxDisplayFlows,
	}

	writeSuccess(w, response)
}

// handleGetFlowsBySource returns flows for a specific source.
func (s *Server) handleGetFlowsBySource(w http.ResponseWriter, r *http.Request) {
	if s.flowStore == nil {
		writeError(w, http.StatusServiceUnavailable, "flow store not available")
		return
	}

	// Get user role from context
	user := auth.GetUserFromContext(r.Context())

	sourceID := chi.URLParam(r, "sourceID")
	if sourceID == "" {
		writeError(w, http.StatusBadRequest, "source ID required")
		return
	}

	direction := r.URL.Query().Get("direction")
	filter := r.URL.Query().Get("filter")

	flows := s.flowStore.GetFlows(sourceID)
	flows = filterFlows(flows, direction, filter)
	totalCount := len(flows)

	// Enrich with FortiGate object names
	if s.fortigate != nil {
		for _, flow := range flows {
			if flow.AddressObjectName == "" {
				if name, found := s.fortigate.LookupIP(flow.SourceID, flow.RemoteIP); found {
					flow.AddressObjectName = name
				}
			}
		}
	}

	// Sort by traffic and limit
	flows = sortAndLimitFlows(flows, s.maxDisplayFlows)

	// Apply role-based filtering
	flows = filterFlowsForRole(flows, user.Role)

	response := FlowsResponse{
		Flows:      flows,
		Total:      totalCount,
		Displayed:  len(flows),
		Limited:    len(flows) < totalCount,
		MaxDisplay: s.maxDisplayFlows,
	}

	writeSuccess(w, response)
}

// handleGetStats returns system statistics.
func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := StatsResponse{}

	if s.flowStore != nil {
		storeStats := s.flowStore.Stats()
		stats.Sources = storeStats.SourceCount
		stats.TotalFlows = storeStats.FlowCount
	}

	stats.WebSocketConns = s.wsHub.ClientCount()

	if s.fortigate != nil {
		stats.FortiGateCaches = s.fortigate.SourceCount()
	}

	writeSuccess(w, stats)
}

// SamplingInfoResponse represents sampling information for a source.
type SamplingInfoResponse struct {
	SourceID   string `json:"source_id"`
	SourceIP   string `json:"source_ip"`
	SourceName string `json:"source_name"`
	Interval   uint32 `json:"interval"`
	Algorithm  uint8  `json:"algorithm"`
	Mode       uint8  `json:"mode"`
	FromConfig bool   `json:"from_config"` // true if from config.yml, false if from NetFlow Options
}

// handleGetSampling returns sampling information for all sources.
func (s *Server) handleGetSampling(w http.ResponseWriter, r *http.Request) {
	response := make([]SamplingInfoResponse, 0)

	// Get detected sampling info from collector
	var detectedSampling map[string]*netflow.SamplingInfo
	if s.collector != nil {
		detectedSampling = s.collector.GetAllSamplingInfo()
	}

	// Build response for each configured source
	if s.appConfig != nil {
		for _, src := range s.appConfig.Sources {
			info := SamplingInfoResponse{
				SourceID:   src.ID,
				SourceIP:   src.SourceIP,
				SourceName: src.Name,
				Interval:   1, // default
				FromConfig: false,
			}

			// Check if we have detected sampling for this source
			if detectedSampling != nil {
				if detected, ok := detectedSampling[src.SourceIP]; ok && detected != nil && detected.Interval > 0 {
					info.Interval = detected.Interval
					info.Algorithm = detected.Algorithm
					info.Mode = detected.Mode
					info.FromConfig = false
				}
			}

			// If no detected sampling, use config fallback
			if info.Interval <= 1 && src.SamplingInterval > 1 {
				info.Interval = uint32(src.SamplingInterval)
				info.FromConfig = true
			}

			// Only include if sampling interval is > 1
			if info.Interval > 1 {
				response = append(response, info)
			}
		}
	}

	writeSuccess(w, response)
}

// filterFlows applies direction and text filters to flows.
func filterFlows(flows []*flowstore.AggregatedFlow, direction, filter string) []*flowstore.AggregatedFlow {
	if direction == "" && filter == "" {
		return flows
	}

	result := make([]*flowstore.AggregatedFlow, 0, len(flows))

	for _, flow := range flows {
		// Direction filter
		if direction != "" {
			if direction == "in" && !flow.Inbound {
				continue
			}
			if direction == "out" && flow.Inbound {
				continue
			}
		}

		// Text/IP filter (fuzzy)
		if filter != "" {
			if !matchesFilter(flow, filter) {
				continue
			}
		}

		result = append(result, flow)
	}

	return result
}

// sortAndLimitFlows sorts flows by traffic (descending) and limits to maxFlows.
func sortAndLimitFlows(flows []*flowstore.AggregatedFlow, maxFlows int) []*flowstore.AggregatedFlow {
	if len(flows) == 0 {
		return flows
	}

	// Sort by bytes_per_sec descending (highest traffic first)
	sort.Slice(flows, func(i, j int) bool {
		// Primary sort: bytes_per_sec
		if flows[i].BytesPerSec != flows[j].BytesPerSec {
			return flows[i].BytesPerSec > flows[j].BytesPerSec
		}
		// Secondary sort: total bytes
		return flows[i].Bytes > flows[j].Bytes
	})

	// Limit to maxFlows
	if maxFlows > 0 && len(flows) > maxFlows {
		return flows[:maxFlows]
	}

	return flows
}

// matchesFilter checks if a flow matches a filter string.
// Supports IP addresses, subnets, ports, and fuzzy text matching.
func matchesFilter(flow *flowstore.AggregatedFlow, filter string) bool {
	filter = strings.ToLower(filter)

	// Check various fields
	if strings.Contains(strings.ToLower(flow.LocalIP), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(flow.RemoteIP), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(flow.RemoteCity), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(flow.RemoteCountry), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(flow.RemoteOrganization), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(flow.ProtocolName), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(flow.AddressObjectName), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(flow.SourceName), filter) {
		return true
	}

	// Temporary debug logging (use trace level to avoid spam)
	logging.Trace("flow did not match filter",
		"filter", filter,
		"remote_ip", flow.RemoteIP,
		"remote_city", flow.RemoteCity,
		"remote_country", flow.RemoteCountry,
		"remote_org", flow.RemoteOrganization,
		"source_name", flow.SourceName)

	return false
}

// filterFlowsByTraffic filters flows based on min/max traffic thresholds.
// It aggregates bytes per remote IP and filters flows accordingly.
func filterFlowsByTraffic(flows []*flowstore.AggregatedFlow, minTraffic, maxTraffic uint64) []*flowstore.AggregatedFlow {
	if minTraffic == 0 && maxTraffic == 0 {
		return flows // No filtering needed
	}

	// First, calculate total bytes per remote IP
	remoteIPTotals := make(map[string]uint64)
	for _, flow := range flows {
		remoteIPTotals[flow.RemoteIP] += flow.Bytes
	}

	// Then filter flows based on their remote IP's total traffic
	var result []*flowstore.AggregatedFlow
	for _, flow := range flows {
		total := remoteIPTotals[flow.RemoteIP]

		// Check min threshold
		if minTraffic > 0 && total < minTraffic {
			continue
		}

		// Check max threshold
		if maxTraffic > 0 && total > maxTraffic {
			continue
		}

		result = append(result, flow)
	}

	return result
}

// filterFlowsForRole filters flow data based on user role.
// It creates copies of flows to avoid modifying the originals.
func filterFlowsForRole(flows []*flowstore.AggregatedFlow, role auth.Role) []*flowstore.AggregatedFlow {
	if role == auth.RoleAdmin {
		// Admins see everything
		return flows
	}

	result := make([]*flowstore.AggregatedFlow, 0, len(flows))

	for _, flow := range flows {
		// Create a copy of the flow
		filtered := *flow

		localIP, remoteIP, clearLocalPort, clearRemotePort, hideRemoteLocation, hideRemoteDetails := auth.FilterFlowForRole(
			role, flow.LocalIP, flow.RemoteIP,
		)

		filtered.LocalIP = localIP
		filtered.RemoteIP = remoteIP

		if clearLocalPort {
			filtered.LocalPort = 0
		}

		if clearRemotePort {
			filtered.RemotePort = 0
		}

		if hideRemoteLocation {
			filtered.RemoteLat = 0
			filtered.RemoteLon = 0
			filtered.RemoteCity = ""
			filtered.RemoteCountry = ""
		}

		if hideRemoteDetails {
			filtered.RemoteASN = 0
			filtered.RemoteOrganization = ""
			filtered.AddressObjectName = ""
		}

		// Anonymous users don't see traffic data
		if role == auth.RoleAnonymous {
			filtered.Bytes = 0
			filtered.Packets = 0
			filtered.BytesPerSec = 0
			filtered.LastSampleBytes = 0
			filtered.SampleDuration = 0
		}

		result = append(result, &filtered)
	}

	return result
}

