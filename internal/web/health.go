package web

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kai/netflowmap/internal/auth"
)

// DetailedHealthResponse contains comprehensive health statistics.
type DetailedHealthResponse struct {
	Version   string              `json:"version"`
	Uptime    string              `json:"uptime"`
	StartTime string              `json:"start_time"`
	NetFlow   NetFlowHealthStats  `json:"netflow"`
	Sources   []SourceHealthStats `json:"sources"`
	Runtime   RuntimeHealthStats  `json:"runtime"`
	System    SystemHealthStats   `json:"system"`
}

// NetFlowHealthStats contains NetFlow collector statistics.
type NetFlowHealthStats struct {
	ConnectedClients int    `json:"connected_clients"`
	TotalFlows       int    `json:"total_flows"`
	PacketsReceived  uint64 `json:"packets_received"`
	FlowsReceived    uint64 `json:"flows_received"`
	ParseErrors      uint64 `json:"parse_errors"`
	TemplateCount    int    `json:"template_count"`
}

// SourceHealthStats contains per-source statistics.
type SourceHealthStats struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	FlowCount      int    `json:"flow_count"`
	AddressObjects int    `json:"address_objects"`
}

// RuntimeHealthStats contains Go runtime statistics.
type RuntimeHealthStats struct {
	GoVersion    string `json:"go_version"`
	NumCPU       int    `json:"num_cpu"`
	NumGoroutine int    `json:"num_goroutine"`
	MemAlloc     uint64 `json:"mem_alloc"`
	MemAllocMB   string `json:"mem_alloc_mb"`
	MemSys       uint64 `json:"mem_sys"`
	MemSysMB     string `json:"mem_sys_mb"`
	HeapInuse    uint64 `json:"heap_inuse"`
	HeapInuseMB  string `json:"heap_inuse_mb"`
	NumGC        uint32 `json:"num_gc"`
}

// SystemHealthStats contains system-level statistics.
type SystemHealthStats struct {
	CPUUsagePercent    float64 `json:"cpu_usage_percent"`
	MemoryUsedBytes    uint64  `json:"memory_used_bytes"`
	MemoryTotalBytes   uint64  `json:"memory_total_bytes"`
	MemoryUsedMB       string  `json:"memory_used_mb"`
	MemoryTotalMB      string  `json:"memory_total_mb"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`
	Available          bool    `json:"available"`
}

var serverStartTime = time.Now()

// Version is set by the main package at startup.
var Version = "unknown"

// handleDetailedHealth returns comprehensive health statistics (admin only).
func (s *Server) handleDetailedHealth(w http.ResponseWriter, r *http.Request) {
	// Check if user is admin
	user := auth.GetUserFromContext(r.Context())
	if user.Role != auth.RoleAdmin {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	response := DetailedHealthResponse{
		Version:   Version,
		Uptime:    formatDuration(time.Since(serverStartTime)),
		StartTime: serverStartTime.Format(time.RFC3339),
	}

	// NetFlow stats
	response.NetFlow.ConnectedClients = s.wsHub.ClientCount()

	if s.flowStore != nil {
		storeStats := s.flowStore.Stats()
		response.NetFlow.TotalFlows = storeStats.FlowCount
	}

	if s.collector != nil {
		collectorStats := s.collector.Stats()
		response.NetFlow.PacketsReceived = collectorStats.PacketsReceived
		response.NetFlow.FlowsReceived = collectorStats.FlowsReceived
		response.NetFlow.ParseErrors = collectorStats.ParseErrors
		response.NetFlow.TemplateCount = collectorStats.TemplateCount
	}

	// Per-source stats
	if s.appConfig != nil {
		for _, src := range s.appConfig.Sources {
			srcStats := SourceHealthStats{
				ID:   src.ID,
				Name: src.Name,
			}

			if s.flowStore != nil {
				srcStats.FlowCount = s.flowStore.FlowCount(src.ID)
			}

			if s.fortigate != nil {
				srcStats.AddressObjects = s.fortigate.ObjectCount(src.ID)
			}

			response.Sources = append(response.Sources, srcStats)
		}
	}

	// Go runtime stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	response.Runtime = RuntimeHealthStats{
		GoVersion:    runtime.Version(),
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		MemAlloc:     memStats.Alloc,
		MemAllocMB:   fmt.Sprintf("%.1f MB", float64(memStats.Alloc)/1024/1024),
		MemSys:       memStats.Sys,
		MemSysMB:     fmt.Sprintf("%.1f MB", float64(memStats.Sys)/1024/1024),
		HeapInuse:    memStats.HeapInuse,
		HeapInuseMB:  fmt.Sprintf("%.1f MB", float64(memStats.HeapInuse)/1024/1024),
		NumGC:        memStats.NumGC,
	}

	// System stats (Linux only, reads from /proc)
	response.System = getSystemStats()

	writeSuccess(w, response)
}

// getSystemStats reads system statistics from /proc (Linux only).
func getSystemStats() SystemHealthStats {
	stats := SystemHealthStats{Available: false}

	// Read memory info
	memInfo, err := readMemInfo()
	if err == nil {
		stats.Available = true
		stats.MemoryTotalBytes = memInfo.total
		stats.MemoryUsedBytes = memInfo.used
		stats.MemoryTotalMB = fmt.Sprintf("%.0f MB", float64(memInfo.total)/1024/1024)
		stats.MemoryUsedMB = fmt.Sprintf("%.0f MB", float64(memInfo.used)/1024/1024)
		if memInfo.total > 0 {
			stats.MemoryUsagePercent = float64(memInfo.used) / float64(memInfo.total) * 100
		}
	}

	// Read CPU usage
	cpuPercent, err := readCPUUsage()
	if err == nil {
		stats.Available = true
		stats.CPUUsagePercent = cpuPercent
	}

	return stats
}

type memInfoData struct {
	total uint64
	used  uint64
}

// readMemInfo reads memory information from /proc/meminfo.
func readMemInfo() (memInfoData, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return memInfoData{}, err
	}
	defer file.Close()

	var total, available uint64
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		// Values in /proc/meminfo are in KB
		switch fields[0] {
		case "MemTotal:":
			total = value * 1024
		case "MemAvailable:":
			available = value * 1024
		}
	}

	return memInfoData{
		total: total,
		used:  total - available,
	}, nil
}

// CPU usage tracking
var (
	lastCPUTotal uint64
	lastCPUIdle  uint64
	lastCPUTime  time.Time
)

// readCPUUsage calculates CPU usage from /proc/stat.
func readCPUUsage() (float64, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0, fmt.Errorf("invalid cpu line")
			}

			var total, idle uint64
			for i := 1; i < len(fields); i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				total += val
				if i == 4 { // idle is the 4th value (index 4 in fields, 3 in cpu values)
					idle = val
				}
			}

			// Calculate delta
			now := time.Now()
			if lastCPUTime.IsZero() {
				lastCPUTotal = total
				lastCPUIdle = idle
				lastCPUTime = now
				return 0, nil // First call, no data yet
			}

			totalDelta := float64(total - lastCPUTotal)
			idleDelta := float64(idle - lastCPUIdle)

			lastCPUTotal = total
			lastCPUIdle = idle
			lastCPUTime = now

			if totalDelta == 0 {
				return 0, nil
			}

			cpuPercent := (1.0 - idleDelta/totalDelta) * 100
			if cpuPercent < 0 {
				cpuPercent = 0
			}
			if cpuPercent > 100 {
				cpuPercent = 100
			}

			return cpuPercent, nil
		}
	}

	return 0, fmt.Errorf("cpu line not found")
}

// formatDuration formats a duration into a human-readable string.
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

