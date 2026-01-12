package netflow

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/RiskIdent/NetFlowMap/internal/logging"
)

// FlowHandler is a function that processes received flows.
type FlowHandler func(flows []Flow)

// Collector receives and processes NetFlow v9 packets.
type Collector struct {
	mu sync.RWMutex

	port      int
	conn      *net.UDPConn
	parser    *Parser
	templates *TemplateCache
	handler   FlowHandler

	// Sampling info per source IP
	samplingInfo map[string]*SamplingInfo

	// Stats
	packetsReceived uint64
	flowsReceived   uint64
	parseErrors     uint64

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// CollectorConfig holds configuration for the collector.
type CollectorConfig struct {
	// Port is the UDP port to listen on
	Port int
	// Handler is called for each batch of received flows
	Handler FlowHandler
}

// NewCollector creates a new NetFlow collector.
func NewCollector(cfg CollectorConfig) *Collector {
	templates := NewTemplateCache()

	return &Collector{
		port:         cfg.Port,
		templates:    templates,
		parser:       NewParser(templates),
		handler:      cfg.Handler,
		samplingInfo: make(map[string]*SamplingInfo),
	}
}

// Start begins listening for NetFlow packets.
func (c *Collector) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return fmt.Errorf("collector already running")
	}

	addr := &net.UDPAddr{
		Port: c.port,
		IP:   net.IPv4zero,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port %d: %w", c.port, err)
	}

	c.conn = conn
	c.ctx, c.cancel = context.WithCancel(context.Background())

	// Set read buffer size
	if err := conn.SetReadBuffer(8 * 1024 * 1024); err != nil {
		logging.Warning("failed to set UDP read buffer", "error", err)
	}

	// Start receiver goroutine
	c.wg.Add(1)
	go c.receiveLoop()

	// Start template cleanup goroutine
	c.wg.Add(1)
	go c.templateCleanupLoop()

	logging.Info("NetFlow collector started", "port", c.port)
	return nil
}

// Stop stops the collector.
func (c *Collector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	c.cancel()
	c.conn.Close()
	c.wg.Wait()

	c.conn = nil
	logging.Info("NetFlow collector stopped")
	return nil
}

// receiveLoop continuously receives and processes NetFlow packets.
func (c *Collector) receiveLoop() {
	defer c.wg.Done()

	buf := make([]byte, 65535)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Set read deadline to allow checking context
		c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, remoteAddr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-c.ctx.Done():
				return
			default:
				logging.Debug("UDP read error", "error", err)
				continue
			}
		}

		c.mu.Lock()
		c.packetsReceived++
		c.mu.Unlock()

		sourceIP := remoteAddr.IP.String()

		// Parse packet with options support
		result, err := c.parser.ParsePacketWithOptions(buf[:n], sourceIP)
		if err != nil {
			c.mu.Lock()
			c.parseErrors++
			c.mu.Unlock()
			logging.Debug("failed to parse NetFlow packet", "source", sourceIP, "error", err)
			continue
		}

		// Handle sampling info if present
		if result.SamplingInfo != nil && result.SamplingInfo.Interval > 0 {
			c.mu.Lock()
			existingInfo := c.samplingInfo[sourceIP]
			if existingInfo == nil || existingInfo.Interval != result.SamplingInfo.Interval {
				c.samplingInfo[sourceIP] = result.SamplingInfo
				logging.Info("detected NetFlow sampling",
					"source", sourceIP,
					"interval", result.SamplingInfo.Interval,
					"algorithm", result.SamplingInfo.Algorithm,
					"mode", result.SamplingInfo.Mode)
			}
			c.mu.Unlock()
		}

		if len(result.Flows) > 0 {
			c.mu.Lock()
			c.flowsReceived += uint64(len(result.Flows))
			c.mu.Unlock()

			// Call handler
			if c.handler != nil {
				c.handler(result.Flows)
			}

			logging.Trace("received flows", "source", sourceIP, "count", len(result.Flows))
		}
	}
}

// templateCleanupLoop periodically cleans up expired templates.
func (c *Collector) templateCleanupLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			removed := c.templates.Cleanup()
			if removed > 0 {
				logging.Debug("cleaned up expired templates", "count", removed)
			}
		}
	}
}

// Stats returns collector statistics.
func (c *Collector) Stats() CollectorStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CollectorStats{
		PacketsReceived: c.packetsReceived,
		FlowsReceived:   c.flowsReceived,
		ParseErrors:     c.parseErrors,
		TemplateCount:   c.templates.Count(),
	}
}

// CollectorStats holds collector statistics.
type CollectorStats struct {
	PacketsReceived uint64
	FlowsReceived   uint64
	ParseErrors     uint64
	TemplateCount   int
}

// IsRunning returns true if the collector is running.
func (c *Collector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil
}

// Port returns the port the collector is listening on.
func (c *Collector) Port() int {
	return c.port
}

// TemplateCache returns the template cache for inspection.
func (c *Collector) TemplateCache() *TemplateCache {
	return c.templates
}

// GetSamplingInfo returns the sampling info for a specific source IP.
func (c *Collector) GetSamplingInfo(sourceIP string) *SamplingInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.samplingInfo[sourceIP]
}

// GetAllSamplingInfo returns sampling info for all sources.
func (c *Collector) GetAllSamplingInfo() map[string]*SamplingInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*SamplingInfo)
	for k, v := range c.samplingInfo {
		result[k] = v
	}
	return result
}

