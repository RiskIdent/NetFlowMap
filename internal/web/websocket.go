package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kai/netflowmap/internal/auth"
	"github.com/kai/netflowmap/internal/flowstore"
	"github.com/kai/netflowmap/internal/logging"
)

// createWebSocketUpgrader creates a WebSocket upgrader with proper origin validation.
func (s *Server) createWebSocketUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")

			// No origin header - allow (same-origin request)
			if origin == "" {
				return true
			}

			// If allowed origins are configured, check against them
			if len(s.allowedOrigins) > 0 {
				if s.allowedOrigins[strings.ToLower(origin)] {
					return true
				}
				logging.Warning("WebSocket connection rejected: origin not allowed",
					"origin", origin)
				return false
			}

			// No allowed origins configured - check same-origin
			host := r.Host
			if strings.Contains(origin, host) {
				return true
			}

			logging.Warning("WebSocket connection rejected: cross-origin without allowed_origins config",
				"origin", origin,
				"host", host)
			return false
		},
	}
}

// WebSocketHub manages WebSocket connections.
type WebSocketHub struct {
	mu         sync.RWMutex
	clients    map[*WebSocketClient]struct{}
	broadcast  chan any
	register   chan *WebSocketClient
	unregister chan *WebSocketClient
	done       chan struct{}
}

// WebSocketClient represents a connected WebSocket client.
type WebSocketClient struct {
	hub  *WebSocketHub
	conn *websocket.Conn
	send chan []byte

	// User role for data filtering
	userRole auth.Role

	// Client-specific filters
	filterMu   sync.RWMutex
	sourceID   string
	direction  string
	textFilter string
	minTraffic uint64 // Minimum traffic threshold in bytes (0 = off)
	maxTraffic uint64 // Maximum traffic threshold in bytes (0 = off/no limit)
}

// WebSocketMessage is the message format for WebSocket communication.
type WebSocketMessage struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// InitialFlowsMessage contains the initial flows data with metadata.
type InitialFlowsMessage struct {
	Flows     any  `json:"flows"`
	Total     int  `json:"total"`
	Displayed int  `json:"displayed"`
	Limited   bool `json:"limited"`
}

// ClientFilterMessage represents a filter update from the client.
type ClientFilterMessage struct {
	Source     string `json:"source"`
	Direction  string `json:"direction"`
	Filter     string `json:"filter"`
	MinTraffic uint64 `json:"minTraffic"` // Minimum traffic threshold in bytes (0 = off)
	MaxTraffic uint64 `json:"maxTraffic"` // Maximum traffic threshold in bytes (0 = off/no limit)
}

// NewWebSocketHub creates a new WebSocket hub.
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients:    make(map[*WebSocketClient]struct{}),
		broadcast:  make(chan any, 256),
		register:   make(chan *WebSocketClient),
		unregister: make(chan *WebSocketClient),
		done:       make(chan struct{}),
	}
}

// Run starts the WebSocket hub.
func (h *WebSocketHub) Run() {
	for {
		select {
		case <-h.done:
			h.mu.Lock()
			for client := range h.clients {
				close(client.send)
				delete(h.clients, client)
			}
			h.mu.Unlock()
			return

		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = struct{}{}
			h.mu.Unlock()
			logging.Debug("WebSocket client connected", "clients", h.ClientCount())

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			logging.Debug("WebSocket client disconnected", "clients", h.ClientCount())

		case message := <-h.broadcast:
			h.broadcastMessage(message)
		}
	}
}

// broadcastMessage sends a message to all connected clients.
func (h *WebSocketHub) broadcastMessage(data any) {
	msg := WebSocketMessage{
		Type: "flow",
		Data: data,
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		logging.Warning("failed to marshal WebSocket message", "error", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		select {
		case client.send <- jsonData:
		default:
			// Client buffer full, skip
		}
	}
}

// Broadcast sends a message to all connected clients.
func (h *WebSocketHub) Broadcast(data any) {
	select {
	case h.broadcast <- data:
	default:
		// Broadcast buffer full, skip
	}
}

// BroadcastJSON sends a pre-formatted message to all connected clients.
func (h *WebSocketHub) BroadcastJSON(msg WebSocketMessage) {
	jsonData, err := json.Marshal(msg)
	if err != nil {
		logging.Warning("failed to marshal WebSocket message", "error", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		select {
		case client.send <- jsonData:
		default:
			// Client buffer full, skip
		}
	}
}

// Close stops the WebSocket hub.
func (h *WebSocketHub) Close() {
	close(h.done)
}

// ClientCount returns the number of connected clients.
func (h *WebSocketHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// GetClients returns a slice of all connected clients.
func (h *WebSocketHub) GetClients() []*WebSocketClient {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clients := make([]*WebSocketClient, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	return clients
}

// handleWebSocket handles WebSocket upgrade requests.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Get user role from context (set by auth middleware)
	user := auth.GetUserFromContext(r.Context())

	// Create upgrader with origin validation
	upgrader := s.createWebSocketUpgrader()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logging.Warning("WebSocket upgrade failed", "error", err)
		return
	}

	client := &WebSocketClient{
		hub:      s.wsHub,
		conn:     conn,
		send:     make(chan []byte, 256),
		userRole: user.Role,
	}

	s.wsHub.register <- client

	// Start client goroutines
	go client.writePump()
	go client.readPump()

	// Send initial data
	if s.flowStore != nil {
		flows := s.flowStore.GetAllFlows()
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
		
		// Sort and limit flows
		flows = sortAndLimitFlows(flows, s.maxDisplayFlows)
		
		initialData := InitialFlowsMessage{
			Flows:     flows,
			Total:     totalCount,
			Displayed: len(flows),
			Limited:   len(flows) < totalCount,
		}
		
		initialMsg := WebSocketMessage{
			Type: "initial",
			Data: initialData,
		}
		if jsonData, err := json.Marshal(initialMsg); err == nil {
			select {
			case client.send <- jsonData:
			default:
			}
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection.
func (c *WebSocketClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump pumps messages from the WebSocket connection to the hub.
func (c *WebSocketClient) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(4096)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logging.Debug("WebSocket read error", "error", err)
			}
			break
		}

		// Parse incoming message
		c.handleMessage(message)
	}
}

// handleMessage processes incoming WebSocket messages from the client.
func (c *WebSocketClient) handleMessage(message []byte) {
	var msg WebSocketMessage
	if err := json.Unmarshal(message, &msg); err != nil {
		logging.Debug("failed to parse WebSocket message", "error", err)
		return
	}

	switch msg.Type {
	case "filter":
		// Parse filter data
		filterData, err := json.Marshal(msg.Data)
		if err != nil {
			return
		}

		var filter ClientFilterMessage
		if err := json.Unmarshal(filterData, &filter); err != nil {
			logging.Debug("failed to parse filter message", "error", err)
			return
		}

		// Update client filters
		c.filterMu.Lock()
		c.sourceID = filter.Source
		c.direction = filter.Direction
		c.textFilter = filter.Filter
		c.minTraffic = filter.MinTraffic
		c.maxTraffic = filter.MaxTraffic
		c.filterMu.Unlock()

		logging.Debug("client filter updated",
			"source", filter.Source,
			"direction", filter.Direction,
			"filter", filter.Filter,
			"minTraffic", filter.MinTraffic,
			"maxTraffic", filter.MaxTraffic)
	}
}

// GetFilters returns the current filter settings for this client.
func (c *WebSocketClient) GetFilters() (sourceID, direction, textFilter string, minTraffic, maxTraffic uint64) {
	c.filterMu.RLock()
	defer c.filterMu.RUnlock()
	return c.sourceID, c.direction, c.textFilter, c.minTraffic, c.maxTraffic
}

// GetUserRole returns the user role for this client.
func (c *WebSocketClient) GetUserRole() auth.Role {
	return c.userRole
}

// BroadcastFlowUpdate is a helper for the flow store to send updates.
func (s *Server) BroadcastFlowUpdate(flow *flowstore.AggregatedFlow) {
	s.wsHub.Broadcast(flow)
}

