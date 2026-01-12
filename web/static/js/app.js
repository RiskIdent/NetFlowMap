// NetFlowMap Frontend Application

class NetFlowMap {
    constructor() {
        this.map = null;
        this.ws = null;
        this.flows = new Map(); // key -> flow data
        this.flowLines = new Map(); // key -> Leaflet polyline
        this.remoteMarkers = new Map(); // remoteIP -> Leaflet marker
        this.sourceMarkers = new Map(); // sourceID -> Leaflet marker
        this.sources = [];
        this.currentSource = '';
        this.currentDirection = '';
        this.currentFilter = '';
        this.totalFlows = 0;
        this.displayedFlows = 0;
        this.isLimited = false;
        
        // Sampling configuration
        this.samplingInfo = new Map(); // sourceIP -> { interval, algorithm, mode }
        this.extrapolateEnabled = false;
        
        // Traffic threshold filter (in bytes)
        this.minTrafficThreshold = 0;
        this.maxTrafficThreshold = 0; // 0 = off (no limit)
        this.remoteIPTotals = new Map(); // remoteIP -> total bytes
        this.flowsWithoutLocation = []; // Flows that couldn't be mapped
        
        // User authentication
        this.currentUser = null;
        this.authEnabled = false;
        
        this.init();
    }

    async init() {
        this.initMap();
        this.initControls();
        await this.loadAuthStatus();
        await this.loadSources();
        await this.loadSamplingInfo();
        this.connectWebSocket();
        
        // Periodically check for sampling info updates
        setInterval(() => this.loadSamplingInfo(), 60000);
    }

    // Load authentication status
    async loadAuthStatus() {
        try {
            // First check if auth is enabled
            const configResponse = await fetch('/auth/config');
            if (configResponse.ok) {
                const config = await configResponse.json();
                this.authEnabled = config.enabled;
            }

            // Then get current user
            const response = await fetch('/auth/me');
            if (response.ok) {
                const data = await response.json();
                this.currentUser = data;
                this.updateUserUI();
            }
        } catch (error) {
            console.warn('Failed to load auth status:', error);
        }
    }

    // Update user interface based on auth status
    updateUserUI() {
        const userNameEl = document.getElementById('user-name');
        const userRoleEl = document.getElementById('user-role');
        const loginBtn = document.getElementById('login-btn');
        const logoutBtn = document.getElementById('logout-btn');

        // Reset visibility
        loginBtn.style.display = 'none';
        logoutBtn.style.display = 'none';

        if (!this.authEnabled) {
            // Auth disabled - show as admin, hide both buttons
            userNameEl.textContent = '';
            userRoleEl.textContent = 'Admin';
            userRoleEl.className = 'user-role role-admin';
        } else if (!this.currentUser || !this.currentUser.authenticated) {
            // Anonymous user
            userNameEl.textContent = '';
            userRoleEl.textContent = 'Guest';
            userRoleEl.className = 'user-role role-anonymous';
            loginBtn.style.display = 'inline-flex';
        } else {
            // Logged in user
            userNameEl.textContent = this.currentUser.username;
            userRoleEl.textContent = this.currentUser.role;
            userRoleEl.className = `user-role role-${this.currentUser.role}`;
            logoutBtn.style.display = 'inline-flex';
        }

        // Show health button for admins
        const healthBtn = document.getElementById('health-btn');
        const isAdmin = (!this.authEnabled) || 
                        (this.currentUser && this.currentUser.role === 'admin');
        healthBtn.style.display = isAdmin ? 'inline-flex' : 'none';

        // Setup logout handler
        logoutBtn.onclick = () => this.logout();
    }

    // Logout user
    async logout() {
        try {
            await fetch('/auth/logout', { method: 'POST' });
            window.location.reload();
        } catch (error) {
            console.error('Logout failed:', error);
        }
    }

    // Initialize Leaflet map
    initMap() {
        this.map = L.map('map', {
            center: [30, 0],
            zoom: 2,
            minZoom: 2,
            maxZoom: 18,
            worldCopyJump: true,
            zoomControl: false  // Remove zoom buttons, use scroll/pinch instead
        });

        // Dark tile layer
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 20
        }).addTo(this.map);

        // Remove default tile filter since we're using dark tiles
        document.querySelector('.leaflet-tile-pane').style.filter = 'none';
    }

    // Initialize UI controls
    initControls() {
        // Source selector
        document.getElementById('source-select').addEventListener('change', (e) => {
            this.currentSource = e.target.value;
            this.sendFiltersToServer();
        });

        // Direction buttons
        document.querySelectorAll('.btn-direction').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.btn-direction').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.currentDirection = e.target.dataset.direction;
                this.sendFiltersToServer();
            });
        });

        // Filter input
        let filterTimeout;
        document.getElementById('filter-input').addEventListener('input', (e) => {
            clearTimeout(filterTimeout);
            filterTimeout = setTimeout(() => {
                this.currentFilter = e.target.value;
                this.sendFiltersToServer();
            }, 300);
        });

        // Filter clear
        document.getElementById('filter-clear').addEventListener('click', () => {
            document.getElementById('filter-input').value = '';
            this.currentFilter = '';
            this.sendFiltersToServer();
        });

        // Info panel close
        document.getElementById('info-close').addEventListener('click', () => {
            document.getElementById('info-panel').classList.add('hidden');
        });

        // Extrapolation toggle
        document.getElementById('extrapolate-toggle').addEventListener('change', (e) => {
            this.extrapolateEnabled = e.target.checked;
            // Recalculate totals and redraw all flows with new extrapolation setting
            this.calculateRemoteIPTotals();
            this.clearAllFlows();
            this.flows.forEach(flow => this.addOrUpdateFlow(flow));
            this.updateFlowCount();
        });

        // Min traffic slider with discrete "nice" values
        const trafficSlider = document.getElementById('min-traffic-slider');
        const trafficValue = document.getElementById('min-traffic-value');
        
        trafficSlider.addEventListener('input', (e) => {
            const sliderPos = parseInt(e.target.value);
            this.minTrafficThreshold = this.trafficSteps[sliderPos] || 0;
            trafficValue.textContent = sliderPos === 0 ? 'Off' : this.formatBytes(this.minTrafficThreshold);
            this.applyTrafficFilter();
        });

        // Min traffic reset button
        document.getElementById('min-traffic-reset').addEventListener('click', () => {
            trafficSlider.value = 0;
            this.minTrafficThreshold = 0;
            trafficValue.textContent = 'Off';
            this.applyTrafficFilter();
        });

        // Max traffic slider with discrete "nice" values
        const maxTrafficSlider = document.getElementById('max-traffic-slider');
        const maxTrafficValue = document.getElementById('max-traffic-value');
        
        maxTrafficSlider.addEventListener('input', (e) => {
            const sliderPos = parseInt(e.target.value);
            this.maxTrafficThreshold = this.maxTrafficSteps[sliderPos] || 0;
            maxTrafficValue.textContent = sliderPos === 0 ? 'Off' : this.formatBytes(this.maxTrafficThreshold);
            
            // Ensure min <= max: if min > max, adjust min
            if (this.maxTrafficThreshold > 0 && this.minTrafficThreshold > this.maxTrafficThreshold) {
                this.minTrafficThreshold = this.maxTrafficThreshold;
                // Find the corresponding slider position for min
                const minPos = this.trafficSteps.findIndex(v => v >= this.minTrafficThreshold);
                trafficSlider.value = minPos >= 0 ? minPos : 0;
                trafficValue.textContent = minPos === 0 ? 'Off' : this.formatBytes(this.minTrafficThreshold);
            }
            
            this.applyTrafficFilter();
        });

        // Max traffic reset button
        document.getElementById('max-traffic-reset').addEventListener('click', () => {
            maxTrafficSlider.value = 0;
            this.maxTrafficThreshold = 0;
            maxTrafficValue.textContent = 'Off';
            this.applyTrafficFilter();
        });

        // Update min slider to sync with max
        const originalMinHandler = trafficSlider.oninput;
        trafficSlider.addEventListener('input', (e) => {
            // Ensure min <= max: if min > max, adjust max
            if (this.maxTrafficThreshold > 0 && this.minTrafficThreshold > this.maxTrafficThreshold) {
                this.maxTrafficThreshold = this.minTrafficThreshold;
                // Find the corresponding slider position for max
                const maxPos = this.maxTrafficSteps.findIndex(v => v >= this.maxTrafficThreshold);
                if (maxPos >= 0) {
                    maxTrafficSlider.value = maxPos;
                    maxTrafficValue.textContent = this.formatBytes(this.maxTrafficThreshold);
                } else {
                    // Min is larger than max slider can go, set max to Off
                    maxTrafficSlider.value = 0;
                    this.maxTrafficThreshold = 0;
                    maxTrafficValue.textContent = 'Off';
                }
            }
        });

        // Flows without location link
        document.getElementById('flows-without-location').addEventListener('click', () => {
            this.openUnmappedModal();
        });

        // Unmapped flows modal close handlers
        document.getElementById('unmapped-close').addEventListener('click', () => {
            this.closeUnmappedModal();
        });

        // Health modal
        document.getElementById('health-btn').addEventListener('click', () => {
            this.openHealthModal();
        });

        document.getElementById('health-close').addEventListener('click', () => {
            this.closeHealthModal();
        });

        // Modal backdrop click handlers
        document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
            backdrop.addEventListener('click', (e) => {
                const modal = e.target.closest('.modal');
                if (modal) {
                    if (modal.id === 'health-modal') {
                        this.closeHealthModal();
                    } else if (modal.id === 'unmapped-modal') {
                        this.closeUnmappedModal();
                    }
                }
            });
        });

        // Close modals on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeHealthModal();
                this.closeUnmappedModal();
            }
        });
    }

    // Health modal interval reference
    healthRefreshInterval = null;

    // Open health modal and start auto-refresh
    openHealthModal() {
        document.getElementById('health-modal').classList.remove('hidden');
        this.loadHealthStats();
        
        // Auto-refresh every 10 seconds
        this.healthRefreshInterval = setInterval(() => {
            this.loadHealthStats();
        }, 10000);
    }

    // Close health modal and stop auto-refresh
    closeHealthModal() {
        document.getElementById('health-modal').classList.add('hidden');
        
        if (this.healthRefreshInterval) {
            clearInterval(this.healthRefreshInterval);
            this.healthRefreshInterval = null;
        }
    }

    // Open unmapped flows modal
    openUnmappedModal() {
        document.getElementById('unmapped-modal').classList.remove('hidden');
        this.renderUnmappedFlows();
    }

    // Close unmapped flows modal
    closeUnmappedModal() {
        document.getElementById('unmapped-modal').classList.add('hidden');
    }

    // Render unmapped flows list
    renderUnmappedFlows() {
        const content = document.getElementById('unmapped-content');
        
        if (this.flowsWithoutLocation.length === 0) {
            content.innerHTML = '<div class="unmapped-empty">No flows without location data.</div>';
            return;
        }

        // Group flows by remote IP to show totals
        const byRemoteIP = new Map();
        this.flowsWithoutLocation.forEach(flow => {
            const existing = byRemoteIP.get(flow.remote_ip);
            if (existing) {
                existing.bytes += flow.bytes || 0;
                existing.flows.push(flow);
            } else {
                byRemoteIP.set(flow.remote_ip, {
                    ip: flow.remote_ip,
                    org: flow.remote_organization || flow.remote_asn || '-',
                    bytes: flow.bytes || 0,
                    flows: [flow]
                });
            }
        });

        // Sort by bytes descending
        const sorted = Array.from(byRemoteIP.values()).sort((a, b) => b.bytes - a.bytes);

        let html = `
            <div class="unmapped-header">
                <span>Remote IP</span>
                <span>Organization</span>
                <span>Traffic</span>
                <span>Flows</span>
            </div>
            <div class="unmapped-list">
        `;

        sorted.forEach(item => {
            const protocols = [...new Set(item.flows.map(f => f.protocol))].join(', ');
            html += `
                <div class="unmapped-item">
                    <span class="unmapped-item-ip">${item.ip}</span>
                    <span class="unmapped-item-org" title="${item.org}">${item.org}</span>
                    <span class="unmapped-item-traffic">${this.formatBytes(item.bytes)}</span>
                    <span class="unmapped-item-protocol">${item.flows.length} (${protocols})</span>
                </div>
            `;
        });

        html += '</div>';
        content.innerHTML = html;
    }

    // Load health statistics from API
    async loadHealthStats() {
        try {
            const response = await fetch('/api/health/detailed');
            const data = await response.json();
            
            if (data.success) {
                this.renderHealthStats(data.data);
                document.getElementById('health-last-update').textContent = 
                    `Last update: ${new Date().toLocaleTimeString()}`;
            } else {
                document.getElementById('health-content').innerHTML = 
                    `<div class="health-loading">Error: ${data.error}</div>`;
            }
        } catch (error) {
            console.error('Failed to load health stats:', error);
            document.getElementById('health-content').innerHTML = 
                `<div class="health-loading">Failed to load health statistics</div>`;
        }
    }

    // Render health statistics in the modal
    renderHealthStats(stats) {
        const content = document.getElementById('health-content');
        
        // Determine progress bar classes based on percentage
        const getProgressClass = (percent) => {
            if (percent < 50) return 'low';
            if (percent < 80) return 'medium';
            return 'high';
        };

        let sourcesHtml = '';
        if (stats.sources && stats.sources.length > 0) {
            sourcesHtml = stats.sources.map(src => `
                <div class="health-source-item">
                    <span class="health-source-name">${src.name}</span>
                    <div class="health-source-stats">
                        <span class="health-source-stat">
                            <span class="health-source-stat-label">Flows:</span>
                            ${src.flow_count}
                        </span>
                        <span class="health-source-stat">
                            <span class="health-source-stat-label">Objects:</span>
                            ${src.address_objects}
                        </span>
                    </div>
                </div>
            `).join('');
        } else {
            sourcesHtml = '<div class="health-stat"><span class="health-stat-value">No sources configured</span></div>';
        }

        const memPercent = stats.system.memory_usage_percent || 0;
        const cpuPercent = stats.system.cpu_usage_percent || 0;

        content.innerHTML = `
            <div class="health-section">
                <div class="health-section-title">NetFlowMap <span class="health-version">v${stats.version}</span></div>
                <div class="health-grid">
                    <div class="health-stat">
                        <div class="health-stat-label">Uptime</div>
                        <div class="health-stat-value">${stats.uptime}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Connected Clients</div>
                        <div class="health-stat-value highlight">${stats.netflow.connected_clients}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Total Flows</div>
                        <div class="health-stat-value">${stats.netflow.total_flows}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Packets Received</div>
                        <div class="health-stat-value">${stats.netflow.packets_received.toLocaleString()}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Flows Received</div>
                        <div class="health-stat-value">${stats.netflow.flows_received.toLocaleString()}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Parse Errors</div>
                        <div class="health-stat-value ${stats.netflow.parse_errors > 0 ? 'warning' : 'success'}">${stats.netflow.parse_errors}</div>
                    </div>
                </div>
            </div>

            <div class="health-section">
                <div class="health-section-title">Sources</div>
                <div class="health-sources-list">
                    ${sourcesHtml}
                </div>
            </div>

            <div class="health-section">
                <div class="health-section-title">Go Runtime</div>
                <div class="health-grid">
                    <div class="health-stat">
                        <div class="health-stat-label">Go Version</div>
                        <div class="health-stat-value">${stats.runtime.go_version}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Goroutines</div>
                        <div class="health-stat-value">${stats.runtime.num_goroutine}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Memory Allocated</div>
                        <div class="health-stat-value">${stats.runtime.mem_alloc_mb}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Heap In Use</div>
                        <div class="health-stat-value">${stats.runtime.heap_inuse_mb}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Memory System</div>
                        <div class="health-stat-value">${stats.runtime.mem_sys_mb}</div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">GC Runs</div>
                        <div class="health-stat-value">${stats.runtime.num_gc}</div>
                    </div>
                </div>
            </div>

            ${stats.system.available ? `
            <div class="health-section">
                <div class="health-section-title">System (Host)</div>
                <div class="health-grid">
                    <div class="health-stat">
                        <div class="health-stat-label">CPU Usage</div>
                        <div class="health-stat-value">${cpuPercent.toFixed(1)}%</div>
                        <div class="health-progress">
                            <div class="health-progress-bar ${getProgressClass(cpuPercent)}" style="width: ${cpuPercent}%"></div>
                        </div>
                    </div>
                    <div class="health-stat">
                        <div class="health-stat-label">Memory Usage</div>
                        <div class="health-stat-value">${stats.system.memory_used_mb} / ${stats.system.memory_total_mb}</div>
                        <div class="health-progress">
                            <div class="health-progress-bar ${getProgressClass(memPercent)}" style="width: ${memPercent}%"></div>
                        </div>
                    </div>
                </div>
            </div>
            ` : ''}
        `;
    }

    // Discrete traffic threshold steps for Min slider (nice round values)
    // 0 = off, then 100B, 1KB, 10KB, 100KB, 1MB, 10MB, 100MB, 200MB, 300MB, 500MB, 750MB, 1GB
    trafficSteps = [
        0,                      // 0: Off
        100,                    // 1: 100 B
        1024,                   // 2: 1 KB
        10 * 1024,              // 3: 10 KB
        100 * 1024,             // 4: 100 KB
        1024 * 1024,            // 5: 1 MB
        10 * 1024 * 1024,       // 6: 10 MB
        100 * 1024 * 1024,      // 7: 100 MB
        200 * 1024 * 1024,      // 8: 200 MB
        300 * 1024 * 1024,      // 9: 300 MB
        500 * 1024 * 1024,      // 10: 500 MB
        750 * 1024 * 1024,      // 11: 750 MB
        1024 * 1024 * 1024,     // 12: 1 GB
    ];

    // Discrete traffic threshold steps for Max slider (up to 1MB only)
    // 0 = off (no limit), then 100B, 500B, 1KB, 10KB, 100KB, 1MB
    maxTrafficSteps = [
        0,                      // 0: Off (no limit)
        100,                    // 1: 100 B
        500,                    // 2: 500 B
        1024,                   // 3: 1 KB
        10 * 1024,              // 4: 10 KB
        100 * 1024,             // 5: 100 KB
        1024 * 1024,            // 6: 1 MB
    ];

    // Apply traffic filter - send to server for proper filtering
    applyTrafficFilter() {
        // Send filter to server - server will respond with properly filtered flows
        this.sendFiltersToServer();
        
        // Also update local display count
        this.updateFlowCount();
    }

    // Calculate total bytes per remote IP
    calculateRemoteIPTotals() {
        this.remoteIPTotals.clear();
        
        this.flows.forEach(flow => {
            if (!flow.remote_ip) return;
            
            const currentTotal = this.remoteIPTotals.get(flow.remote_ip) || 0;
            const flowBytes = this.extrapolateEnabled 
                ? (flow.bytes || 0) * this.getSamplingInterval(flow)
                : (flow.bytes || 0);
            
            this.remoteIPTotals.set(flow.remote_ip, currentTotal + flowBytes);
        });
    }

    // Load sampling information from server
    async loadSamplingInfo() {
        try {
            const response = await fetch('/api/sampling');
            const data = await response.json();
            
            if (data.success && Array.isArray(data.data)) {
                this.samplingInfo.clear();
                
                // API now returns source_id based entries with interval > 1 only
                data.data.forEach(info => {
                    this.samplingInfo.set(info.source_id, {
                        sourceIP: info.source_ip,
                        sourceName: info.source_name,
                        interval: info.interval,
                        algorithm: info.algorithm,
                        mode: info.mode,
                        fromConfig: info.from_config
                    });
                });
                
                this.updateSamplingUI();
            }
        } catch (error) {
            console.error('Failed to load sampling info:', error);
        }
    }

    // Update UI based on sampling configuration
    updateSamplingUI() {
        const controlEl = document.getElementById('sampling-control');
        const infoEl = document.getElementById('sampling-info');
        
        if (this.samplingInfo.size > 0) {
            controlEl.classList.remove('hidden');
            
            // Build info text
            const infos = [];
            this.samplingInfo.forEach((info, sourceID) => {
                const sourceLabel = info.sourceName || sourceID;
                const sourceType = info.fromConfig ? 'config' : 'detected';
                infos.push(`${sourceLabel}: 1:${info.interval} (${sourceType})`);
            });
            
            infoEl.textContent = `Sampling: ${infos.join(', ')}`;
            infoEl.title = `NetFlow sampling active. Enable extrapolation to estimate real traffic values.`;
        } else {
            controlEl.classList.add('hidden');
            // Reset toggle when no sampling
            document.getElementById('extrapolate-toggle').checked = false;
            this.extrapolateEnabled = false;
        }
    }

    // Get sampling interval for a flow's source
    getSamplingInterval(flow) {
        // Look up by source_id
        if (this.samplingInfo.has(flow.source_id)) {
            return this.samplingInfo.get(flow.source_id).interval;
        }
        
        return 1; // No sampling
    }

    // Send current filter settings to server
    sendFiltersToServer() {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            return;
        }

        const message = {
            type: 'filter',
            data: {
                source: this.currentSource,
                direction: this.currentDirection,
                filter: this.currentFilter,
                minTraffic: this.minTrafficThreshold,
                maxTraffic: this.maxTrafficThreshold
            }
        };

        this.ws.send(JSON.stringify(message));
    }

    // Load available sources
    async loadSources() {
        try {
            const response = await fetch('/api/sources');
            const data = await response.json();
            
            if (data.success) {
                this.sources = data.data;
                this.updateSourceSelector();
                this.addSourceMarkers();
            }
        } catch (error) {
            console.error('Failed to load sources:', error);
        }
    }

    // Update source selector dropdown
    updateSourceSelector() {
        const select = document.getElementById('source-select');
        select.innerHTML = '<option value="">All Sources</option>';
        
        this.sources.forEach(source => {
            const option = document.createElement('option');
            option.value = source.id;
            option.textContent = `${source.name} (${source.flow_count} flows)`;
            select.appendChild(option);
        });
    }

    // Add markers for source firewalls
    addSourceMarkers() {
        this.sources.forEach(source => {
            if (source.latitude && source.longitude) {
                const marker = L.circleMarker([source.latitude, source.longitude], {
                    radius: 10,
                    fillColor: '#f59e0b',
                    color: 'rgba(245, 158, 11, 0.5)',
                    weight: 3,
                    opacity: 1,
                    fillOpacity: 0.9
                }).addTo(this.map);

                marker.bindTooltip(source.name, {
                    permanent: false,
                    direction: 'top',
                    className: 'source-tooltip'
                });

                // Click handler for source marker
                marker.on('click', () => {
                    this.showSourceInfo(source);
                });

                this.sourceMarkers.set(source.id, marker);
            }
        });
    }

    // Connect to WebSocket for real-time updates
    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('WebSocket connected');
            document.getElementById('connection-status').className = 'status-connected';
            
            // Send initial filter settings to server
            this.sendFiltersToServer();
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            document.getElementById('connection-status').className = 'status-disconnected';
            
            // Reconnect after 3 seconds
            setTimeout(() => this.connectWebSocket(), 3000);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleWebSocketMessage(message);
            } catch (error) {
                console.error('Failed to parse WebSocket message:', error);
            }
        };
    }

    // Handle incoming WebSocket messages
    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'initial':
            case 'update':
                // Full flow list (with metadata)
                const flowData = message.data;
                
                // ALWAYS clear all flows on every update to ensure stale flows are removed
                this.clearAllFlows();
                
                if (flowData) {
                    this.totalFlows = flowData.total || 0;
                    this.displayedFlows = flowData.displayed || 0;
                    this.isLimited = flowData.limited || false;
                    
                    if (Array.isArray(flowData.flows)) {
                        // First pass: store all flows
                        flowData.flows.forEach(flow => {
                            if (flow && flow.key) {
                                this.flows.set(flow.key, flow);
                            }
                        });
                        
                        // Calculate totals before applying filter
                        this.calculateRemoteIPTotals();
                        
                        // Second pass: visualize flows that pass the filter
                        flowData.flows.forEach(flow => this.addOrUpdateFlow(flow));
                    }
                } else if (Array.isArray(message.data)) {
                    // Fallback for old format
                    message.data.forEach(flow => {
                        if (flow && flow.key) {
                            this.flows.set(flow.key, flow);
                        }
                    });
                    this.calculateRemoteIPTotals();
                    message.data.forEach(flow => this.addOrUpdateFlow(flow));
                }
                this.updateFlowCount();
                break;

            case 'flow':
                // Single flow update (legacy, not used anymore)
                this.addOrUpdateFlow(message.data);
                this.calculateRemoteIPTotals();
                this.updateFlowCount();
                break;
        }
    }

    // Clear all flows from the map
    clearAllFlows() {
        this.flowLines.forEach((line, key) => {
            line.off();  // Remove all event listeners
            this.map.removeLayer(line);
        });
        this.flowLines.clear();
        
        this.remoteMarkers.forEach((data, key) => {
            data.marker.off();  // Remove all event listeners
            this.map.removeLayer(data.marker);
        });
        this.remoteMarkers.clear();
        
        this.flows.clear();
    }

    // Add or update a flow
    addOrUpdateFlow(flow) {
        if (!flow || !flow.key) return;

        // Store flow data
        this.flows.set(flow.key, flow);

        // Check if flow should be displayed based on filters
        if (!this.shouldDisplayFlow(flow)) {
            this.removeFlowFromMap(flow.key);
            return;
        }

        // Update or create visualization
        this.visualizeFlow(flow);
    }

    // Check if flow should be displayed
    // Note: Traffic filtering is now done server-side
    shouldDisplayFlow(flow) {
        // All flows received from server should be displayed
        // (server already applies min/max traffic filters)
        return true;
    }

    // Visualize a flow on the map
    visualizeFlow(flow) {
        // Need valid coordinates
        if (!flow.source_lat || !flow.source_lon || !flow.remote_lat || !flow.remote_lon) {
            return;
        }

        const sourceLatLng = [flow.source_lat, flow.source_lon];
        const remoteLatLng = [flow.remote_lat, flow.remote_lon];

        // Create curved line
        const curvePoints = this.createCurve(sourceLatLng, remoteLatLng);
        
        // Line color based on direction
        const color = flow.inbound ? '#ef4444' : '#3b82f6';
        
        // Line weight based on bandwidth (logarithmic scale)
        const weight = Math.min(Math.max(Math.log10(flow.bytes_per_sec + 1) * 1.5, 2), 8);

        // Remove existing line
        if (this.flowLines.has(flow.key)) {
            const oldLine = this.flowLines.get(flow.key);
            oldLine.off();  // Remove all event listeners
            this.map.removeLayer(oldLine);
        }

        // Create new polyline
        const polyline = L.polyline(curvePoints, {
            color: color,
            weight: weight,
            opacity: 0.7,
            smoothFactor: 1,
            className: 'flow-line'
        }).addTo(this.map);

        // Click handler for line - open popup at cursor position
        polyline.on('click', (e) => {
            this.showFlowPopup(flow, e.latlng);
        });

        this.flowLines.set(flow.key, polyline);

        // Add or update remote marker
        this.addRemoteMarker(flow);
    }

    // Create curved path between two points (Bézier curve)
    createCurve(start, end) {
        const points = [];
        const numPoints = 25;  // Reduced from 50 for better performance
        
        // Calculate midpoint with offset for curve
        const midLat = (start[0] + end[0]) / 2;
        const midLng = (start[1] + end[1]) / 2;
        
        // Offset the control point perpendicular to the line
        const dx = end[1] - start[1];
        const dy = end[0] - start[0];
        const dist = Math.sqrt(dx * dx + dy * dy);
        
        // Curve height proportional to distance
        const curveHeight = Math.min(dist * 0.3, 30);
        
        // Control point
        const ctrlLat = midLat + (dx / dist) * curveHeight;
        const ctrlLng = midLng - (dy / dist) * curveHeight;

        // Generate points along quadratic Bézier curve
        for (let i = 0; i <= numPoints; i++) {
            const t = i / numPoints;
            const lat = (1 - t) * (1 - t) * start[0] + 2 * (1 - t) * t * ctrlLat + t * t * end[0];
            const lng = (1 - t) * (1 - t) * start[1] + 2 * (1 - t) * t * ctrlLng + t * t * end[1];
            points.push([lat, lng]);
        }

        return points;
    }

    // Add marker for remote IP
    addRemoteMarker(flow) {
        const markerKey = flow.remote_ip;
        
        // Skip if marker already exists
        if (this.remoteMarkers.has(markerKey)) {
            return;
        }

        if (!flow.remote_lat || !flow.remote_lon) {
            return;
        }

        const marker = L.circleMarker([flow.remote_lat, flow.remote_lon], {
            radius: 6,
            fillColor: '#10b981',
            color: 'rgba(16, 185, 129, 0.3)',
            weight: 2,
            opacity: 1,
            fillOpacity: 0.8
        }).addTo(this.map);

        // Tooltip - show organization or address object name
        let tooltipContent = flow.remote_ip;
        if (flow.address_object_name) {
            tooltipContent = `${flow.address_object_name} (${flow.remote_ip})`;
        } else if (flow.remote_organization) {
            tooltipContent = `${flow.remote_organization} (${flow.remote_ip})`;
        }
        
        marker.bindTooltip(tooltipContent, {
            permanent: false,
            direction: 'top'
        });

        // Click handler - show all flows for this remote IP
        marker.on('click', () => {
            this.showRemoteIPInfo(flow.remote_ip);
        });

        this.remoteMarkers.set(markerKey, {
            marker: marker,
            flow: flow
        });
    }

    // Remove flow visualization from map
    removeFlowFromMap(flowKey) {
        if (this.flowLines.has(flowKey)) {
            const line = this.flowLines.get(flowKey);
            line.off();  // Remove all event listeners
            this.map.removeLayer(line);
            this.flowLines.delete(flowKey);
        }
    }

    // Show popup for a flow
    showFlowPopup(flow, clickLatLng = null) {
        let popupLatLng;
        
        if (clickLatLng) {
            // Use click position
            popupLatLng = clickLatLng;
        } else {
            // Fallback to midpoint between source and remote
            const sourceLatLng = [flow.source_lat, flow.source_lon];
            const remoteLatLng = [flow.remote_lat, flow.remote_lon];
            const midLat = (sourceLatLng[0] + remoteLatLng[0]) / 2;
            const midLng = (sourceLatLng[1] + remoteLatLng[1]) / 2;
            popupLatLng = [midLat, midLng];
        }

        const content = this.createFlowPopupContent(flow);

        L.popup()
            .setLatLng(popupLatLng)
            .setContent(content)
            .openOn(this.map);
    }

    // Create popup HTML content for a flow
    createFlowPopupContent(flow) {
        const direction = flow.inbound ? 'inbound' : 'outbound';
        const directionLabel = flow.inbound ? '↓ Inbound' : '↑ Outbound';
        
        const isExtrapolated = this.isExtrapolationActive();
        const displayBytes = this.getExtrapolatedValue(flow.bytes || 0, flow);
        const displayBytesPerSec = this.getExtrapolatedValue(flow.bytes_per_sec || 0, flow);
        
        const bandwidth = this.formatBandwidthWithDuration(displayBytesPerSec, flow.sample_duration, isExtrapolated);
        
        let remoteLabel = flow.remote_ip;
        if (flow.address_object_name) {
            remoteLabel = `${flow.address_object_name} (${flow.remote_ip})`;
        }

        let location = '';
        if (flow.remote_city || flow.remote_country) {
            location = [flow.remote_city, flow.remote_country].filter(Boolean).join(', ');
        }

        // Format organization/ASN info
        let orgInfo = '';
        if (flow.remote_organization) {
            orgInfo = flow.remote_asn 
                ? `${flow.remote_organization} (AS${flow.remote_asn})`
                : flow.remote_organization;
        } else if (flow.remote_asn) {
            orgInfo = `AS${flow.remote_asn}`;
        }

        const extrapolatedClass = isExtrapolated ? 'extrapolated' : '';

        return `
            <div class="popup-content">
                <div class="popup-header">
                    <span class="direction-badge ${direction}">${directionLabel}</span>
                    ${flow.protocol_name}
                </div>
                <div class="popup-row">
                    <span class="label">Source:</span>
                    <span class="value">${flow.source_name}</span>
                </div>
                <div class="popup-row">
                    <span class="label">Local:</span>
                    <span class="value">${flow.local_ip}:${flow.local_port}</span>
                </div>
                <div class="popup-row">
                    <span class="label">Remote:</span>
                    <span class="value">${remoteLabel}:${flow.remote_port}</span>
                </div>
                ${orgInfo ? `<div class="popup-row"><span class="label">Organization:</span><span class="value org-name">${orgInfo}</span></div>` : ''}
                <div class="popup-row">
                    <span class="label">Bandwidth:</span>
                    <span class="value highlight ${extrapolatedClass}">${bandwidth}</span>
                </div>
                <div class="popup-row">
                    <span class="label">Total:</span>
                    <span class="value ${extrapolatedClass}">${this.formatBytes(displayBytes, isExtrapolated)}</span>
                </div>
                ${location ? `<div class="popup-location">📍 ${location}</div>` : ''}
                ${isExtrapolated ? `<div class="popup-location" style="color: var(--accent-yellow);">⚠ Estimated (1:${this.getSamplingInterval(flow)} sampling)</div>` : ''}
            </div>
        `;
    }

    // Show info panel for all flows to/from a remote IP
    showRemoteIPInfo(remoteIP) {
        const flowsForIP = [];
        
        this.flows.forEach(flow => {
            if (flow.remote_ip === remoteIP && this.shouldDisplayFlow(flow)) {
                flowsForIP.push(flow);
            }
        });

        if (flowsForIP.length === 0) {
            return;
        }

        // Get location info from first flow
        const firstFlow = flowsForIP[0];
        let title = firstFlow.address_object_name 
            ? `${firstFlow.address_object_name} (${remoteIP})`
            : remoteIP;
        
        let location = '';
        if (firstFlow.remote_city || firstFlow.remote_country) {
            location = [firstFlow.remote_city, firstFlow.remote_country].filter(Boolean).join(', ');
        }

        // Organization info
        let orgInfo = '';
        if (firstFlow.remote_organization) {
            orgInfo = firstFlow.remote_asn 
                ? `${firstFlow.remote_organization} (AS${firstFlow.remote_asn})`
                : firstFlow.remote_organization;
        } else if (firstFlow.remote_asn) {
            orgInfo = `AS${firstFlow.remote_asn}`;
        }

        // Calculate totals across all flows to this IP
        let totalBytes = 0;
        let totalPackets = 0;
        let inboundBytes = 0;
        let outboundBytes = 0;
        let totalBytesPerSec = 0;

        const isExtrapolated = this.isExtrapolationActive();

        flowsForIP.forEach(flow => {
            const multiplier = isExtrapolated ? this.getSamplingInterval(flow) : 1;
            totalBytes += (flow.bytes || 0) * multiplier;
            totalPackets += (flow.packets || 0) * multiplier;
            totalBytesPerSec += (flow.bytes_per_sec || 0) * multiplier;
            if (flow.inbound) {
                inboundBytes += (flow.bytes || 0) * multiplier;
            } else {
                outboundBytes += (flow.bytes || 0) * multiplier;
            }
        });

        const extrapolatedClass = isExtrapolated ? 'extrapolated' : '';
        const extrapolatedNote = isExtrapolated ? 
            `<div style="color: var(--accent-yellow); font-size: 0.8rem; margin-top: 10px;">⚠ Values are estimated based on sampling</div>` : '';

        const content = document.getElementById('info-content');
        content.innerHTML = `
            <div class="info-title">${title}</div>
            ${orgInfo ? `<div style="color: var(--accent-green); margin-bottom: 8px; font-size: 0.85rem;">🏢 ${orgInfo}</div>` : ''}
            ${location ? `<div style="color: var(--text-secondary); margin-bottom: 15px; font-size: 0.9rem;">📍 ${location}</div>` : ''}
            <div class="info-section">
                <div class="info-section-title">Traffic Summary</div>
                <div class="traffic-summary">
                    <div class="summary-row">
                        <span class="label">Total Data:</span>
                        <span class="value highlight ${extrapolatedClass}">${this.formatBytes(totalBytes, isExtrapolated)}</span>
                    </div>
                    <div class="summary-row">
                        <span class="label">↓ Inbound:</span>
                        <span class="value ${extrapolatedClass}" style="color: #ef4444;">${this.formatBytes(inboundBytes, isExtrapolated)}</span>
                    </div>
                    <div class="summary-row">
                        <span class="label">↑ Outbound:</span>
                        <span class="value ${extrapolatedClass}" style="color: #3b82f6;">${this.formatBytes(outboundBytes, isExtrapolated)}</span>
                    </div>
                    <div class="summary-row">
                        <span class="label">Bandwidth:</span>
                        <span class="value ${extrapolatedClass}">${isExtrapolated ? '≈' : ''}${this.formatBandwidth(totalBytesPerSec)}</span>
                    </div>
                    <div class="summary-row">
                        <span class="label">Packets:</span>
                        <span class="value ${extrapolatedClass}">${isExtrapolated ? '≈' : ''}${totalPackets.toLocaleString()}</span>
                    </div>
                    ${extrapolatedNote}
                </div>
            </div>
            <div class="info-section">
                <div class="info-section-title">Active Connections (${flowsForIP.length})</div>
                ${flowsForIP.map(flow => this.createFlowItemHTML(flow)).join('')}
            </div>
        `;

        document.getElementById('info-panel').classList.remove('hidden');
    }

    // Show info panel for a source
    showSourceInfo(source) {
        const flowsForSource = [];
        
        this.flows.forEach(flow => {
            if (flow.source_id === source.id && this.shouldDisplayFlow(flow)) {
                flowsForSource.push(flow);
            }
        });

        const content = document.getElementById('info-content');
        content.innerHTML = `
            <div class="info-title">${source.name}</div>
            <div style="color: var(--text-secondary); margin-bottom: 15px; font-size: 0.9rem;">
                📍 ${source.latitude.toFixed(4)}, ${source.longitude.toFixed(4)}
            </div>
            <div class="info-section">
                <div class="info-section-title">Active Connections (${flowsForSource.length})</div>
                ${flowsForSource.length > 0 
                    ? flowsForSource.slice(0, 20).map(flow => this.createFlowItemHTML(flow)).join('')
                    : '<div style="color: var(--text-muted); font-size: 0.85rem;">No active flows</div>'}
                ${flowsForSource.length > 20 
                    ? `<div style="color: var(--text-muted); font-size: 0.85rem; margin-top: 10px;">...and ${flowsForSource.length - 20} more</div>` 
                    : ''}
            </div>
        `;

        document.getElementById('info-panel').classList.remove('hidden');
    }

    // Create HTML for a flow item in the info panel
    createFlowItemHTML(flow) {
        const direction = flow.inbound ? 'inbound' : 'outbound';
        const directionLabel = flow.inbound ? '↓ IN' : '↑ OUT';
        const bandwidth = this.formatBandwidth(flow.bytes_per_sec);
        
        let remoteLabel = flow.remote_ip;
        if (flow.address_object_name) {
            remoteLabel = flow.address_object_name;
        }

        return `
            <div class="flow-item" onclick="app.showFlowPopup(app.flows.get('${flow.key}'))">
                <div class="flow-direction ${direction}">${directionLabel}</div>
                <div class="flow-ips">${flow.local_ip} ↔ ${remoteLabel}</div>
                <div class="flow-bandwidth">${flow.protocol_name} | ${bandwidth}</div>
            </div>
        `;
    }

    // Refresh displayed flows (now handled by server sending new filtered data)
    async refreshFlows() {
        // Filtering is now done server-side
        // This method is kept for compatibility but the actual refresh
        // happens automatically when the server sends new filtered data
        this.updateFlowCount();
    }

    // Remove remote markers that no longer have visible flows
    cleanupRemoteMarkers() {
        const visibleRemoteIPs = new Set();
        
        this.flowLines.forEach((_, key) => {
            const flow = this.flows.get(key);
            if (flow) {
                visibleRemoteIPs.add(flow.remote_ip);
            }
        });

        this.remoteMarkers.forEach((data, ip) => {
            if (!visibleRemoteIPs.has(ip)) {
                data.marker.off();  // Remove all event listeners
                this.map.removeLayer(data.marker);
                this.remoteMarkers.delete(ip);
            }
        });
    }

    // Update flow count display
    updateFlowCount() {
        let onMapCount = 0;
        this.flowsWithoutLocation = [];
        
        this.flows.forEach(flow => {
            if (this.shouldDisplayFlow(flow)) {
                // Check if flow has valid coordinates
                if (flow.source_lat && flow.source_lon && flow.remote_lat && flow.remote_lon) {
                    onMapCount++;
                } else {
                    this.flowsWithoutLocation.push(flow);
                }
            }
        });
        
        const flowCountEl = document.getElementById('flow-count');
        const limitInfoEl = document.getElementById('flow-limit-info');
        const withoutLocationEl = document.getElementById('flows-without-location');
        
        flowCountEl.textContent = onMapCount;
        
        // Show "without location" link if there are unmapped flows
        if (this.flowsWithoutLocation.length > 0) {
            withoutLocationEl.textContent = `· ${this.flowsWithoutLocation.length} without location`;
            withoutLocationEl.classList.remove('hidden');
        } else {
            withoutLocationEl.classList.add('hidden');
        }
        
        if (this.isLimited && this.totalFlows > this.displayedFlows) {
            limitInfoEl.textContent = ` (of ${this.totalFlows})`;
            limitInfoEl.title = `Showing top ${this.displayedFlows} flows sorted by traffic`;
        } else {
            limitInfoEl.textContent = '';
            limitInfoEl.title = '';
        }
    }

    // Format bytes to human-readable
    formatBytes(bytes, extrapolated = false) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        const value = parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        return extrapolated ? `≈${value}` : value;
    }

    // Get extrapolated value if enabled
    getExtrapolatedValue(value, flow) {
        if (!this.extrapolateEnabled) return value;
        const interval = this.getSamplingInterval(flow);
        return value * interval;
    }

    // Check if extrapolation is active for display
    isExtrapolationActive() {
        return this.extrapolateEnabled && this.samplingInfo.size > 0;
    }

    // Format bandwidth (bytes per second) to human-readable
    formatBandwidth(bytesPerSec) {
        if (!bytesPerSec || bytesPerSec === 0) return '0 KB/s';
        
        // Convert to KB/s
        const kbps = bytesPerSec / 1024;
        
        if (kbps < 1024) {
            return kbps.toFixed(1) + ' KB/s';
        }
        
        // Convert to MB/s
        const mbps = kbps / 1024;
        return mbps.toFixed(2) + ' MB/s';
    }

    // Format bandwidth with sample duration info
    formatBandwidthWithDuration(bytesPerSec, sampleDuration, extrapolated = false) {
        const bw = this.formatBandwidth(bytesPerSec);
        const prefix = extrapolated ? '≈' : '';
        
        if (!sampleDuration || sampleDuration <= 0) {
            return prefix + bw + ' <span class="duration-hint">(waiting for data)</span>';
        }
        
        // Format duration
        let durationStr;
        if (sampleDuration < 60) {
            durationStr = Math.round(sampleDuration) + 's';
        } else if (sampleDuration < 3600) {
            durationStr = Math.round(sampleDuration / 60) + 'min';
        } else {
            durationStr = (sampleDuration / 3600).toFixed(1) + 'h';
        }
        
        return prefix + bw + ` <span class="duration-hint">(avg. over ${durationStr})</span>`;
    }
}

// Initialize application
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new NetFlowMap();
});

