package fortigate

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kai/netflowmap/internal/logging"
)

// Client provides access to the FortiGate REST API.
type Client struct {
	host       string
	token      string
	httpClient *http.Client
}

// maskToken returns a masked version of a token for safe logging.
// Shows first 4 chars and last 4 chars with asterisks in between.
func maskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "****" + token[len(token)-4:]
}

// ClientConfig holds configuration for the FortiGate client.
type ClientConfig struct {
	// Host is the FortiGate API URL (e.g., "https://192.168.1.1")
	Host string
	// Token is the API token
	Token string
	// VerifySSL indicates whether to verify SSL certificates
	VerifySSL bool
	// Timeout is the HTTP request timeout
	Timeout time.Duration
}

// NewClient creates a new FortiGate API client.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	// Normalize host URL
	host := strings.TrimSuffix(cfg.Host, "/")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.VerifySSL,
		},
	}

	return &Client{
		host:  host,
		token: cfg.Token,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
	}
}

// doRequest performs an HTTP request to the FortiGate API.
func (c *Client) doRequest(method, path string) ([]byte, error) {
	url := c.host + path

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetAddressObjects retrieves all firewall address objects.
func (c *Client) GetAddressObjects() ([]AddressObject, error) {
	body, err := c.doRequest("GET", "/api/v2/cmdb/firewall/address")
	if err != nil {
		return nil, err
	}

	var response AddressResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Parse network information
	for i := range response.Results {
		parseAddressObject(&response.Results[i])
	}

	logging.Debug("fetched address objects", "count", len(response.Results))
	return response.Results, nil
}

// GetAddressGroups retrieves all firewall address groups.
func (c *Client) GetAddressGroups() ([]AddressGroup, error) {
	body, err := c.doRequest("GET", "/api/v2/cmdb/firewall/addrgrp")
	if err != nil {
		return nil, err
	}

	var response AddressGroupResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	logging.Debug("fetched address groups", "count", len(response.Results))
	return response.Results, nil
}

// TestConnection tests the connection to the FortiGate API.
func (c *Client) TestConnection() error {
	_, err := c.doRequest("GET", "/api/v2/cmdb/system/status")
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	return nil
}

// parseAddressObject parses the network information from an address object.
func parseAddressObject(obj *AddressObject) {
	switch obj.Type {
	case "ipmask":
		// Subnet format: "192.168.1.0 255.255.255.0" or "192.168.1.0/24"
		parts := strings.Fields(obj.Subnet)
		if len(parts) == 2 {
			// IP and mask format
			ip := net.ParseIP(parts[0])
			mask := net.ParseIP(parts[1])
			if ip != nil && mask != nil {
				// Convert mask to CIDR
				maskBytes := mask.To4()
				if maskBytes == nil {
					maskBytes = mask.To16()
				}
				if maskBytes != nil {
					ones, _ := net.IPMask(maskBytes).Size()
					obj.Network = &net.IPNet{
						IP:   ip,
						Mask: net.CIDRMask(ones, len(maskBytes)*8),
					}
					obj.IP = ip
				}
			}
		} else if len(parts) == 1 && strings.Contains(parts[0], "/") {
			// CIDR format
			_, network, err := net.ParseCIDR(parts[0])
			if err == nil {
				obj.Network = network
				obj.IP = network.IP
			}
		}

	case "iprange":
		// For IP ranges, we just store the start IP for simple matching
		obj.IP = net.ParseIP(obj.StartIP)
	}
}

// Host returns the FortiGate host URL.
func (c *Client) Host() string {
	return c.host
}

// String returns a string representation of the client for logging.
// The token is masked for security.
func (c *Client) String() string {
	return fmt.Sprintf("FortiGateClient{host: %s, token: %s}", c.host, maskToken(c.token))
}

// MaskedToken returns a masked version of the token for safe logging.
func (c *Client) MaskedToken() string {
	return maskToken(c.token)
}


