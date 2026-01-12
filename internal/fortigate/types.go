// Package fortigate provides a client for the FortiGate REST API.
package fortigate

import "net"

// AddressObject represents a FortiGate firewall address object.
type AddressObject struct {
	// Name is the object name
	Name string `json:"name"`
	// Type is the address type (ipmask, iprange, fqdn, geography, etc.)
	Type string `json:"type"`
	// Subnet is the IP/mask for ipmask type (e.g., "192.168.1.0 255.255.255.0")
	Subnet string `json:"subnet,omitempty"`
	// StartIP is the start of range for iprange type
	StartIP string `json:"start-ip,omitempty"`
	// EndIP is the end of range for iprange type
	EndIP string `json:"end-ip,omitempty"`
	// FQDN is the domain name for fqdn type
	FQDN string `json:"fqdn,omitempty"`
	// Country is the country code for geography type
	Country string `json:"country,omitempty"`
	// Comment is the object description
	Comment string `json:"comment,omitempty"`

	// Parsed fields (not from API)
	Network *net.IPNet `json:"-"`
	IP      net.IP     `json:"-"`
}

// AddressGroup represents a FortiGate address group.
type AddressGroup struct {
	// Name is the group name
	Name string `json:"name"`
	// Members is the list of member objects
	Members []GroupMember `json:"member"`
	// Comment is the group description
	Comment string `json:"comment,omitempty"`
}

// GroupMember represents a member of an address group.
type GroupMember struct {
	Name string `json:"name"`
}

// APIResponse represents a generic FortiGate API response.
type APIResponse struct {
	HTTPMethod string `json:"http_method"`
	Results    any    `json:"results"`
	VDOM       string `json:"vdom"`
	Path       string `json:"path"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status"`
	Serial     string `json:"serial"`
	Version    string `json:"version"`
	Build      int    `json:"build"`
}

// AddressResponse represents the API response for address objects.
type AddressResponse struct {
	HTTPMethod string          `json:"http_method"`
	Results    []AddressObject `json:"results"`
	VDOM       string          `json:"vdom"`
	Path       string          `json:"path"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	HTTPStatus int             `json:"http_status"`
	Serial     string          `json:"serial"`
	Version    string          `json:"version"`
	Build      int             `json:"build"`
}

// AddressGroupResponse represents the API response for address groups.
type AddressGroupResponse struct {
	HTTPMethod string         `json:"http_method"`
	Results    []AddressGroup `json:"results"`
	VDOM       string         `json:"vdom"`
	Path       string         `json:"path"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	HTTPStatus int            `json:"http_status"`
}


