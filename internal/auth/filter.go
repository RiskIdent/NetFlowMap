package auth

import (
	"net"
)

const (
	// HiddenIP is the placeholder for hidden IP addresses.
	HiddenIP = "[hidden]"
	// PrivateIP is the placeholder for private IP addresses.
	PrivateIP = "[private]"
)

// FlowData represents the flow data fields that can be filtered.
// This is a generic interface to avoid circular imports.
type FlowData interface {
	GetLocalIP() string
	GetRemoteIP() string
	SetLocalIP(string)
	SetRemoteIP(string)
	SetLocalPort(uint16)
	SetRemotePort(uint16)
	ClearRemoteLocation()
	ClearRemoteDetails()
}

// FilterFlowForRole filters flow data based on the user's role.
// Returns filtered IPs and flags indicating what should be hidden.
// For anonymous users: IPs are hidden but geo location is preserved for map visualization.
func FilterFlowForRole(role Role, localIP, remoteIP string) (filteredLocalIP, filteredRemoteIP string, clearLocalPort, clearRemotePort bool, hideRemoteLocation, hideRemoteDetails bool) {
	switch role {
	case RoleAdmin:
		// Admin sees everything
		return localIP, remoteIP, false, false, false, false

	case RoleUser:
		// User sees public IPs, private IPs are hidden
		filteredLocalIP = localIP
		filteredRemoteIP = remoteIP

		if isPrivateIP(localIP) {
			filteredLocalIP = PrivateIP
			clearLocalPort = true
		}

		if isPrivateIP(remoteIP) {
			filteredRemoteIP = PrivateIP
			clearRemotePort = true
			hideRemoteLocation = true
			hideRemoteDetails = true
		}

		return filteredLocalIP, filteredRemoteIP, clearLocalPort, clearRemotePort, hideRemoteLocation, hideRemoteDetails

	default: // Anonymous
		// Anonymous: IPs hidden, but geo location preserved for map visualization
		// They can see the lines on the map, but not the actual IP addresses
		return HiddenIP, HiddenIP, true, true, false, true
	}
}

// ShouldHideFlow returns true if the entire flow should be hidden from the user.
// Currently, we show all flows but with filtered data.
func ShouldHideFlow(role Role) bool {
	// For now, we show all flows but filter the data
	// In the future, we might want to hide certain flows entirely
	return false
}

// isPrivateIP checks if an IP address is private.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check for IPv4
	if ip4 := ip.To4(); ip4 != nil {
		privateRanges := []struct {
			start net.IP
			end   net.IP
		}{
			{net.IPv4(10, 0, 0, 0), net.IPv4(10, 255, 255, 255)},
			{net.IPv4(172, 16, 0, 0), net.IPv4(172, 31, 255, 255)},
			{net.IPv4(192, 168, 0, 0), net.IPv4(192, 168, 255, 255)},
			{net.IPv4(127, 0, 0, 0), net.IPv4(127, 255, 255, 255)},
			{net.IPv4(169, 254, 0, 0), net.IPv4(169, 254, 255, 255)},
		}

		for _, r := range privateRanges {
			if bytesInRange(ip4, r.start, r.end) {
				return true
			}
		}
		return false
	}

	// Check for IPv6
	if ip6 := ip.To16(); ip6 != nil {
		// Check for loopback
		if ip.IsLoopback() {
			return true
		}
		// Check for link-local
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		// Check for unique local (fc00::/7)
		if ip6[0] == 0xfc || ip6[0] == 0xfd {
			return true
		}
	}

	return false
}

// bytesInRange checks if an IP is within a range.
func bytesInRange(ip, start, end net.IP) bool {
	ip = ip.To4()
	start = start.To4()
	end = end.To4()

	if ip == nil || start == nil || end == nil {
		return false
	}

	for i := 0; i < 4; i++ {
		if ip[i] < start[i] {
			return false
		}
		if ip[i] > end[i] {
			return false
		}
	}

	return true
}

// CanSeeIP returns true if the user with the given role can see the specified IP.
func CanSeeIP(role Role, ipStr string) bool {
	switch role {
	case RoleAdmin:
		return true
	case RoleUser:
		return !isPrivateIP(ipStr)
	default:
		return false
	}
}

