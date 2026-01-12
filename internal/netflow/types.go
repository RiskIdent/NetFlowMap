// Package netflow provides NetFlow v9 packet parsing and collection.
package netflow

import (
	"net"
	"time"
)

// Flow represents a parsed network flow record.
type Flow struct {
	// SourceID identifies the NetFlow source device
	SourceID string
	// Timestamp when this flow was received
	Timestamp time.Time

	// Source IP address
	SrcIP net.IP
	// Destination IP address
	DstIP net.IP
	// Source port
	SrcPort uint16
	// Destination port
	DstPort uint16
	// IP protocol number (6=TCP, 17=UDP, etc.)
	Protocol uint8

	// Bytes transferred in this flow
	Bytes uint64
	// Packets transferred in this flow
	Packets uint64

	// Flow duration in milliseconds
	DurationMs uint32

	// Input interface SNMP index
	InputInterface uint32
	// Output interface SNMP index
	OutputInterface uint32

	// TCP flags (if TCP)
	TCPFlags uint8

	// Direction: true = inbound (to firewall), false = outbound (from firewall)
	Inbound bool
}

// Header represents the NetFlow v9 packet header.
type Header struct {
	// Version is the NetFlow version (9)
	Version uint16
	// Count is the number of FlowSets in this packet
	Count uint16
	// SysUptime is milliseconds since the device booted
	SysUptime uint32
	// UnixSecs is seconds since Unix epoch
	UnixSecs uint32
	// Sequence is the sequence counter
	Sequence uint32
	// SourceID identifies the observation domain
	SourceID uint32
}

// TemplateField represents a field in a template.
type TemplateField struct {
	// Type is the field type (e.g., 8 = IPV4_SRC_ADDR)
	Type uint16
	// Length is the field length in bytes
	Length uint16
}

// Template represents a NetFlow v9 template.
type Template struct {
	// ID is the template ID (>255)
	ID uint16
	// Fields is the list of fields in this template
	Fields []TemplateField
	// TotalLength is the sum of all field lengths
	TotalLength int
	// SourceIP is the IP that sent this template
	SourceIP string
	// LastSeen is when this template was last received
	LastSeen time.Time
}

// Common NetFlow v9 field types.
const (
	FieldInBytes         uint16 = 1
	FieldInPkts          uint16 = 2
	FieldFlows           uint16 = 3
	FieldProtocol        uint16 = 4
	FieldSrcTos          uint16 = 5
	FieldTCPFlags        uint16 = 6
	FieldL4SrcPort       uint16 = 7
	FieldIPv4SrcAddr     uint16 = 8
	FieldSrcMask         uint16 = 9
	FieldInputSnmp       uint16 = 10
	FieldL4DstPort       uint16 = 11
	FieldIPv4DstAddr     uint16 = 12
	FieldDstMask         uint16 = 13
	FieldOutputSnmp      uint16 = 14
	FieldIPv4NextHop     uint16 = 15
	FieldSrcAS           uint16 = 16
	FieldDstAS           uint16 = 17
	FieldLastSwitched    uint16 = 21
	FieldFirstSwitched   uint16 = 22
	FieldOutBytes        uint16 = 23
	FieldOutPkts         uint16 = 24
	FieldIPv6SrcAddr     uint16 = 27
	FieldIPv6DstAddr     uint16 = 28
	FieldIPv6FlowLabel   uint16 = 31
	FieldIcmpType        uint16 = 32
	FieldDirection       uint16 = 61
	FieldIPv4SrcPrefix   uint16 = 44
	FieldIPv4DstPrefix   uint16 = 45
	FieldApplicationID   uint16 = 95
	FieldApplicationName uint16 = 96

	// Sampling-related fields
	FieldSamplingInterval uint16 = 34
	FieldSamplingAlgorithm uint16 = 35
	FieldSamplerName       uint16 = 48
	FieldSamplerMode       uint16 = 49
	FieldSamplerInterval   uint16 = 50
)

// SamplingInfo contains information about flow sampling configuration.
type SamplingInfo struct {
	// Interval is the sampling interval (e.g., 100 means 1:100 sampling)
	Interval uint32
	// Algorithm describes the sampling method (1=deterministic, 2=random)
	Algorithm uint8
	// Mode describes the sampler mode
	Mode uint8
	// Active indicates if sampling info was received
	Active bool
}

// FlowSet types.
const (
	FlowSetIDTemplate        uint16 = 0
	FlowSetIDOptionsTemplate uint16 = 1
	FlowSetIDDataMin         uint16 = 256
)

// Protocol numbers.
const (
	ProtocolICMP uint8 = 1
	ProtocolTCP  uint8 = 6
	ProtocolUDP  uint8 = 17
)

// ProtocolName returns the name of the protocol.
func ProtocolName(proto uint8) string {
	switch proto {
	case ProtocolICMP:
		return "ICMP"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return "OTHER"
	}
}

