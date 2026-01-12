package netflow

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// ParseResult contains the results of parsing a NetFlow packet.
type ParseResult struct {
	Flows        []Flow
	SamplingInfo *SamplingInfo // nil if no sampling info in this packet
}

// OptionsTemplate represents a NetFlow v9 options template.
type OptionsTemplate struct {
	ID           uint16
	ScopeFields  []TemplateField
	OptionFields []TemplateField
	TotalLength  int
}

// Parser parses NetFlow v9 packets.
type Parser struct {
	templates        *TemplateCache
	optionsTemplates map[string]map[uint16]*OptionsTemplate // sourceIP -> templateID -> template
}

// NewParser creates a new NetFlow v9 parser.
func NewParser(templates *TemplateCache) *Parser {
	return &Parser{
		templates:        templates,
		optionsTemplates: make(map[string]map[uint16]*OptionsTemplate),
	}
}

// getOptionsTemplate retrieves an options template for a source and template ID.
func (p *Parser) getOptionsTemplate(sourceIP string, templateID uint16) *OptionsTemplate {
	if sourceTemplates, ok := p.optionsTemplates[sourceIP]; ok {
		return sourceTemplates[templateID]
	}
	return nil
}

// ParsePacket parses a NetFlow v9 packet and returns the flows.
func (p *Parser) ParsePacket(data []byte, sourceIP string) ([]Flow, error) {
	result, err := p.ParsePacketWithOptions(data, sourceIP)
	if err != nil {
		return nil, err
	}
	return result.Flows, nil
}

// ParsePacketWithOptions parses a NetFlow v9 packet and returns flows plus sampling info.
func (p *Parser) ParsePacketWithOptions(data []byte, sourceIP string) (*ParseResult, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	// Parse header
	header, err := p.parseHeader(data[:20])
	if err != nil {
		return nil, err
	}

	if header.Version != 9 {
		return nil, fmt.Errorf("unsupported NetFlow version: %d", header.Version)
	}

	// Parse FlowSets
	result := &ParseResult{}
	offset := 20

	for i := 0; i < int(header.Count) && offset < len(data); i++ {
		if offset+4 > len(data) {
			break
		}

		flowSetID := binary.BigEndian.Uint16(data[offset:])
		flowSetLength := binary.BigEndian.Uint16(data[offset+2:])

		if flowSetLength < 4 || offset+int(flowSetLength) > len(data) {
			break
		}

		flowSetData := data[offset+4 : offset+int(flowSetLength)]

		switch {
		case flowSetID == FlowSetIDTemplate:
			// Template FlowSet
			if err := p.parseTemplateFlowSet(flowSetData, sourceIP); err != nil {
				// Log but continue
			}

		case flowSetID == FlowSetIDOptionsTemplate:
			// Options Template FlowSet - parse for sampling info
			if samplingInfo := p.parseOptionsTemplateFlowSet(flowSetData, sourceIP); samplingInfo != nil {
				result.SamplingInfo = samplingInfo
			}

		case flowSetID >= FlowSetIDDataMin:
			// Check if this is an options data record
			if optsTmpl := p.getOptionsTemplate(sourceIP, flowSetID); optsTmpl != nil {
				// Parse options data for sampling info
				if samplingInfo := p.parseOptionsDataRecord(flowSetData, optsTmpl); samplingInfo != nil {
					result.SamplingInfo = samplingInfo
				}
			} else {
				// Regular data FlowSet
				parsedFlows, err := p.parseDataFlowSet(flowSetData, sourceIP, flowSetID, header)
				if err == nil {
					result.Flows = append(result.Flows, parsedFlows...)
				}
			}
		}

		offset += int(flowSetLength)

		// Align to 4-byte boundary
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	return result, nil
}

// parseHeader parses the NetFlow v9 header.
func (p *Parser) parseHeader(data []byte) (*Header, error) {
	return &Header{
		Version:   binary.BigEndian.Uint16(data[0:2]),
		Count:     binary.BigEndian.Uint16(data[2:4]),
		SysUptime: binary.BigEndian.Uint32(data[4:8]),
		UnixSecs:  binary.BigEndian.Uint32(data[8:12]),
		Sequence:  binary.BigEndian.Uint32(data[12:16]),
		SourceID:  binary.BigEndian.Uint32(data[16:20]),
	}, nil
}

// parseTemplateFlowSet parses a template FlowSet.
func (p *Parser) parseTemplateFlowSet(data []byte, sourceIP string) error {
	offset := 0

	for offset+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[offset:])
		fieldCount := binary.BigEndian.Uint16(data[offset+2:])
		offset += 4

		if templateID < FlowSetIDDataMin {
			// Invalid template ID
			continue
		}

		if offset+int(fieldCount)*4 > len(data) {
			return fmt.Errorf("template extends beyond FlowSet")
		}

		fields := make([]TemplateField, fieldCount)
		totalLength := 0

		for i := 0; i < int(fieldCount); i++ {
			fields[i] = TemplateField{
				Type:   binary.BigEndian.Uint16(data[offset:]),
				Length: binary.BigEndian.Uint16(data[offset+2:]),
			}
			totalLength += int(fields[i].Length)
			offset += 4
		}

		tmpl := &Template{
			ID:          templateID,
			Fields:      fields,
			TotalLength: totalLength,
		}

		p.templates.Set(sourceIP, tmpl)
	}

	return nil
}

// parseOptionsTemplateFlowSet parses an options template FlowSet and stores it.
func (p *Parser) parseOptionsTemplateFlowSet(data []byte, sourceIP string) *SamplingInfo {
	if len(data) < 6 {
		return nil
	}

	offset := 0
	var hasSamplingFields bool

	for offset+6 <= len(data) {
		// Options Template header
		templateID := binary.BigEndian.Uint16(data[offset:])
		optionScopeLength := binary.BigEndian.Uint16(data[offset+2:])
		optionLength := binary.BigEndian.Uint16(data[offset+4:])
		offset += 6

		if templateID < FlowSetIDDataMin {
			continue
		}

		// Parse scope fields
		scopeFieldCount := int(optionScopeLength) / 4
		scopeFields := make([]TemplateField, 0, scopeFieldCount)
		totalLength := 0

		for i := 0; i < scopeFieldCount && offset+4 <= len(data); i++ {
			field := TemplateField{
				Type:   binary.BigEndian.Uint16(data[offset:]),
				Length: binary.BigEndian.Uint16(data[offset+2:]),
			}
			scopeFields = append(scopeFields, field)
			totalLength += int(field.Length)
			offset += 4
		}

		// Parse option fields
		optionFieldCount := int(optionLength) / 4
		optionFields := make([]TemplateField, 0, optionFieldCount)

		for i := 0; i < optionFieldCount && offset+4 <= len(data); i++ {
			field := TemplateField{
				Type:   binary.BigEndian.Uint16(data[offset:]),
				Length: binary.BigEndian.Uint16(data[offset+2:]),
			}
			optionFields = append(optionFields, field)
			totalLength += int(field.Length)
			offset += 4

			// Check if this template contains sampling fields
			switch field.Type {
			case FieldSamplingInterval, FieldSamplerInterval, FieldSamplingAlgorithm, FieldSamplerMode:
				hasSamplingFields = true
			}
		}

		// Store the options template
		optsTmpl := &OptionsTemplate{
			ID:           templateID,
			ScopeFields:  scopeFields,
			OptionFields: optionFields,
			TotalLength:  totalLength,
		}

		if p.optionsTemplates[sourceIP] == nil {
			p.optionsTemplates[sourceIP] = make(map[uint16]*OptionsTemplate)
		}
		p.optionsTemplates[sourceIP][templateID] = optsTmpl
	}

	if hasSamplingFields {
		// Return a placeholder indicating sampling template was received
		return &SamplingInfo{Active: true}
	}
	return nil
}

// parseOptionsDataRecord parses an options data record for sampling information.
func (p *Parser) parseOptionsDataRecord(data []byte, tmpl *OptionsTemplate) *SamplingInfo {
	if len(data) < tmpl.TotalLength {
		return nil
	}

	offset := 0
	info := &SamplingInfo{}

	// Skip scope fields
	for _, field := range tmpl.ScopeFields {
		offset += int(field.Length)
	}

	// Parse option fields
	for _, field := range tmpl.OptionFields {
		if offset+int(field.Length) > len(data) {
			break
		}

		fieldData := data[offset : offset+int(field.Length)]

		switch field.Type {
		case FieldSamplingInterval, FieldSamplerInterval:
			info.Interval = uint32(parseUint(fieldData))
			info.Active = true
		case FieldSamplingAlgorithm:
			if len(fieldData) >= 1 {
				info.Algorithm = fieldData[0]
			}
		case FieldSamplerMode:
			if len(fieldData) >= 1 {
				info.Mode = fieldData[0]
			}
		}

		offset += int(field.Length)
	}

	if info.Active && info.Interval > 0 {
		return info
	}
	return nil
}

// parseDataFlowSet parses a data FlowSet using the appropriate template.
func (p *Parser) parseDataFlowSet(data []byte, sourceIP string, templateID uint16, header *Header) ([]Flow, error) {
	tmpl := p.templates.Get(sourceIP, templateID)
	if tmpl == nil {
		return nil, fmt.Errorf("unknown template: %d", templateID)
	}

	var flows []Flow
	offset := 0

	for offset+tmpl.TotalLength <= len(data) {
		flow, err := p.parseDataRecord(data[offset:offset+tmpl.TotalLength], tmpl, sourceIP, header)
		if err == nil {
			flows = append(flows, flow)
		}
		offset += tmpl.TotalLength
	}

	return flows, nil
}

// parseDataRecord parses a single data record using a template.
func (p *Parser) parseDataRecord(data []byte, tmpl *Template, sourceIP string, header *Header) (Flow, error) {
	flow := Flow{
		SourceID:  sourceIP,
		Timestamp: time.Unix(int64(header.UnixSecs), 0),
	}

	offset := 0

	for _, field := range tmpl.Fields {
		if offset+int(field.Length) > len(data) {
			break
		}

		fieldData := data[offset : offset+int(field.Length)]

		switch field.Type {
		case FieldIPv4SrcAddr:
			if len(fieldData) >= 4 {
				flow.SrcIP = net.IP(fieldData[:4])
			}

		case FieldIPv4DstAddr:
			if len(fieldData) >= 4 {
				flow.DstIP = net.IP(fieldData[:4])
			}

		case FieldIPv6SrcAddr:
			if len(fieldData) >= 16 {
				flow.SrcIP = net.IP(fieldData[:16])
			}

		case FieldIPv6DstAddr:
			if len(fieldData) >= 16 {
				flow.DstIP = net.IP(fieldData[:16])
			}

		case FieldL4SrcPort:
			if len(fieldData) >= 2 {
				flow.SrcPort = binary.BigEndian.Uint16(fieldData)
			}

		case FieldL4DstPort:
			if len(fieldData) >= 2 {
				flow.DstPort = binary.BigEndian.Uint16(fieldData)
			}

		case FieldProtocol:
			if len(fieldData) >= 1 {
				flow.Protocol = fieldData[0]
			}

		case FieldInBytes:
			flow.Bytes = parseUint(fieldData)

		case FieldInPkts:
			flow.Packets = parseUint(fieldData)

		case FieldOutBytes:
			if flow.Bytes == 0 {
				flow.Bytes = parseUint(fieldData)
			}

		case FieldOutPkts:
			if flow.Packets == 0 {
				flow.Packets = parseUint(fieldData)
			}

		case FieldInputSnmp:
			flow.InputInterface = uint32(parseUint(fieldData))

		case FieldOutputSnmp:
			flow.OutputInterface = uint32(parseUint(fieldData))

		case FieldTCPFlags:
			if len(fieldData) >= 1 {
				flow.TCPFlags = fieldData[0]
			}

		case FieldFirstSwitched, FieldLastSwitched:
			// Used for duration calculation
			if field.Type == FieldFirstSwitched && len(fieldData) >= 4 {
				firstSwitched := binary.BigEndian.Uint32(fieldData)
				if header.SysUptime > firstSwitched {
					flow.DurationMs = header.SysUptime - firstSwitched
				}
			}

		case FieldDirection:
			if len(fieldData) >= 1 {
				flow.Inbound = fieldData[0] == 0 // 0 = ingress, 1 = egress
			}
		}

		offset += int(field.Length)
	}

	return flow, nil
}

// parseUint parses an unsigned integer of variable length.
func parseUint(data []byte) uint64 {
	switch len(data) {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(data))
	case 4:
		return uint64(binary.BigEndian.Uint32(data))
	case 8:
		return binary.BigEndian.Uint64(data)
	default:
		// Handle non-standard lengths
		var val uint64
		for _, b := range data {
			val = (val << 8) | uint64(b)
		}
		return val
	}
}

