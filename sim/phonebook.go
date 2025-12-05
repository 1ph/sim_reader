package sim

import (
	"fmt"
	"sim_reader/card"
	"strings"
)

// PhonebookEntry represents a single phonebook entry
type PhonebookEntry struct {
	Index  int
	Name   string
	Number string
}

// SMSMessage represents a single SMS message
type SMSMessage struct {
	Index  int
	Status string
	Number string
	Text   string
	Raw    []byte
}

// ReadPhonebook reads phonebook entries from EF_ADN
func ReadPhonebook(reader *card.Reader) ([]PhonebookEntry, error) {
	// Select USIM
	resp, err := reader.Select(GetUSIMAID())
	if err != nil {
		return nil, fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return nil, fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_ADN (0x6F3A)
	resp, err = reader.Select([]byte{0x6F, 0x3A})
	if err != nil {
		return nil, fmt.Errorf("failed to select EF_ADN: %w", err)
	}
	if !resp.IsOK() {
		return nil, fmt.Errorf("EF_ADN selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get record size from FCP
	recordLen := parseFCPRecordSize(resp.Data)
	if recordLen == 0 {
		recordLen = 30 // Default ADN record size
	}

	var entries []PhonebookEntry

	// Read up to 250 records (typical max for ADN)
	for i := 1; i <= 250; i++ {
		resp, err = reader.ReadRecord(byte(i), byte(recordLen))
		if err != nil {
			break
		}
		if !resp.IsOK() {
			break
		}

		entry := decodeADNRecord(resp.Data, i)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	return entries, nil
}

// decodeADNRecord decodes a single ADN record
// Format: Alpha-ID (X bytes) + BCD-len (1) + TON/NPI (1) + Number (10) + CCP (1) + Ext (1)
func decodeADNRecord(data []byte, index int) *PhonebookEntry {
	if len(data) < 14 {
		return nil
	}

	// Check if record is empty (all FF)
	isEmpty := true
	for _, b := range data {
		if b != 0xFF {
			isEmpty = false
			break
		}
	}
	if isEmpty {
		return nil
	}

	// Alpha identifier is everything except last 14 bytes
	alphaLen := len(data) - 14
	if alphaLen < 0 {
		alphaLen = 0
	}

	// Decode name (GSM 7-bit or UCS2)
	name := decodeAlphaID(data[:alphaLen])

	// Decode number (last 14 bytes)
	bcdLen := data[alphaLen]
	if bcdLen == 0xFF || bcdLen == 0 {
		if name == "" {
			return nil
		}
		return &PhonebookEntry{Index: index, Name: name, Number: ""}
	}

	tonNpi := data[alphaLen+1]
	numberBytes := data[alphaLen+2 : alphaLen+12]
	number := decodeBCDNumber(numberBytes, tonNpi)

	if name == "" && number == "" {
		return nil
	}

	return &PhonebookEntry{
		Index:  index,
		Name:   name,
		Number: number,
	}
}

// decodeAlphaID decodes GSM 7-bit or UCS2 alpha identifier
func decodeAlphaID(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Trim trailing FF
	end := len(data)
	for end > 0 && data[end-1] == 0xFF {
		end--
	}
	if end == 0 {
		return ""
	}
	data = data[:end]

	// Check for UCS2 encoding
	if len(data) > 0 && (data[0] == 0x80 || data[0] == 0x81 || data[0] == 0x82) {
		// UCS2 encoded - simplified decode
		var result strings.Builder
		for i := 1; i+1 < len(data); i += 2 {
			if data[i] == 0xFF && data[i+1] == 0xFF {
				break
			}
			char := rune(int(data[i])<<8 | int(data[i+1]))
			if char > 0 && char < 0xFFFF {
				result.WriteRune(char)
			}
		}
		return result.String()
	}

	// GSM 7-bit default alphabet (simplified - just use ASCII printable)
	var result strings.Builder
	for _, b := range data {
		if b >= 0x20 && b < 0x7F {
			result.WriteByte(b)
		} else if b == 0x00 {
			result.WriteByte('@')
		}
	}
	return strings.TrimSpace(result.String())
}

// decodeBCDNumber decodes BCD phone number
func decodeBCDNumber(data []byte, tonNpi byte) string {
	var result strings.Builder

	// International number prefix
	if (tonNpi & 0x70) == 0x10 {
		result.WriteByte('+')
	}

	for _, b := range data {
		low := b & 0x0F
		high := (b >> 4) & 0x0F

		if low <= 9 {
			result.WriteByte('0' + low)
		} else if low == 0x0A {
			result.WriteByte('*')
		} else if low == 0x0B {
			result.WriteByte('#')
		} else if low == 0x0F {
			break
		}

		if high <= 9 {
			result.WriteByte('0' + high)
		} else if high == 0x0A {
			result.WriteByte('*')
		} else if high == 0x0B {
			result.WriteByte('#')
		} else if high == 0x0F {
			break
		}
	}

	return result.String()
}

// ReadSMS reads SMS messages from EF_SMS
func ReadSMS(reader *card.Reader) ([]SMSMessage, error) {
	// Select USIM
	resp, err := reader.Select(GetUSIMAID())
	if err != nil {
		return nil, fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return nil, fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_SMS (0x6F3C)
	resp, err = reader.Select([]byte{0x6F, 0x3C})
	if err != nil {
		return nil, fmt.Errorf("failed to select EF_SMS: %w", err)
	}
	if !resp.IsOK() {
		return nil, fmt.Errorf("EF_SMS selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get record size from FCP
	recordLen := parseFCPRecordSize(resp.Data)
	if recordLen == 0 {
		recordLen = 176 // Default SMS record size
	}

	var messages []SMSMessage

	// Read up to 50 records (typical max for SMS)
	for i := 1; i <= 50; i++ {
		resp, err = reader.ReadRecord(byte(i), byte(recordLen))
		if err != nil {
			break
		}
		if !resp.IsOK() {
			break
		}

		msg := decodeSMSRecord(resp.Data, i)
		if msg != nil {
			messages = append(messages, *msg)
		}
	}

	return messages, nil
}

// decodeSMSRecord decodes a single SMS record
// Format: Status (1) + TPDU (up to 175)
func decodeSMSRecord(data []byte, index int) *SMSMessage {
	if len(data) < 2 {
		return nil
	}

	status := data[0]
	// Status: 0x00 = free, 0x01 = read, 0x03 = unread, 0x05 = sent, 0x07 = unsent
	if status == 0x00 || status == 0xFF {
		return nil // Empty slot
	}

	var statusStr string
	switch status & 0x07 {
	case 0x01:
		statusStr = "Read"
	case 0x03:
		statusStr = "Unread"
	case 0x05:
		statusStr = "Sent"
	case 0x07:
		statusStr = "Unsent"
	default:
		statusStr = fmt.Sprintf("Status:0x%02X", status)
	}

	// TPDU parsing (simplified)
	tpdu := data[1:]

	// For SMS-DELIVER (incoming): first byte is address length
	// This is a simplified parser - full SMS parsing is complex
	msg := &SMSMessage{
		Index:  index,
		Status: statusStr,
		Raw:    data,
	}

	// Try to extract sender/recipient number
	if len(tpdu) > 2 {
		addrLen := int(tpdu[0])
		if addrLen > 0 && addrLen < 20 && len(tpdu) > 2+addrLen/2+1 {
			tonNpi := tpdu[1]
			numBytes := (addrLen + 1) / 2
			if len(tpdu) > 2+numBytes {
				msg.Number = decodeBCDNumber(tpdu[2:2+numBytes], tonNpi)
			}
		}
	}

	// Extract text (simplified - assumes 7-bit GSM encoding at fixed offset)
	// Real SMS parsing would need to handle TP-PID, TP-DCS, TP-SCTS, TP-UDL properly
	textOffset := 20 // Approximate offset after headers
	if len(tpdu) > textOffset {
		msg.Text = decodeGSM7bit(tpdu[textOffset:])
	}

	return msg
}

// decodeGSM7bit decodes GSM 7-bit packed text (simplified)
func decodeGSM7bit(data []byte) string {
	// Simplified: just extract printable ASCII
	var result strings.Builder
	for _, b := range data {
		if b >= 0x20 && b < 0x7F {
			result.WriteByte(b)
		} else if b == 0x00 {
			result.WriteByte('@')
		}
	}
	text := strings.TrimRight(result.String(), "\x00\xFF ")
	if len(text) > 160 {
		text = text[:160]
	}
	return text
}

