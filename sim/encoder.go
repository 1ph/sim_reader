package sim

import (
	"fmt"
	"strings"
)

// EncodeIMSI encodes IMSI string to SIM format
// Format: length byte + BCD swapped with leading parity nibble (9 for odd length)
func EncodeIMSI(imsi string) ([]byte, error) {
	// Remove any non-digit characters
	imsi = strings.TrimSpace(imsi)
	for _, c := range imsi {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("invalid IMSI: contains non-digit character '%c'", c)
		}
	}

	if len(imsi) < 6 || len(imsi) > 15 {
		return nil, fmt.Errorf("invalid IMSI length: %d (must be 6-15 digits)", len(imsi))
	}

	// IMSI is stored as: length | parity + first digit | digit pairs...
	// Parity nibble: 9 for odd length (most common), 1 for even length
	parity := byte(0x09) // Odd parity (IMSI length is odd)
	if len(imsi)%2 == 0 {
		parity = 0x01 // Even parity
	}

	// Calculate length in bytes (including parity byte)
	numBytes := (len(imsi) + 2) / 2 // +1 for parity nibble, rounded up
	result := make([]byte, numBytes+1)
	result[0] = byte(numBytes) // Length byte

	// First byte after length: parity nibble + first IMSI digit
	result[1] = parity | ((imsi[0] - '0') << 4)

	// Remaining digits in swapped BCD pairs
	idx := 2
	for i := 1; i < len(imsi); i += 2 {
		low := imsi[i] - '0'
		high := byte(0x0F) // Padding
		if i+1 < len(imsi) {
			high = imsi[i+1] - '0'
		}
		result[idx] = low | (high << 4)
		idx++
	}

	return result, nil
}

// EncodePLMN encodes MCC and MNC to 3-byte PLMN format
func EncodePLMN(mcc, mnc string) ([]byte, error) {
	if len(mcc) != 3 {
		return nil, fmt.Errorf("invalid MCC length: %d (must be 3)", len(mcc))
	}
	if len(mnc) < 2 || len(mnc) > 3 {
		return nil, fmt.Errorf("invalid MNC length: %d (must be 2 or 3)", len(mnc))
	}

	result := make([]byte, 3)

	// Byte 0: MCC digit 2 | MCC digit 1
	result[0] = ((mcc[1] - '0') << 4) | (mcc[0] - '0')

	// Byte 1: MNC digit 3 | MCC digit 3
	mnc3 := byte(0x0F) // 2-digit MNC
	if len(mnc) == 3 {
		mnc3 = mnc[2] - '0'
	}
	result[1] = (mnc3 << 4) | (mcc[2] - '0')

	// Byte 2: MNC digit 2 | MNC digit 1
	result[2] = ((mnc[1] - '0') << 4) | (mnc[0] - '0')

	return result, nil
}

// EncodePLMNList encodes a list of PLMNs (MCC+MNC strings like "25088")
func EncodePLMNList(plmns []string, maxBytes int) ([]byte, error) {
	result := make([]byte, maxBytes)
	// Fill with FF (empty entries)
	for i := range result {
		result[i] = 0xFF
	}

	offset := 0
	for _, plmn := range plmns {
		if offset+3 > maxBytes {
			break
		}
		if len(plmn) < 5 || len(plmn) > 6 {
			continue // Skip invalid
		}

		mcc := plmn[:3]
		mnc := plmn[3:]
		encoded, err := EncodePLMN(mcc, mnc)
		if err != nil {
			continue
		}

		copy(result[offset:], encoded)
		offset += 3
	}

	return result, nil
}

// EncodeTLVString encodes a string as TLV with tag 0x80
func EncodeTLVString(s string) []byte {
	data := []byte(s)
	result := make([]byte, 2+len(data))
	result[0] = 0x80 // Tag for string
	result[1] = byte(len(data))
	copy(result[2:], data)
	return result
}

// EncodeIMPI encodes IMS Private User Identity
// Format: TLV with tag 0x80
func EncodeIMPI(impi string, fileSize int) []byte {
	tlv := EncodeTLVString(impi)
	result := make([]byte, fileSize)
	// Fill with FF
	for i := range result {
		result[i] = 0xFF
	}
	copy(result, tlv)
	return result
}

// EncodeIMPU encodes IMS Public User Identity for a record
// Format: TLV with tag 0x80
func EncodeIMPU(impu string, recordSize int) []byte {
	tlv := EncodeTLVString(impu)
	result := make([]byte, recordSize)
	// Fill with FF
	for i := range result {
		result[i] = 0xFF
	}
	copy(result, tlv)
	return result
}

// EncodeDomain encodes Home Network Domain Name
// Format: TLV with tag 0x80
func EncodeDomain(domain string, fileSize int) []byte {
	tlv := EncodeTLVString(domain)
	result := make([]byte, fileSize)
	for i := range result {
		result[i] = 0xFF
	}
	copy(result, tlv)
	return result
}

// EncodePCSCF encodes P-CSCF address for a record
// Format: Type (1 byte) + TLV
// Type: 0x00 = FQDN, 0x01 = IPv4, 0x02 = IPv6
func EncodePCSCF(address string, recordSize int) []byte {
	result := make([]byte, recordSize)
	for i := range result {
		result[i] = 0xFF
	}

	// Determine address type
	addrType := byte(0x00) // Default FQDN

	// Check if IPv4
	if isIPv4(address) {
		addrType = 0x01
		// Parse IPv4 and encode
		parts := strings.Split(address, ".")
		if len(parts) == 4 {
			result[0] = addrType
			for i, p := range parts {
				var val int
				fmt.Sscanf(p, "%d", &val)
				result[1+i] = byte(val)
			}
			return result
		}
	}

	// FQDN: Type + TLV
	result[0] = addrType
	tlv := EncodeTLVString(address)
	copy(result[1:], tlv)

	return result
}

// isIPv4 checks if string is an IPv4 address
func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		var val int
		n, err := fmt.Sscanf(p, "%d", &val)
		if err != nil || n != 1 || val < 0 || val > 255 {
			return false
		}
	}
	return true
}

// EncodeUST encodes USIM Service Table
// Sets or clears specific service bits
func EncodeUST(currentUST []byte, services map[int]bool) []byte {
	result := make([]byte, len(currentUST))
	copy(result, currentUST)

	for serviceNum, enabled := range services {
		if serviceNum < 1 {
			continue
		}
		byteIdx := (serviceNum - 1) / 8
		bitIdx := (serviceNum - 1) % 8

		if byteIdx >= len(result) {
			continue
		}

		if enabled {
			result[byteIdx] |= (1 << bitIdx)
		} else {
			result[byteIdx] &^= (1 << bitIdx)
		}
	}

	return result
}

// EncodeIST encodes ISIM Service Table (same format as UST)
func EncodeIST(currentIST []byte, services map[int]bool) []byte {
	return EncodeUST(currentIST, services)
}

// EncodeAD encodes Administrative Data
// Byte 4 contains MNC length (2 or 3)
func EncodeAD(currentAD []byte, mncLength int) []byte {
	result := make([]byte, len(currentAD))
	copy(result, currentAD)

	if len(result) >= 4 {
		// Clear lower nibble and set MNC length
		result[3] = (result[3] & 0xF0) | byte(mncLength&0x0F)
	}

	return result
}

// ClearFPLMN creates empty FPLMN data (all 0xFF)
func ClearFPLMN(size int) []byte {
	result := make([]byte, size)
	for i := range result {
		result[i] = 0xFF
	}
	return result
}

// Service numbers for common services
const (
	UST_LOCAL_PHONEBOOK      = 1
	UST_FDN                  = 2
	UST_SMS                  = 10
	UST_MSISDN               = 21
	UST_GSM_ACCESS           = 27
	UST_DATA_DOWNLOAD_SMS_PP = 28
	UST_CALL_CONTROL         = 30
	UST_MO_SMS_CONTROL       = 31
	UST_GBA                  = 67
	UST_IMS_CALL_DISCONNECT  = 87 // VoLTE indicator
	UST_EPDG_CONFIG          = 89 // ePDG for VoWiFi
	UST_EPDG_CONFIG_PLMN     = 90
	UST_EPDG_EMERGENCY       = 93
	UST_5G_NAS_CONFIG        = 104
	UST_5G_NSSAI             = 108
	UST_SMS_OVER_IP          = 111 // Not standard, check card
	UST_SUCI_CALCULATION     = 112
	UST_WLAN_OFFLOADING      = 124 // VoWiFi

	IST_PCSCF_ADDRESS     = 1
	IST_GBA               = 2
	IST_HTTP_DIGEST       = 3
	IST_LOCAL_KEY         = 4
	IST_XCAP_CONFIG       = 5
	IST_SMS_OVER_IP       = 7
	IST_VOICE_DOMAIN_PREF = 12
)

// EncodePIN encodes a PIN/PUK code to 8 bytes
// PIN is typically 4-8 digits, PUK is 8 digits
// Format: BCD encoding padded with 0xFF
func EncodePIN(pin string) []byte {
	// Remove any non-digit characters
	pin = strings.TrimSpace(pin)
	digits := ""
	for _, c := range pin {
		if c >= '0' && c <= '9' {
			digits += string(c)
		}
	}

	// Pad or truncate to 8 bytes (16 BCD digits)
	result := make([]byte, 8)
	for i := range result {
		result[i] = 0xFF
	}

	// Encode decimal digits to BCD
	for i := 0; i < len(digits) && i < 16; i++ {
		digit := digits[i] - '0'
		byteIdx := i / 2
		if i%2 == 0 {
			result[byteIdx] = (result[byteIdx] & 0xF0) | digit
		} else {
			result[byteIdx] = (digit << 4) | (result[byteIdx] & 0x0F)
		}
	}

	return result
}
