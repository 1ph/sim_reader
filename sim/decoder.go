package sim

import (
	"encoding/hex"
	"fmt"
	"sim_reader/dictionaries"
	"sort"
	"strings"
)

// DecodeICCID decodes ICCID from BCD format
// ICCID is stored as 10 bytes in swapped BCD
func DecodeICCID(data []byte) string {
	if len(data) < 10 {
		return hex.EncodeToString(data)
	}
	return decodeBCDSwapped(data[:10])
}

// DecodeIMSI decodes IMSI from SIM format
// First byte is length, rest is BCD swapped with leading 0x9 nibble
func DecodeIMSI(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	length := int(data[0])
	if length > len(data)-1 {
		length = len(data) - 1
	}

	// IMSI format: length byte, then BCD with first nibble = 9 (odd) or 1 (even)
	bcd := decodeBCDSwapped(data[1 : length+1])
	if len(bcd) > 0 {
		// Skip the parity nibble (first digit is 9 or 1)
		return bcd[1:]
	}
	return bcd
}

// DecodeMSISDN decodes phone number from alpha-id + BCD format
// Format: alpha-id (variable), BCD length, TON/NPI, BCD number, capability/ext
func DecodeMSISDN(data []byte) string {
	if len(data) < 14 {
		return ""
	}

	// Find the BCD number part (last 14 bytes typically)
	// Structure: Alpha-ID | BCD-length | TON-NPI | BCD-number | CCP | Ext
	// We look for non-FF data from the end

	// Standard MSISDN record is X + 14 bytes where X is alpha length
	// Last 14 bytes: BCD-len(1) + TON-NPI(1) + Number(10) + CCP(1) + Ext(1)

	bcdStart := len(data) - 14
	if bcdStart < 0 {
		bcdStart = 0
	}

	bcdLen := int(data[bcdStart])
	if bcdLen == 0xFF || bcdLen == 0 || bcdLen > 11 {
		return ""
	}

	tonNpi := data[bcdStart+1]
	numData := data[bcdStart+2 : bcdStart+2+bcdLen-1]

	number := decodeBCDSwapped(numData)
	// Remove trailing F
	number = strings.TrimRight(number, "F")

	// Add + for international numbers (TON = 001 = international)
	if (tonNpi & 0x70) == 0x10 {
		number = "+" + number
	}

	return number
}

// DecodeSPN decodes Service Provider Name
func DecodeSPN(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// First byte is display condition, rest is the name
	name := data[1:]
	// Find null terminator or 0xFF padding
	for i, b := range name {
		if b == 0xFF || b == 0x00 {
			name = name[:i]
			break
		}
	}
	return string(name)
}

// DecodePLMN decodes a 3-byte PLMN (MCC-MNC)
// Format: MCC digit 2 | MCC digit 1 | MNC digit 3 | MCC digit 3 | MNC digit 2 | MNC digit 1
func DecodePLMN(data []byte) (mcc, mnc string) {
	if len(data) < 3 {
		return "", ""
	}

	mcc1 := data[0] & 0x0F
	mcc2 := (data[0] >> 4) & 0x0F
	mcc3 := data[1] & 0x0F
	mnc3 := (data[1] >> 4) & 0x0F
	mnc1 := data[2] & 0x0F
	mnc2 := (data[2] >> 4) & 0x0F

	mcc = fmt.Sprintf("%d%d%d", mcc1, mcc2, mcc3)

	if mnc3 == 0x0F {
		// 2-digit MNC
		mnc = fmt.Sprintf("%d%d", mnc1, mnc2)
	} else {
		// 3-digit MNC
		mnc = fmt.Sprintf("%d%d%d", mnc1, mnc2, mnc3)
	}

	return mcc, mnc
}

// DecodePLMNList decodes a list of PLMNs
func DecodePLMNList(data []byte) []string {
	var plmns []string
	for i := 0; i+3 <= len(data); i += 3 {
		chunk := data[i : i+3]
		// Skip empty entries (all FF)
		if chunk[0] == 0xFF && chunk[1] == 0xFF && chunk[2] == 0xFF {
			continue
		}
		mcc, mnc := DecodePLMN(chunk)
		if mcc != "" && mcc != "fff" {
			plmns = append(plmns, mcc+mnc)
		}
	}
	return plmns
}

// DecodePLMNwACT decodes PLMN with Access Technology (5 bytes each)
func DecodePLMNwACT(data []byte) []PLMNwACT {
	var result []PLMNwACT
	for i := 0; i+5 <= len(data); i += 5 {
		chunk := data[i : i+5]
		// Skip empty entries
		if chunk[0] == 0xFF && chunk[1] == 0xFF && chunk[2] == 0xFF {
			continue
		}
		mcc, mnc := DecodePLMN(chunk[:3])
		if mcc == "" || mcc == "fff" {
			continue
		}

		act := uint16(chunk[3])<<8 | uint16(chunk[4])
		result = append(result, PLMNwACT{
			MCC:  mcc,
			MNC:  mnc,
			ACT:  act,
			Tech: DecodeACT(act),
		})
	}
	return result
}

// PLMNwACT represents a PLMN with access technology
type PLMNwACT struct {
	MCC  string
	MNC  string
	ACT  uint16
	Tech []string
}

// DecodeACT decodes Access Technology bits
func DecodeACT(act uint16) []string {
	var techs []string
	if act&0x8000 != 0 {
		techs = append(techs, "UTRAN")
	}
	if act&0x4000 != 0 {
		techs = append(techs, "E-UTRAN")
	}
	if act&0x0080 != 0 {
		techs = append(techs, "GSM")
	}
	if act&0x0040 != 0 {
		techs = append(techs, "GSM COMPACT")
	}
	if act&0x0020 != 0 {
		techs = append(techs, "cdma2000 HRPD")
	}
	if act&0x0010 != 0 {
		techs = append(techs, "cdma2000 1xRTT")
	}
	if act&0x0008 != 0 {
		techs = append(techs, "NR") // 5G
	}
	if act&0x0004 != 0 {
		techs = append(techs, "NG-RAN") // 5G SA
	}
	return techs
}

// DecodeUST decodes USIM Service Table
func DecodeUST(data []byte) map[int]bool {
	services := make(map[int]bool)
	for byteIdx, b := range data {
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			serviceNum := byteIdx*8 + bitIdx + 1
			if b&(1<<bitIdx) != 0 {
				services[serviceNum] = true
			}
		}
	}
	return services
}

// DecodeIST decodes ISIM Service Table
func DecodeIST(data []byte) map[int]bool {
	return DecodeUST(data) // Same format
}

// DecodeIMPI decodes IMS Private User Identity (NAI format)
// TLV format with tag 0x80
func DecodeIMPI(data []byte) string {
	return decodeTLVString(data)
}

// DecodeIMPU decodes IMS Public User Identity (SIP URI)
// TLV format with tag 0x80
func DecodeIMPU(data []byte) string {
	return decodeTLVString(data)
}

// DecodeDomain decodes Home Network Domain Name
// TLV format with tag 0x80
func DecodeDomain(data []byte) string {
	return decodeTLVString(data)
}

// DecodePCSCF decodes P-CSCF address
// Can be IPv4, IPv6, or FQDN in TLV format
func DecodePCSCF(data []byte) string {
	if len(data) < 3 {
		return ""
	}

	// Format: Type (1 byte) + TLV
	// Type: 0x00 = FQDN, 0x01 = IPv4, 0x02 = IPv6
	addrType := data[0]

	switch addrType {
	case 0x00: // FQDN
		return decodeTLVString(data[1:])
	case 0x01: // IPv4
		if len(data) >= 5 {
			return fmt.Sprintf("%d.%d.%d.%d", data[1], data[2], data[3], data[4])
		}
	case 0x02: // IPv6
		if len(data) >= 17 {
			return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
				data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16])
		}
	default:
		// Try to decode as TLV string anyway
		return decodeTLVString(data)
	}

	return hex.EncodeToString(data)
}

// DecodeAD decodes Administrative Data
type AdminData struct {
	UEMode      string // Normal, Type Approval, etc.
	SpecificFac []byte
	MNCLength   int
}

func DecodeAD(data []byte) AdminData {
	ad := AdminData{}
	if len(data) < 3 {
		return ad
	}

	// Byte 1: UE operation mode
	switch data[0] {
	case 0x00:
		ad.UEMode = "Normal"
	case 0x01:
		ad.UEMode = "Type Approval"
	case 0x02:
		ad.UEMode = "Normal + specific facilities"
	case 0x04:
		ad.UEMode = "Type Approval + specific facilities"
	case 0x80:
		ad.UEMode = "Cell Test"
	default:
		ad.UEMode = fmt.Sprintf("Unknown (0x%02X)", data[0])
	}

	// Bytes 2-3: additional info / specific facilities
	ad.SpecificFac = data[1:3]

	// Byte 4 (if present): MNC length in IMSI
	if len(data) >= 4 {
		ad.MNCLength = int(data[3] & 0x0F)
	}

	return ad
}

// DecodeACC decodes Access Control Class
func DecodeACC(data []byte) []int {
	if len(data) < 2 {
		return nil
	}
	acc := uint16(data[0])<<8 | uint16(data[1])
	var classes []int
	for i := 0; i < 16; i++ {
		if acc&(1<<i) != 0 {
			classes = append(classes, i)
		}
	}
	return classes
}

// DecodeFCP decodes File Control Parameters (FCP) template
func DecodeFCP(data []byte) string {
	if len(data) == 0 {
		return "Empty"
	}

	// FCP template tag is 0x62
	idx := 0
	if data[0] == 0x62 {
		_, lenBytes := parseLength(data, 1)
		if lenBytes > 0 {
			idx = 1 + lenBytes
		} else {
			idx = 2
		}
	}

	var results []string
	for idx < len(data)-1 {
		tag := data[idx]
		length, lenBytes := parseLength(data, idx+1)
		if lenBytes == 0 || idx+1+lenBytes+length > len(data) {
			break
		}
		val := data[idx+1+lenBytes : idx+1+lenBytes+length]

		switch tag {
		case 0x82: // File Descriptor
			if len(val) >= 2 {
				ftype := ""
				switch val[0] & 0x07 {
				case 0x01:
					ftype = "Transparent"
				case 0x02:
					ftype = "Linear Fixed"
				case 0x04:
					ftype = "Cyclic"
				case 0x07:
					ftype = "DF/ADF"
				default:
					ftype = fmt.Sprintf("Unknown(0x%02X)", val[0])
				}
				results = append(results, ftype)
				if len(val) >= 5 && (val[0]&0x02 != 0 || val[0]&0x04 != 0) {
					recLen := int(val[2])<<8 | int(val[3])
					numRec := int(val[4])
					results = append(results, fmt.Sprintf("RecLen: %d, NumRec: %d", recLen, numRec))
				} else if len(val) >= 4 && (val[0]&0x02 != 0 || val[0]&0x04 != 0) {
					recLen := int(val[2])<<8 | int(val[3])
					results = append(results, fmt.Sprintf("RecLen: %d", recLen))
				}
			}
		case 0x80, 0x81: // File size
			size := 0
			for _, b := range val {
				size = (size << 8) | int(b)
			}
			results = append(results, fmt.Sprintf("Size: %d", size))
		case 0x83: // File ID
			results = append(results, fmt.Sprintf("ID: %04X", val))
		case 0x88: // SFI
			if len(val) > 0 {
				results = append(results, fmt.Sprintf("SFI: %02X", val[0]))
			}
		case 0x8A: // LCSI
			if len(val) > 0 {
				lcsi := ""
				switch val[0] {
				case 0x01:
					lcsi = "Creation"
				case 0x03:
					lcsi = "Initialization"
				case 0x05:
					lcsi = "Operational (Activated)"
				case 0x04, 0x06:
					lcsi = "Operational (Deactivated)"
				case 0x0C, 0x0D, 0x0E, 0x0F:
					lcsi = "Termination"
				default:
					lcsi = fmt.Sprintf("0x%02X", val[0])
				}
				results = append(results, "Status: "+lcsi)
			}
		}
		idx += 1 + lenBytes + length
	}

	if len(results) == 0 {
		return hex.EncodeToString(data)
	}
	return strings.Join(results, ", ")
}

// DecodeDIR decodes EF_DIR record (Application Directory)
func DecodeDIR(data []byte) string {
	// data is one record of EF_DIR
	// Format: 61 [Len] [4F [Len] AID] [50 [Len] Label] ...
	if len(data) == 0 || data[0] == 0xFF {
		return ""
	}

	idx := 0
	if data[idx] == 0x61 {
		_, lenBytes := parseLength(data, idx+1)
		idx += 1 + lenBytes
	}

	var aid, label string
	for idx < len(data)-1 {
		tag := data[idx]
		length, lenBytes := parseLength(data, idx+1)
		if lenBytes == 0 || idx+1+lenBytes+length > len(data) {
			break
		}
		val := data[idx+1+lenBytes : idx+1+lenBytes+length]

		switch tag {
		case 0x4F: // AID
			aid = strings.ToUpper(hex.EncodeToString(val))
			// Try to identify application
			if strings.HasPrefix(aid, "A0000000871002") {
				aid += " (USIM)"
			} else if strings.HasPrefix(aid, "A0000000871004") {
				aid += " (ISIM)"
			} else if strings.HasPrefix(aid, "A0000003431002") {
				aid += " (CSIM)"
			}
		case 0x50: // Application Label
			label = string(val)
		}
		idx += 1 + lenBytes + length
	}

	if aid == "" {
		return ""
	}
	if label != "" {
		return fmt.Sprintf("AID: %s, Label: %s", aid, label)
	}
	return "AID: " + aid
}

// DecodeServiceTableNames returns names of enabled services from UST/IST
func DecodeServiceTableNames(data []byte, isISIM bool) []string {
	enabled := DecodeUST(data)
	var result []string
	
	serviceMap := USTServices
	if isISIM {
		serviceMap = ISTServices
	}

	// Sort keys for deterministic output
	var keys []int
	for k := range enabled {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	for _, k := range keys {
		if name, ok := serviceMap[k]; ok {
			result = append(result, fmt.Sprintf("#%d: %s", k, name))
		} else {
			result = append(result, fmt.Sprintf("#%d: Unknown", k))
		}
	}
	return result
}

// parseLength decodes ASN.1/TLV length
func parseLength(data []byte, offset int) (int, int) {
	if offset >= len(data) {
		return 0, 0
	}
	b := data[offset]
	if b < 0x80 {
		return int(b), 1
	}
	lenBytes := int(b & 0x7F)
	if lenBytes == 0 || offset+1+lenBytes > len(data) {
		return 0, 0
	}
	res := 0
	for i := 0; i < lenBytes; i++ {
		res = (res << 8) | int(data[offset+1+i])
	}
	return res, 1 + lenBytes
}

// Helper functions

func decodeBCDSwapped(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		low := b & 0x0F
		high := (b >> 4) & 0x0F
		if low <= 9 {
			result.WriteByte('0' + low)
		} else if low == 0x0F {
			// Padding
		} else {
			result.WriteByte('A' + low - 10)
		}
		if high <= 9 {
			result.WriteByte('0' + high)
		} else if high == 0x0F {
			// Padding
		} else {
			result.WriteByte('A' + high - 10)
		}
	}
	return result.String()
}

func decodeTLVString(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Simple TLV: Tag (1 byte) + Length (1 byte) + Value
	// Tag 0x80 is commonly used for strings
	idx := 0
	for idx < len(data) {
		if data[idx] == 0xFF {
			break
		}
		tag := data[idx]
		if idx+1 >= len(data) {
			break
		}
		length := int(data[idx+1])
		if idx+2+length > len(data) {
			break
		}
		value := data[idx+2 : idx+2+length]

		if tag == 0x80 {
			// String value
			return strings.TrimRight(string(value), "\x00\xFF")
		}
		idx += 2 + length
	}

	// If no TLV found, try direct decode
	result := strings.TrimRight(string(data), "\x00\xFF")
	// Filter non-printable
	var clean strings.Builder
	for _, r := range result {
		if r >= 32 && r < 127 {
			clean.WriteRune(r)
		}
	}
	return clean.String()
}

// GetMCCCountry returns country name for MCC
// Uses embedded MCC/MNC dictionary for comprehensive coverage
func GetMCCCountry(mcc string) string {
	return dictionaries.GetCountry(mcc)
}

// GetOperatorName returns operator name for MCC-MNC
// Uses embedded MCC/MNC dictionary for comprehensive coverage
func GetOperatorName(mcc, mnc string) string {
	return dictionaries.GetOperatorName(mcc, mnc)
}

// DecodeLanguages decodes EF_LI (Language Indication)
// Each language is 2 bytes ISO 639-1 code
func DecodeLanguages(data []byte) []string {
	var langs []string
	for i := 0; i+1 < len(data); i += 2 {
		if data[i] == 0xFF && data[i+1] == 0xFF {
			break
		}
		lang := string(data[i : i+2])
		if lang[0] >= 'a' && lang[0] <= 'z' {
			langs = append(langs, lang)
		}
	}
	return langs
}

// DecodeHPLMNPeriod decodes EF_HPPLMN (Higher Priority PLMN search period)
// Returns period in minutes (value * 6 minutes, 0 = disabled)
func DecodeHPLMNPeriod(data []byte) int {
	if len(data) < 1 || data[0] == 0xFF {
		return 0
	}
	return int(data[0]) * 6 // Period in minutes
}

// DecodeLOCI decodes EF_LOCI (Location Information)
// 3GPP TS 31.102: TMSI(4) + LAI(5) + TMSI time(1) + Status(1) = 11 bytes
func DecodeLOCI(data []byte) *LocationInfo {
	if len(data) < 11 {
		return nil
	}
	// Check if empty (all FF)
	allFF := true
	for _, b := range data[:11] {
		if b != 0xFF {
			allFF = false
			break
		}
	}
	if allFF {
		return nil
	}

	info := &LocationInfo{
		TMSI:     fmt.Sprintf("%08X", data[0:4]),
		LAI:      fmt.Sprintf("%X", data[4:9]),
		TMSITime: int(data[9]),
	}

	// Decode LAI: MCC(3 digits) + MNC(2-3 digits) + LAC(2 bytes)
	mcc, mnc := DecodePLMN(data[4:7])
	lac := uint16(data[7])<<8 | uint16(data[8])
	info.LAI = fmt.Sprintf("%s-%s LAC:%04X", mcc, mnc, lac)

	// Location update status
	switch data[10] & 0x07 {
	case 0:
		info.Status = "Updated"
	case 1:
		info.Status = "Not updated"
	case 2:
		info.Status = "PLMN not allowed"
	case 3:
		info.Status = "Location Area not allowed"
	default:
		info.Status = fmt.Sprintf("Unknown (0x%02X)", data[10])
	}
	return info
}

// DecodePSLOCI decodes EF_PSLOCI (PS Location Information)
// 3GPP TS 31.102: P-TMSI(4) + P-TMSI-sig(3) + RAI(6) + Status(1) = 14 bytes
func DecodePSLOCI(data []byte) *PSLocationInfo {
	if len(data) < 14 {
		return nil
	}
	// Check if empty
	allFF := true
	for _, b := range data[:14] {
		if b != 0xFF {
			allFF = false
			break
		}
	}
	if allFF {
		return nil
	}

	info := &PSLocationInfo{
		PTMSI:    fmt.Sprintf("%08X", data[0:4]),
		PTMSISig: fmt.Sprintf("%06X", data[4:7]),
	}

	// Decode RAI: MCC + MNC + LAC + RAC
	mcc, mnc := DecodePLMN(data[7:10])
	lac := uint16(data[10])<<8 | uint16(data[11])
	rac := data[12]
	info.RAI = fmt.Sprintf("%s-%s LAC:%04X RAC:%02X", mcc, mnc, lac, rac)

	switch data[13] & 0x07 {
	case 0:
		info.Status = "Updated"
	case 1:
		info.Status = "Not updated"
	case 2:
		info.Status = "PLMN not allowed"
	case 3:
		info.Status = "Routing Area not allowed"
	default:
		info.Status = fmt.Sprintf("Unknown (0x%02X)", data[13])
	}
	return info
}

// DecodeEPSLOCI decodes EF_EPSLOCI (EPS Location Information)
// 3GPP TS 31.102: GUTI(12) + TAI(5) + Status(1) = 18 bytes
func DecodeEPSLOCI(data []byte) *EPSLocationInfo {
	if len(data) < 18 {
		return nil
	}
	// Check if empty
	allFF := true
	for _, b := range data[:18] {
		if b != 0xFF {
			allFF = false
			break
		}
	}
	if allFF {
		return nil
	}

	info := &EPSLocationInfo{
		GUTI: fmt.Sprintf("%X", data[0:12]),
	}

	// Decode TAI: MCC + MNC + TAC
	mcc, mnc := DecodePLMN(data[12:15])
	tac := uint16(data[15])<<8 | uint16(data[16])
	info.TAI = fmt.Sprintf("%s-%s TAC:%04X", mcc, mnc, tac)

	switch data[17] & 0x07 {
	case 0:
		info.Status = "Updated"
	case 1:
		info.Status = "Not updated"
	case 2:
		info.Status = "PLMN not allowed"
	case 3:
		info.Status = "Tracking Area not allowed"
	default:
		info.Status = fmt.Sprintf("Unknown (0x%02X)", data[17])
	}
	return info
}
