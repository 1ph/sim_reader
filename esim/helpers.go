package esim

import (
	"sim_reader/esim/asn1"
)

// getTagNumber extracts tag number from ASN1 structure
func getTagNumber(a *asn1.ASN1) int {
	if a.Tag&0x1F == 0x1F {
		return a.FullTag
	}
	return int(a.Tag & 0x1F)
}

// getContextTag returns context-specific tag number
func getContextTag(a *asn1.ASN1) int {
	return getTagNumber(a)
}

// isConstructed checks if tag is constructed
func isConstructed(a *asn1.ASN1) bool {
	return a.Form == asn1.FormConstructed
}

// isContextSpecific checks if tag is context-specific
func isContextSpecific(a *asn1.ASN1) bool {
	return a.Class == asn1.ClassContextSpecific
}

// decodeInteger decodes ASN.1 INTEGER from bytes
func decodeInteger(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	result := 0
	for _, b := range data {
		result = (result << 8) | int(b)
	}
	return result
}

// encodeInteger encodes integer to minimal byte representation
func encodeInteger(val int) []byte {
	if val == 0 {
		return []byte{0}
	}
	var result []byte
	for val > 0 {
		result = append([]byte{byte(val & 0xFF)}, result...)
		val >>= 8
	}
	// Add 0x00 prefix if high bit is set (for unsigned)
	if len(result) > 0 && result[0]&0x80 != 0 {
		result = append([]byte{0}, result...)
	}
	return result
}

// decodeSwappedBCD decodes BCD with swapped nibbles (ICCID, IMSI format)
func decodeSwappedBCD(data []byte) string {
	result := ""
	for _, b := range data {
		lo := b & 0x0F
		hi := (b >> 4) & 0x0F
		if lo != 0x0F {
			result += string('0' + lo)
		}
		if hi != 0x0F {
			result += string('0' + hi)
		}
	}
	return result
}

// encodeSwappedBCD encodes string to BCD with swapped nibbles
func encodeSwappedBCD(s string) []byte {
	var result []byte
	for i := 0; i < len(s); i += 2 {
		var lo, hi byte
		lo = s[i] - '0'
		if i+1 < len(s) {
			hi = s[i+1] - '0'
		} else {
			hi = 0x0F
		}
		result = append(result, (hi<<4)|lo)
	}
	return result
}

// decodeIMSI decodes IMSI from EF_IMSI format
func decodeIMSI(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	length := int(data[0])
	if length > len(data)-1 {
		length = len(data) - 1
	}
	// First byte after length contains type and first digit
	// Skip first nibble (parity/type), rest are digits
	imsi := decodeSwappedBCD(data[1 : 1+length])
	// Remove first digit (parity indicator)
	if len(imsi) > 0 {
		return imsi[1:]
	}
	return imsi
}

// encodeIMSI encodes IMSI to EF_IMSI format
func encodeIMSI(imsi string) []byte {
	// Add parity indicator
	withParity := "9" + imsi // 9 = odd parity, 3GPP TS 31.102
	if len(imsi)%2 == 0 {
		withParity = "1" + imsi // even parity
	}
	encoded := encodeSwappedBCD(withParity)
	length := byte(len(encoded))
	return append([]byte{length}, encoded...)
}

// decodeOID decodes ASN.1 Object Identifier
func decodeOID(data []byte) OID {
	if len(data) == 0 {
		return nil
	}

	// First byte encodes first two components: value = 40*first + second
	oid := OID{int(data[0]) / 40, int(data[0]) % 40}

	// Remaining components in base-128
	val := 0
	for i := 1; i < len(data); i++ {
		val = (val << 7) | int(data[i]&0x7F)
		if data[i]&0x80 == 0 {
			oid = append(oid, val)
			val = 0
		}
	}

	return oid
}

// encodeOID encodes OID to DER format
func encodeOID(oid OID) []byte {
	if len(oid) < 2 {
		return nil
	}

	// First two components are encoded together
	result := []byte{byte(oid[0]*40 + oid[1])}

	// Remaining components in base-128
	for i := 2; i < len(oid); i++ {
		result = append(result, encodeBase128(oid[i])...)
	}

	return result
}

// encodeBase128 encodes number in base-128 format
func encodeBase128(val int) []byte {
	if val == 0 {
		return []byte{0}
	}

	var bytes []byte
	for n := val; n > 0; n >>= 7 {
		bytes = append([]byte{byte(n & 0x7F)}, bytes...)
	}
	// Set continuation bit for all except last
	for i := 0; i < len(bytes)-1; i++ {
		bytes[i] |= 0x80
	}
	return bytes
}

// decodeOIDList decodes OID list from SEQUENCE
func decodeOIDList(a *asn1.ASN1) []OID {
	var oids []OID
	for a.Unmarshal() {
		if a.Tag == 0x06 { // OID tag
			oids = append(oids, decodeOID(a.Data))
		}
	}
	return oids
}

// encodeOIDList encodes OID list to SEQUENCE
func encodeOIDList(oids []OID) []byte {
	var data []byte
	for _, oid := range oids {
		encoded := encodeOID(oid)
		data = append(data, asn1.Marshal(0x06, nil, encoded...)...)
	}
	return data
}

// decodeBoolean decodes ASN.1 BOOLEAN
func decodeBoolean(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return data[0] != 0
}

// encodeBoolean encodes boolean to DER format
func encodeBoolean(val bool) []byte {
	if val {
		return []byte{0xFF}
	}
	return []byte{0x00}
}

// decodeUint16BE decodes 2 bytes as uint16 big-endian
func decodeUint16BE(data []byte) uint16 {
	if len(data) < 2 {
		if len(data) == 1 {
			return uint16(data[0])
		}
		return 0
	}
	return uint16(data[0])<<8 | uint16(data[1])
}

// encodeUint16BE encodes uint16 to 2 bytes big-endian
func encodeUint16BE(val uint16) []byte {
	return []byte{byte(val >> 8), byte(val)}
}

// copyBytes creates a copy of byte slice
func copyBytes(data []byte) []byte {
	if data == nil {
		return nil
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result
}

// assignToProfile assigns decoded element to corresponding Profile field
func assignToProfile(profile *Profile, elem *ProfileElement) {
	switch elem.Tag {
	case TagProfileHeader:
		if h, ok := elem.Value.(*ProfileHeader); ok {
			profile.Header = h
		}
	case TagMF:
		if mf, ok := elem.Value.(*MasterFile); ok {
			profile.MF = mf
		}
	case TagPukCodes:
		if p, ok := elem.Value.(*PUKCodes); ok {
			profile.PukCodes = p
		}
	case TagPinCodes:
		if p, ok := elem.Value.(*PINCodes); ok {
			profile.PinCodes = append(profile.PinCodes, p)
		}
	case TagTelecom:
		if t, ok := elem.Value.(*TelecomDF); ok {
			profile.Telecom = t
		}
	case TagUSIM:
		if u, ok := elem.Value.(*USIMApplication); ok {
			profile.USIM = u
		}
	case TagOptUSIM:
		if u, ok := elem.Value.(*OptionalUSIM); ok {
			profile.OptUSIM = u
		}
	case TagISIM:
		if i, ok := elem.Value.(*ISIMApplication); ok {
			profile.ISIM = i
		}
	case TagOptISIM:
		if i, ok := elem.Value.(*OptionalISIM); ok {
			profile.OptISIM = i
		}
	case TagCSIM:
		if c, ok := elem.Value.(*CSIMApplication); ok {
			profile.CSIM = c
		}
	case TagOptCSIM:
		if c, ok := elem.Value.(*OptionalCSIM); ok {
			profile.OptCSIM = c
		}
	case TagGSMAccess:
		if g, ok := elem.Value.(*GSMAccessDF); ok {
			profile.GSMAccess = g
		}
	case TagAKAParameter:
		if a, ok := elem.Value.(*AKAParameter); ok {
			profile.AKAParams = append(profile.AKAParams, a)
		}
	case TagCDMAParameter:
		if c, ok := elem.Value.(*CDMAParameter); ok {
			profile.CDMAParams = c
		}
	case TagDF5GS:
		if d, ok := elem.Value.(*DF5GS); ok {
			profile.DF5GS = d
		}
	case TagDFSAIP:
		if d, ok := elem.Value.(*DFSAIP); ok {
			profile.DFSAIP = d
		}
	case TagGenericFileManagement:
		if g, ok := elem.Value.(*GenericFileManagement); ok {
			profile.GFM = append(profile.GFM, g)
		}
	case TagSecurityDomain:
		if s, ok := elem.Value.(*SecurityDomain); ok {
			profile.SecurityDomains = append(profile.SecurityDomains, s)
		}
	case TagRFM:
		if r, ok := elem.Value.(*RFMConfig); ok {
			profile.RFM = append(profile.RFM, r)
		}
	case TagEnd:
		if e, ok := elem.Value.(*EndElement); ok {
			profile.End = e
		}
	}
}
