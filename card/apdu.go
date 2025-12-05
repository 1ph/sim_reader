package card

import (
	"fmt"
)

// APDU response status words
const (
	SW_OK                       = 0x9000 // Success
	SW_FILE_NOT_FOUND           = 0x6A82 // File not found
	SW_RECORD_NOT_FOUND         = 0x6A83 // Record not found
	SW_WRONG_LENGTH             = 0x6700 // Wrong length
	SW_SECURITY_NOT_SATISFIED   = 0x6982 // Security status not satisfied
	SW_AUTH_FAILED              = 0x6983 // Authentication method blocked
	SW_REF_DATA_NOT_FOUND       = 0x6984 // Reference data not found
	SW_CONDITIONS_NOT_SATISFIED = 0x6985 // Conditions of use not satisfied
	SW_WRONG_P1P2               = 0x6A86 // Incorrect P1 P2
	SW_INS_NOT_SUPPORTED        = 0x6D00 // Instruction not supported
	SW_CLA_NOT_SUPPORTED        = 0x6E00 // Class not supported
)

// APDU instruction bytes
const (
	INS_SELECT        = 0xA4
	INS_READ_BINARY   = 0xB0
	INS_READ_RECORD   = 0xB2
	INS_UPDATE_BINARY = 0xD6
	INS_UPDATE_RECORD = 0xDC
	INS_GET_RESPONSE  = 0xC0
	INS_VERIFY        = 0x20
	INS_STATUS        = 0xF2
	INS_AUTHENTICATE  = 0x88
)

// Authentication context types (P2 for AUTHENTICATE command)
const (
	AUTH_CONTEXT_GSM      = 0x80 // GSM context (2G)
	AUTH_CONTEXT_3G       = 0x81 // 3G/UMTS context (USIM)
	AUTH_CONTEXT_VGCS_VBS = 0x82 // VGCS/VBS context
	AUTH_CONTEXT_GBA      = 0x84 // GBA context (bootstrapping)
	AUTH_CONTEXT_MBMS     = 0x85 // MBMS context
	AUTH_CONTEXT_IMS      = 0x81 // IMS context (same as 3G for ISIM)
)

// APDUResponse represents a response from the card
type APDUResponse struct {
	Data []byte
	SW1  byte
	SW2  byte
}

// SW returns the status word as uint16
func (r *APDUResponse) SW() uint16 {
	return uint16(r.SW1)<<8 | uint16(r.SW2)
}

// IsOK returns true if the response indicates success
func (r *APDUResponse) IsOK() bool {
	return r.SW1 == 0x90 && r.SW2 == 0x00
}

// HasMoreData returns true if more data is available (SW1 = 0x61)
func (r *APDUResponse) HasMoreData() bool {
	return r.SW1 == 0x61
}

// NeedsRetry returns true if the command should be retried with correct length (SW1 = 0x6C)
func (r *APDUResponse) NeedsRetry() bool {
	return r.SW1 == 0x6C
}

// Error returns an error if the response is not OK
func (r *APDUResponse) Error() error {
	if r.IsOK() || r.HasMoreData() {
		return nil
	}
	return fmt.Errorf("APDU error: SW=%04X (%s)", r.SW(), SWToString(r.SW()))
}

// SWToString converts status word to human-readable string
func SWToString(sw uint16) string {
	switch sw {
	case SW_OK:
		return "Success"
	case SW_FILE_NOT_FOUND:
		return "File not found"
	case SW_RECORD_NOT_FOUND:
		return "Record not found"
	case SW_WRONG_LENGTH:
		return "Wrong length"
	case SW_SECURITY_NOT_SATISFIED:
		return "Security status not satisfied"
	case SW_AUTH_FAILED:
		return "Authentication method blocked"
	case SW_REF_DATA_NOT_FOUND:
		return "Reference data not found"
	case SW_CONDITIONS_NOT_SATISFIED:
		return "Conditions of use not satisfied"
	case SW_WRONG_P1P2:
		return "Incorrect P1 P2"
	case SW_INS_NOT_SUPPORTED:
		return "Instruction not supported"
	case SW_CLA_NOT_SUPPORTED:
		return "Class not supported"
	default:
		sw1 := byte(sw >> 8)
		sw2 := byte(sw)
		if sw1 == 0x61 {
			return fmt.Sprintf("%d bytes available", sw2)
		}
		if sw1 == 0x6C {
			return fmt.Sprintf("Retry with Le=%d", sw2)
		}
		if sw1 == 0x63 && (sw2&0xF0) == 0xC0 {
			return fmt.Sprintf("PIN verification failed, %d attempts remaining", sw2&0x0F)
		}
		return "Unknown error"
	}
}

// SendAPDU sends an APDU command and parses the response
func (r *Reader) SendAPDU(apdu []byte) (*APDUResponse, error) {
	raw, err := r.Transmit(apdu)
	if err != nil {
		return nil, err
	}

	if len(raw) < 2 {
		return nil, fmt.Errorf("response too short: %d bytes", len(raw))
	}

	resp := &APDUResponse{
		Data: raw[:len(raw)-2],
		SW1:  raw[len(raw)-2],
		SW2:  raw[len(raw)-1],
	}

	return resp, nil
}

// Select selects a file or application by ID
func (r *Reader) Select(fileID []byte) (*APDUResponse, error) {
	// SELECT command: CLA=00, INS=A4, P1=00, P2=04 for AID, P2=00 for file
	p1 := byte(0x00)
	p2 := byte(0x04) // Return FCP template

	if len(fileID) == 2 {
		// File ID selection
		p1 = 0x00
		p2 = 0x04
	} else if len(fileID) > 2 {
		// AID selection
		p1 = 0x04
		p2 = 0x04
	}

	apdu := make([]byte, 5+len(fileID))
	apdu[0] = 0x00 // CLA
	apdu[1] = INS_SELECT
	apdu[2] = p1
	apdu[3] = p2
	apdu[4] = byte(len(fileID))
	copy(apdu[5:], fileID)

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}

	// Handle GET RESPONSE if needed
	if resp.HasMoreData() {
		return r.GetResponse(resp.SW2)
	}

	return resp, nil
}

// SelectByPath selects a file by path from MF
func (r *Reader) SelectByPath(path []byte) (*APDUResponse, error) {
	apdu := make([]byte, 5+len(path))
	apdu[0] = 0x00
	apdu[1] = INS_SELECT
	apdu[2] = 0x08 // Select by path from MF
	apdu[3] = 0x04 // Return FCP
	apdu[4] = byte(len(path))
	copy(apdu[5:], path)

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}

	if resp.HasMoreData() {
		return r.GetResponse(resp.SW2)
	}

	return resp, nil
}

// SelectDF selects a DF by File ID (for cards that don't support AID selection)
// This uses P1=00, P2=04 which selects DF by file identifier
func (r *Reader) SelectDF(fileID []byte) (*APDUResponse, error) {
	if len(fileID) != 2 {
		return nil, fmt.Errorf("DF file ID must be 2 bytes, got %d", len(fileID))
	}

	apdu := []byte{
		0x00,       // CLA
		INS_SELECT, // INS
		0x00,       // P1: Select DF, EF or MF by file id
		0x04,       // P2: Return FCP template
		0x02,       // Lc
		fileID[0],  // File ID high byte
		fileID[1],  // File ID low byte
	}

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}

	if resp.HasMoreData() {
		return r.GetResponse(resp.SW2)
	}

	return resp, nil
}

// GSM class commands (CLA=A0) for cards that use File ID selection

// SelectGSM selects a file using GSM class command (CLA=A0)
// Returns response with file info (SW=9FXX means XX bytes available via GET RESPONSE)
func (r *Reader) SelectGSM(fileID []byte) (*APDUResponse, error) {
	apdu := make([]byte, 5+len(fileID))
	apdu[0] = 0xA0 // CLA - GSM
	apdu[1] = INS_SELECT
	apdu[2] = 0x00 // P1
	apdu[3] = 0x00 // P2
	apdu[4] = byte(len(fileID))
	copy(apdu[5:], fileID)

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}

	// GSM cards return 9F XX where XX is number of bytes available
	if resp.SW1 == 0x9F {
		return r.GetResponseGSM(resp.SW2)
	}

	// Also handle 61 XX (standard "more data" response)
	if resp.HasMoreData() {
		return r.GetResponseGSM(resp.SW2)
	}

	return resp, nil
}

// GetResponseGSM retrieves response data using GSM class (CLA=A0)
func (r *Reader) GetResponseGSM(length byte) (*APDUResponse, error) {
	apdu := []byte{0xA0, INS_GET_RESPONSE, 0x00, 0x00, length}
	return r.SendAPDU(apdu)
}

// ReadRecordGSM reads a record using GSM class command (CLA=A0)
func (r *Reader) ReadRecordGSM(recordNum, length byte) (*APDUResponse, error) {
	apdu := []byte{
		0xA0, // CLA - GSM
		INS_READ_RECORD,
		recordNum,
		0x04, // P2: record number in P1, absolute mode
		length,
	}

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}

	// Handle retry with correct length
	if resp.NeedsRetry() {
		apdu[4] = resp.SW2
		return r.SendAPDU(apdu)
	}

	return resp, nil
}

// ReadBinaryGSM reads binary data using GSM class command (CLA=A0)
func (r *Reader) ReadBinaryGSM(offset uint16, length byte) (*APDUResponse, error) {
	apdu := []byte{
		0xA0, // CLA - GSM
		INS_READ_BINARY,
		byte(offset >> 8),
		byte(offset & 0xFF),
		length,
	}

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}

	// Handle retry with correct length
	if resp.NeedsRetry() {
		apdu[4] = resp.SW2
		return r.SendAPDU(apdu)
	}

	return resp, nil
}

// GetResponse retrieves response data from the card
func (r *Reader) GetResponse(length byte) (*APDUResponse, error) {
	apdu := []byte{0x00, INS_GET_RESPONSE, 0x00, 0x00, length}
	return r.SendAPDU(apdu)
}

// ReadBinary reads binary data from the currently selected file
func (r *Reader) ReadBinary(offset uint16, length byte) (*APDUResponse, error) {
	apdu := []byte{
		0x00,
		INS_READ_BINARY,
		byte(offset >> 8),
		byte(offset & 0xFF),
		length,
	}

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}

	// Handle retry with correct length
	if resp.NeedsRetry() {
		apdu[4] = resp.SW2
		return r.SendAPDU(apdu)
	}

	return resp, nil
}

// ReadRecord reads a record from the currently selected file
func (r *Reader) ReadRecord(recordNum, length byte) (*APDUResponse, error) {
	apdu := []byte{
		0x00,
		INS_READ_RECORD,
		recordNum,
		0x04, // P2: record number in P1, absolute mode
		length,
	}

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}

	// Handle retry with correct length
	if resp.NeedsRetry() {
		apdu[4] = resp.SW2
		return r.SendAPDU(apdu)
	}

	return resp, nil
}

// VerifyPIN verifies a PIN or ADM key
func (r *Reader) VerifyPIN(pinType byte, pin []byte) (*APDUResponse, error) {
	// Pad PIN to 8 bytes with 0xFF
	paddedPIN := make([]byte, 8)
	for i := range paddedPIN {
		paddedPIN[i] = 0xFF
	}
	copy(paddedPIN, pin)

	apdu := make([]byte, 13)
	apdu[0] = 0x00
	apdu[1] = INS_VERIFY
	apdu[2] = 0x00
	apdu[3] = pinType
	apdu[4] = 0x08
	copy(apdu[5:], paddedPIN)

	return r.SendAPDU(apdu)
}

// ReadAllBinary reads all binary data from currently selected file
func (r *Reader) ReadAllBinary(fileSize int) ([]byte, error) {
	var data []byte
	offset := uint16(0)

	for int(offset) < fileSize {
		remaining := fileSize - int(offset)
		readLen := byte(0xFF)
		if remaining < 255 {
			readLen = byte(remaining)
		}

		resp, err := r.ReadBinary(offset, readLen)
		if err != nil {
			return data, err
		}

		if !resp.IsOK() && !resp.NeedsRetry() {
			// End of file or error
			break
		}

		data = append(data, resp.Data...)
		offset += uint16(len(resp.Data))

		if len(resp.Data) == 0 {
			break
		}
	}

	return data, nil
}

// UpdateBinary writes binary data to the currently selected file
func (r *Reader) UpdateBinary(offset uint16, data []byte) (*APDUResponse, error) {
	if len(data) > 255 {
		return nil, fmt.Errorf("data too long: %d bytes (max 255)", len(data))
	}

	apdu := make([]byte, 5+len(data))
	apdu[0] = 0x00
	apdu[1] = INS_UPDATE_BINARY
	apdu[2] = byte(offset >> 8)
	apdu[3] = byte(offset & 0xFF)
	apdu[4] = byte(len(data))
	copy(apdu[5:], data)

	return r.SendAPDU(apdu)
}

// UpdateRecord writes a record to the currently selected file
func (r *Reader) UpdateRecord(recordNum byte, data []byte) (*APDUResponse, error) {
	if len(data) > 255 {
		return nil, fmt.Errorf("data too long: %d bytes (max 255)", len(data))
	}

	apdu := make([]byte, 5+len(data))
	apdu[0] = 0x00
	apdu[1] = INS_UPDATE_RECORD
	apdu[2] = recordNum
	apdu[3] = 0x04 // P2: record number in P1, absolute mode
	apdu[4] = byte(len(data))
	copy(apdu[5:], data)

	return r.SendAPDU(apdu)
}

// WriteAllBinary writes all data to currently selected file (handles chunking)
func (r *Reader) WriteAllBinary(data []byte) error {
	offset := uint16(0)
	chunkSize := 255

	for int(offset) < len(data) {
		remaining := len(data) - int(offset)
		writeLen := chunkSize
		if remaining < chunkSize {
			writeLen = remaining
		}

		chunk := data[offset : int(offset)+writeLen]
		resp, err := r.UpdateBinary(offset, chunk)
		if err != nil {
			return fmt.Errorf("update binary at offset %d failed: %w", offset, err)
		}

		if !resp.IsOK() {
			return fmt.Errorf("update binary at offset %d failed: %s", offset, SWToString(resp.SW()))
		}

		offset += uint16(writeLen)
	}

	return nil
}

// AuthenticateResult contains the result of AUTHENTICATE command
type AuthenticateResult struct {
	Success bool   // Authentication succeeded
	RES     []byte // Response (SRES for 2G, RES for 3G/4G)
	CK      []byte // Cipher Key (3G/4G only)
	IK      []byte // Integrity Key (3G/4G only)
	Kc      []byte // Cipher Key (2G only)
	AUTS    []byte // Resynchronization token (if sync failure)
	SW      uint16 // Status word
}

// Authenticate sends AUTHENTICATE command to USIM/ISIM
// rand: 16 bytes random challenge
// autn: 16 bytes authentication token (for 3G/4G context)
// context: authentication context (AUTH_CONTEXT_3G, AUTH_CONTEXT_GSM, etc.)
// Returns RES, CK, IK for success, or AUTS for sync failure
func (r *Reader) Authenticate(rand, autn []byte, context byte) (*AuthenticateResult, error) {
	result := &AuthenticateResult{}

	// Build authentication data
	// For 3G context: length || RAND || length || AUTN
	var authData []byte
	if context == AUTH_CONTEXT_GSM {
		// GSM context: just RAND (16 bytes)
		if len(rand) != 16 {
			return nil, fmt.Errorf("RAND must be 16 bytes for GSM context")
		}
		authData = rand
	} else {
		// 3G/4G context: TLV format
		// Format: length(RAND) || RAND || length(AUTN) || AUTN
		if len(rand) != 16 {
			return nil, fmt.Errorf("RAND must be 16 bytes")
		}
		if len(autn) != 16 {
			return nil, fmt.Errorf("AUTN must be 16 bytes")
		}
		authData = make([]byte, 0, 34)
		authData = append(authData, byte(len(rand)))
		authData = append(authData, rand...)
		authData = append(authData, byte(len(autn)))
		authData = append(authData, autn...)
	}

	// Build APDU: CLA INS P1 P2 Lc Data Le
	apdu := make([]byte, 5+len(authData)+1)
	apdu[0] = 0x00              // CLA
	apdu[1] = INS_AUTHENTICATE  // INS
	apdu[2] = 0x00              // P1
	apdu[3] = context           // P2: authentication context
	apdu[4] = byte(len(authData))
	copy(apdu[5:], authData)
	apdu[5+len(authData)] = 0x00 // Le: expect response

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return nil, fmt.Errorf("AUTHENTICATE command failed: %w", err)
	}

	result.SW = resp.SW()

	// Handle response
	if resp.HasMoreData() {
		// Get the actual response data
		getResp, err := r.GetResponse(resp.SW2)
		if err != nil {
			return nil, fmt.Errorf("GET RESPONSE failed: %w", err)
		}
		resp = getResp
		result.SW = resp.SW()
	}

	// Parse response based on status word
	switch {
	case resp.IsOK():
		// Success - parse response data
		result.Success = true
		if err := parseAuthResponse(resp.Data, context, result); err != nil {
			return result, fmt.Errorf("failed to parse auth response: %w", err)
		}

	case resp.SW1 == 0x9F:
		// More data available (some cards)
		getResp, err := r.GetResponse(resp.SW2)
		if err != nil {
			return nil, fmt.Errorf("GET RESPONSE failed: %w", err)
		}
		result.Success = true
		result.SW = getResp.SW()
		if err := parseAuthResponse(getResp.Data, context, result); err != nil {
			return result, fmt.Errorf("failed to parse auth response: %w", err)
		}

	case result.SW == 0x6985:
		// Conditions not satisfied (may need to select USIM ADF first)
		return result, fmt.Errorf("authentication failed: conditions not satisfied (SW=6985)")

	case result.SW == 0x6982:
		// Security status not satisfied
		return result, fmt.Errorf("authentication failed: security status not satisfied (SW=6982)")

	case resp.SW1 == 0x98 && resp.SW2 == 0x62:
		// Authentication error, MAC failure
		return result, fmt.Errorf("authentication failed: MAC failure (SW=9862)")

	case resp.SW1 == 0x98 && resp.SW2 == 0x64:
		// Authentication error, sync failure - response contains AUTS
		result.Success = false
		// AUTS is in the response data (if any) or need GET RESPONSE
		if len(resp.Data) > 0 {
			result.AUTS = parseAUTS(resp.Data)
		}
		return result, nil

	case result.SW == 0x6A88:
		// Reference data not found
		return result, fmt.Errorf("authentication failed: reference data not found (SW=6A88)")

	default:
		return result, fmt.Errorf("authentication failed: %s (SW=%04X)", SWToString(result.SW), result.SW)
	}

	return result, nil
}

// parseAuthResponse parses the authentication response data
func parseAuthResponse(data []byte, context byte, result *AuthenticateResult) error {
	if len(data) == 0 {
		return fmt.Errorf("empty response data")
	}

	if context == AUTH_CONTEXT_GSM {
		// GSM response: SRES (4 bytes) || Kc (8 bytes)
		if len(data) < 12 {
			return fmt.Errorf("GSM response too short: %d bytes", len(data))
		}
		result.RES = data[:4]   // SRES
		result.Kc = data[4:12]  // Kc
		return nil
	}

	// 3G/4G response format: DB || length(RES) || RES || length(CK) || CK || length(IK) || IK
	// or: DC || AUTS (sync failure)
	// or simplified: tag || data

	idx := 0
	tag := data[idx]
	idx++

	switch tag {
	case 0xDB:
		// Successful authentication
		// Format: DB || RES_len || RES || CK_len || CK || IK_len || IK
		if idx >= len(data) {
			return fmt.Errorf("response too short after tag DB")
		}

		// RES
		resLen := int(data[idx])
		idx++
		if idx+resLen > len(data) {
			return fmt.Errorf("RES length overflow")
		}
		result.RES = make([]byte, resLen)
		copy(result.RES, data[idx:idx+resLen])
		idx += resLen

		// CK
		if idx >= len(data) {
			return fmt.Errorf("missing CK length")
		}
		ckLen := int(data[idx])
		idx++
		if idx+ckLen > len(data) {
			return fmt.Errorf("CK length overflow")
		}
		result.CK = make([]byte, ckLen)
		copy(result.CK, data[idx:idx+ckLen])
		idx += ckLen

		// IK
		if idx >= len(data) {
			return fmt.Errorf("missing IK length")
		}
		ikLen := int(data[idx])
		idx++
		if idx+ikLen > len(data) {
			return fmt.Errorf("IK length overflow")
		}
		result.IK = make([]byte, ikLen)
		copy(result.IK, data[idx:idx+ikLen])

	case 0xDC:
		// Synchronization failure - AUTS follows
		result.Success = false
		if idx >= len(data) {
			return fmt.Errorf("missing AUTS length")
		}
		autsLen := int(data[idx])
		idx++
		if idx+autsLen > len(data) {
			return fmt.Errorf("AUTS length overflow")
		}
		result.AUTS = make([]byte, autsLen)
		copy(result.AUTS, data[idx:idx+autsLen])

	default:
		// Some cards may use simplified format without tags
		// Try to parse as: RES_len || RES || CK_len || CK || IK_len || IK
		idx = 0
		resLen := int(data[idx])
		idx++

		if resLen > 0 && idx+resLen <= len(data) {
			result.RES = make([]byte, resLen)
			copy(result.RES, data[idx:idx+resLen])
			idx += resLen

			if idx < len(data) {
				ckLen := int(data[idx])
				idx++
				if idx+ckLen <= len(data) {
					result.CK = make([]byte, ckLen)
					copy(result.CK, data[idx:idx+ckLen])
					idx += ckLen

					if idx < len(data) {
						ikLen := int(data[idx])
						idx++
						if idx+ikLen <= len(data) {
							result.IK = make([]byte, ikLen)
							copy(result.IK, data[idx:idx+ikLen])
						}
					}
				}
			}
		}
	}

	return nil
}

// parseAUTS extracts AUTS from response data
func parseAUTS(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	// Check for DC tag
	if data[0] == 0xDC && len(data) > 2 {
		autsLen := int(data[1])
		if len(data) >= 2+autsLen {
			return data[2 : 2+autsLen]
		}
	}

	// Check for raw AUTS (14 bytes for standard AUTS)
	if len(data) >= 14 {
		return data[:14]
	}

	return data
}
