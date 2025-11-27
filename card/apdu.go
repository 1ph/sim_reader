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
