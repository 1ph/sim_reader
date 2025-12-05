package card

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// PIN types for VERIFY command
const (
	PIN_CHV1      = 0x01 // PIN1 (CHV1)
	PIN_CHV2      = 0x02 // PIN2 (CHV2)
	PIN_ADM1      = 0x0A // ADM1 (Administrative PIN 1)
	PIN_ADM2      = 0x0B // ADM2 (Administrative PIN 2)
	PIN_ADM3      = 0x0C // ADM3
	PIN_ADM4      = 0x0D // ADM4
	PIN_UNIVERSAL = 0x11 // Universal PIN
)

// ParseADMKey parses an ADM key from string format
// Supports:
// - Hex format (16 chars): "F38A3DECF6C7D239"
// - Decimal format (8 digits): "77111606" -> ASCII bytes "77111606"
func ParseADMKey(keyStr string) ([]byte, error) {
	keyStr = strings.TrimSpace(keyStr)

	// Check if it's a hex string (16 hex characters = 8 bytes)
	if len(keyStr) == 16 && isHexString(keyStr) {
		return hex.DecodeString(keyStr)
	}

	// Check if it's a decimal PIN (8 digits) - convert to ASCII
	if len(keyStr) == 8 && isDecimalString(keyStr) {
		return []byte(keyStr), nil
	}

	// Try to decode as hex anyway for other lengths
	if isHexString(keyStr) && len(keyStr)%2 == 0 {
		return hex.DecodeString(keyStr)
	}

	// Otherwise treat as ASCII
	if len(keyStr) <= 8 {
		return []byte(keyStr), nil
	}

	return nil, fmt.Errorf("invalid ADM key format: '%s' (expected 16 hex chars or 8 digit decimal)", keyStr)
}

// isHexString checks if string contains only hex characters
func isHexString(s string) bool {
	matched, _ := regexp.MatchString("^[0-9A-Fa-f]+$", s)
	return matched
}

// isDecimalString checks if string contains only decimal digits
func isDecimalString(s string) bool {
	matched, _ := regexp.MatchString("^[0-9]+$", s)
	return matched
}

// VerifyADM1 authenticates with ADM1 key
func (r *Reader) VerifyADM1(key []byte) error {
	resp, err := r.VerifyPIN(PIN_ADM1, key)
	if err != nil {
		return fmt.Errorf("ADM1 verification failed: %w", err)
	}

	if !resp.IsOK() {
		sw := resp.SW()
		if resp.SW1 == 0x63 && (resp.SW2&0xF0) == 0xC0 {
			attempts := resp.SW2 & 0x0F
			return fmt.Errorf("ADM1 verification failed: wrong key, %d attempts remaining", attempts)
		}
		return fmt.Errorf("ADM1 verification failed: %s (SW=%04X)", SWToString(sw), sw)
	}

	return nil
}

// VerifyADM2 authenticates with ADM2 key
func (r *Reader) VerifyADM2(key []byte) error {
	resp, err := r.VerifyPIN(PIN_ADM2, key)
	if err != nil {
		return fmt.Errorf("ADM2 verification failed: %w", err)
	}

	if !resp.IsOK() {
		sw := resp.SW()
		if resp.SW1 == 0x63 && (resp.SW2&0xF0) == 0xC0 {
			attempts := resp.SW2 & 0x0F
			return fmt.Errorf("ADM2 verification failed: wrong key, %d attempts remaining", attempts)
		}
		return fmt.Errorf("ADM2 verification failed: %s (SW=%04X)", SWToString(sw), sw)
	}

	return nil
}

// VerifyADM3 authenticates with ADM3 key
func (r *Reader) VerifyADM3(key []byte) error {
	resp, err := r.VerifyPIN(PIN_ADM3, key)
	if err != nil {
		return fmt.Errorf("ADM3 verification failed: %w", err)
	}

	if !resp.IsOK() {
		sw := resp.SW()
		if resp.SW1 == 0x63 && (resp.SW2&0xF0) == 0xC0 {
			attempts := resp.SW2 & 0x0F
			return fmt.Errorf("ADM3 verification failed: wrong key, %d attempts remaining", attempts)
		}
		return fmt.Errorf("ADM3 verification failed: %s (SW=%04X)", SWToString(sw), sw)
	}

	return nil
}

// VerifyADM4 authenticates with ADM4 key
func (r *Reader) VerifyADM4(key []byte) error {
	resp, err := r.VerifyPIN(PIN_ADM4, key)
	if err != nil {
		return fmt.Errorf("ADM4 verification failed: %w", err)
	}

	if !resp.IsOK() {
		sw := resp.SW()
		if resp.SW1 == 0x63 && (resp.SW2&0xF0) == 0xC0 {
			attempts := resp.SW2 & 0x0F
			return fmt.Errorf("ADM4 verification failed: wrong key, %d attempts remaining", attempts)
		}
		return fmt.Errorf("ADM4 verification failed: %s (SW=%04X)", SWToString(sw), sw)
	}

	return nil
}

// VerifyPIN1 verifies PIN1 (CHV1)
func (r *Reader) VerifyPIN1(pin string) error {
	resp, err := r.VerifyPIN(PIN_CHV1, []byte(pin))
	if err != nil {
		return fmt.Errorf("PIN1 verification failed: %w", err)
	}

	if !resp.IsOK() {
		sw := resp.SW()
		if resp.SW1 == 0x63 && (resp.SW2&0xF0) == 0xC0 {
			attempts := resp.SW2 & 0x0F
			return fmt.Errorf("PIN1 verification failed: wrong PIN, %d attempts remaining", attempts)
		}
		return fmt.Errorf("PIN1 verification failed: %s (SW=%04X)", SWToString(sw), sw)
	}

	return nil
}

// KeyToHex converts key bytes to hex string for display
func KeyToHex(key []byte) string {
	return strings.ToUpper(hex.EncodeToString(key))
}

// ADMInfo contains information about an ADM key slot
type ADMInfo struct {
	Exists   bool
	Blocked  bool
	Attempts int // Remaining attempts (-1 if unknown)
}

// CheckADM checks if an ADM key slot exists and its status
// This sends VERIFY with Lc=0 (no data) to query the status.
// Per ISO 7816-4, this should NOT consume retry attempts.
// However, behavior depends on card implementation - most modern cards
// (G+D, Gemalto, Sysmocom, Thales) support this safely.
func (r *Reader) CheckADM(pinType byte) ADMInfo {
	// Send VERIFY with Lc=0 (no data) - query status only, should not decrement counter
	apdu := []byte{0x00, 0x20, 0x00, pinType, 0x00}
	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return ADMInfo{Exists: false, Attempts: -1}
	}

	sw := resp.SW()

	// 63CX - PIN exists, X attempts remaining
	if resp.SW1 == 0x63 && (resp.SW2&0xF0) == 0xC0 {
		return ADMInfo{Exists: true, Blocked: false, Attempts: int(resp.SW2 & 0x0F)}
	}

	// 6983 - Authentication blocked
	if sw == 0x6983 {
		return ADMInfo{Exists: true, Blocked: true, Attempts: 0}
	}

	// 6A88 - Reference data not found (ADM doesn't exist)
	if sw == 0x6A88 {
		return ADMInfo{Exists: false, Attempts: -1}
	}

	// 6984 - Reference data not usable (sometimes means doesn't exist)
	if sw == 0x6984 {
		return ADMInfo{Exists: false, Attempts: -1}
	}

	// 6A86 - Wrong P1P2 (ADM doesn't exist)
	if sw == 0x6A86 {
		return ADMInfo{Exists: false, Attempts: -1}
	}

	// 9000 - Already verified (shouldn't happen with empty data)
	if sw == 0x9000 {
		return ADMInfo{Exists: true, Blocked: false, Attempts: -1}
	}

	// 6982 - Security status not satisfied (ADM exists but needs verification)
	if sw == 0x6982 {
		return ADMInfo{Exists: true, Blocked: false, Attempts: -1}
	}

	// Default: assume exists with unknown status
	return ADMInfo{Exists: true, Attempts: -1}
}

// GetAllADMStatus returns status of all ADM keys (ADM1-ADM4)
func (r *Reader) GetAllADMStatus() map[string]ADMInfo {
	return map[string]ADMInfo{
		"ADM1": r.CheckADM(PIN_ADM1),
		"ADM2": r.CheckADM(PIN_ADM2),
		"ADM3": r.CheckADM(PIN_ADM3),
		"ADM4": r.CheckADM(PIN_ADM4),
	}
}
