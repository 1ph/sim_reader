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
		return fmt.Errorf("ADM2 verification failed: %s", SWToString(resp.SW()))
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
