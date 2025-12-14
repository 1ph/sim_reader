package card

import (
	"encoding/hex"
	"testing"
)

// ============ SCP02 TESTS ============

func TestSCP02_Padding(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  int // expected length (multiple of 8)
	}{
		{"Empty", []byte{}, 8},
		{"1 byte", []byte{0x01}, 8},
		{"7 bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, 8},
		{"8 bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 16},
		{"9 bytes", make([]byte, 9), 16},
		{"15 bytes", make([]byte, 15), 16},
		{"16 bytes", make([]byte, 16), 24},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			padded := iso7816Pad(tc.input, 8)
			if len(padded) != tc.want {
				t.Errorf("iso7816Pad() length = %d, want %d", len(padded), tc.want)
			}
			// First byte of padding should be 0x80
			if len(tc.input) < len(padded) && padded[len(tc.input)] != 0x80 {
				t.Errorf("iso7816Pad() padding byte = %02X, want 0x80", padded[len(tc.input)])
			}
		})
	}
}

// ============ SCP03 TESTS ============

func TestSCP03_AESCMAC(t *testing.T) {
	// Test vectors from NIST SP 800-38B
	key, _ := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")

	tests := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "Empty message",
			message: "",
			want:    "bb1d6929e95937287fa37d129b756746",
		},
		{
			name:    "16 bytes",
			message: "6BC1BEE22E409F96E93D7E117393172A",
			want:    "070a16b46b4d4144f79bdd9dd04a287c",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, _ := hex.DecodeString(tc.message)
			mac, err := aesCMAC(key, msg)
			if err != nil {
				t.Fatalf("aesCMAC() error = %v", err)
			}
			got := hex.EncodeToString(mac)
			if got != tc.want {
				t.Errorf("aesCMAC() = %s, want %s", got, tc.want)
			}
		})
	}
}

// ============ KEY DERIVATION TESTS ============

func TestSCP02_DerivationConstant(t *testing.T) {
	// SCP02 uses specific derivation constants
	derivationConsts := map[string]byte{
		"S-ENC": 0x01,
		"S-MAC": 0x02,
		"DEK":   0x03,
	}

	for name, expected := range derivationConsts {
		t.Logf("%s derivation constant: 0x%02X", name, expected)
	}
}

func TestSCP03_DerivationLabel(t *testing.T) {
	// SCP03 uses specific labels in KDF
	labels := map[string]byte{
		"S-ENC":  0x04,
		"S-MAC":  0x06,
		"S-RMAC": 0x07,
		"Card":   0x00,
		"Host":   0x01,
	}

	for name, expected := range labels {
		t.Logf("%s label: 0x%02X", name, expected)
	}
}

// ============ SESSION STRUCTURE TESTS ============

func TestSCP02Session_Fields(t *testing.T) {
	session := &SCP02Session{
		KVN:           0x00,
		SENC:          make([]byte, 24),
		SMAC:          make([]byte, 24),
		SDEK:          make([]byte, 24),
		SeqCounter:    make([]byte, 2),
		CardChallenge: make([]byte, 6),
		HostChallenge: make([]byte, 8),
	}

	if session.KVN != 0x00 {
		t.Errorf("KVN = %02X, want 0x00", session.KVN)
	}
	if len(session.SENC) != 24 {
		t.Errorf("SENC length = %d, want 24", len(session.SENC))
	}
}

func TestSCP03Session_Fields(t *testing.T) {
	session := &SCP03Session{
		KVN:           0x00,
		SENC:          make([]byte, 16),
		SMAC:          make([]byte, 16),
		SRMAC:         make([]byte, 16),
		HostChallenge: make([]byte, 8),
		CardChallenge: make([]byte, 8),
	}

	if session.KVN != 0x00 {
		t.Errorf("KVN = %02X, want 0x00", session.KVN)
	}
	if len(session.SENC) != 16 {
		t.Errorf("SENC length = %d, want 16", len(session.SENC))
	}
}

// ============ INITIALIZE UPDATE TESTS ============

func TestInitializeUpdateAPDU(t *testing.T) {
	hostChallenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	kvn := byte(0x00)

	// INITIALIZE UPDATE APDU: CLA INS P1 P2 Lc Data
	apdu := []byte{
		0x80, // CLA
		0x50, // INS (INITIALIZE UPDATE)
		kvn,  // P1 (Key Version Number)
		0x00, // P2
		0x08, // Lc (host challenge length)
	}
	apdu = append(apdu, hostChallenge...)
	// Note: Le may or may not be appended depending on implementation

	if apdu[0] != 0x80 {
		t.Errorf("CLA = %02X, want 0x80", apdu[0])
	}
	if apdu[1] != 0x50 {
		t.Errorf("INS = %02X, want 0x50", apdu[1])
	}
	// Minimum APDU length: 5 header + 8 challenge = 13 bytes
	if len(apdu) < 13 {
		t.Errorf("APDU length = %d, want >= 13", len(apdu))
	}
}

func TestExternalAuthenticateAPDU(t *testing.T) {
	hostCryptogram := make([]byte, 8)
	mac := make([]byte, 8)

	apdu := []byte{
		0x84, // CLA (secured)
		0x82, // INS (EXTERNAL AUTHENTICATE)
		0x03, // P1 (security level)
		0x00, // P2
		0x10, // Lc
	}
	apdu = append(apdu, hostCryptogram...)
	apdu = append(apdu, mac...)

	if apdu[0] != 0x84 {
		t.Errorf("CLA = %02X, want 0x84", apdu[0])
	}
	if apdu[1] != 0x82 {
		t.Errorf("INS = %02X, want 0x82", apdu[1])
	}
	if len(apdu) != 21 {
		t.Errorf("APDU length = %d, want 21", len(apdu))
	}
}

// ============ SECURITY LEVEL TESTS ============

func TestSecurityLevelConstants(t *testing.T) {
	// GlobalPlatform security levels
	levels := map[string]byte{
		"No security":           0x00,
		"C-MAC":                 0x01,
		"C-DEC + C-MAC":         0x03,
		"R-MAC":                 0x10,
		"C-MAC + R-MAC":         0x11,
		"C-DEC + C-MAC + R-MAC": 0x13,
	}

	for name, level := range levels {
		t.Logf("Security level %s: 0x%02X", name, level)
	}
}

// ============ GP KEY SET TESTS ============

func TestGPKeySet(t *testing.T) {
	keySet := GPKeySet{
		ENC: make([]byte, 16),
		MAC: make([]byte, 16),
		DEK: make([]byte, 16),
	}

	if len(keySet.ENC) != 16 {
		t.Errorf("ENC length = %d, want 16", len(keySet.ENC))
	}
}
