package sim

import (
	"testing"
)

// ============ IMSI ENCODER TESTS ============

func TestEncodeIMSI_Valid(t *testing.T) {
	tests := []struct {
		imsi string
	}{
		// 15-digit IMSI - test roundtrip instead of exact bytes
		{"250880000000017"},
		{"250880000000003"},
		{"310410123456789"},
		{"001010000000001"},
	}

	for _, tc := range tests {
		t.Run(tc.imsi, func(t *testing.T) {
			got, err := EncodeIMSI(tc.imsi)
			if err != nil {
				t.Fatalf("EncodeIMSI() error = %v", err)
			}
			// Verify roundtrip
			decoded := DecodeIMSI(got)
			if decoded != tc.imsi {
				t.Errorf("EncodeIMSI(%s) -> DecodeIMSI() = %s, want %s", tc.imsi, decoded, tc.imsi)
			}
		})
	}
}

func TestEncodeIMSI_Invalid(t *testing.T) {
	tests := []struct {
		name string
		imsi string
	}{
		{"Empty", ""},
		{"Too short", "250"},
		{"Too long", "2508800000000170000"},
		{"Non-numeric", "250ABC0000001"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := EncodeIMSI(tc.imsi)
			if err == nil {
				t.Errorf("EncodeIMSI(%q) should return error", tc.imsi)
			}
		})
	}
}

// ============ PLMN ENCODER TESTS ============

func TestEncodePLMN_Valid(t *testing.T) {
	tests := []struct {
		mcc, mnc string
	}{
		// 2-digit MNC - test roundtrip
		{"250", "88"},
		{"250", "02"},
		{"001", "01"},
		{"999", "99"},

		// 3-digit MNC
		{"310", "410"},
		{"310", "260"},
		{"311", "480"},
	}

	for _, tc := range tests {
		t.Run(tc.mcc+"/"+tc.mnc, func(t *testing.T) {
			got, err := EncodePLMN(tc.mcc, tc.mnc)
			if err != nil {
				t.Fatalf("EncodePLMN() error = %v", err)
			}
			// Verify roundtrip
			gotMCC, gotMNC := DecodePLMN(got)
			if gotMCC != tc.mcc || gotMNC != tc.mnc {
				t.Errorf("EncodePLMN(%s, %s) -> DecodePLMN() = %s/%s", tc.mcc, tc.mnc, gotMCC, gotMNC)
			}
		})
	}
}

func TestEncodePLMN_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		mcc, mnc string
	}{
		{"Empty MCC", "", "88"},
		{"Empty MNC", "250", ""},
		{"Short MCC", "25", "88"},
		{"Long MCC", "2500", "88"},
		{"Short MNC", "250", "8"},
		{"Long MNC", "250", "8888"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := EncodePLMN(tc.mcc, tc.mnc)
			if err == nil {
				t.Errorf("EncodePLMN(%q, %q) should return error", tc.mcc, tc.mnc)
			}
		})
	}
}

// ============ TLV STRING ENCODER TESTS ============

func TestEncodeTLVString(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		check func([]byte) bool
	}{
		{
			name: "Simple string",
			s:    "test",
			check: func(data []byte) bool {
				return len(data) >= 2 && data[0] == 0x80 && data[1] == 4
			},
		},
		{
			name: "Empty string",
			s:    "",
			check: func(data []byte) bool {
				return len(data) == 2 && data[0] == 0x80 && data[1] == 0
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EncodeTLVString(tc.s)
			if !tc.check(got) {
				t.Errorf("EncodeTLVString(%q) = %X", tc.s, got)
			}
		})
	}
}

// ============ UST ENCODER TESTS ============

func TestEncodeUST(t *testing.T) {
	// Test enabling a service
	current := []byte{0x00, 0x00, 0x00, 0x00}
	changes := map[int]bool{1: true}
	got := EncodeUST(current, changes)

	// Service 1 is bit 0 of byte 0
	if got[0]&0x01 == 0 {
		t.Error("Service 1 should be enabled")
	}

	// Test enabling multiple services
	current = []byte{0x00, 0x00, 0x00, 0x00}
	changes = map[int]bool{1: true, 2: true, 3: true}
	got = EncodeUST(current, changes)

	if got[0]&0x07 != 0x07 {
		t.Errorf("Services 1,2,3 should be enabled, got %02X", got[0])
	}
}

// ============ AD ENCODER TESTS ============

func TestEncodeAD(t *testing.T) {
	tests := []struct {
		name    string
		current []byte
		mncLen  int
		wantLen int
	}{
		{
			name:    "Set MNC length 2",
			current: []byte{0x00, 0x00, 0x01, 0x00},
			mncLen:  2,
			wantLen: 2,
		},
		{
			name:    "Set MNC length 3",
			current: []byte{0x00, 0x00, 0x01, 0x02},
			mncLen:  3,
			wantLen: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EncodeAD(tc.current, tc.mncLen)
			if len(got) >= 4 && int(got[3]) != tc.wantLen {
				t.Errorf("EncodeAD() MNC length = %d, want %d", got[3], tc.wantLen)
			}
		})
	}
}

// ============ FPLMN CLEAR TESTS ============

func TestClearFPLMN(t *testing.T) {
	sizes := []int{12, 24, 36, 60}

	for _, size := range sizes {
		t.Run("", func(t *testing.T) {
			got := ClearFPLMN(size)
			if len(got) != size {
				t.Errorf("ClearFPLMN(%d) length = %d, want %d", size, len(got), size)
			}
			for i, b := range got {
				if b != 0xFF {
					t.Errorf("ClearFPLMN(%d)[%d] = %02X, want 0xFF", size, i, b)
				}
			}
		})
	}
}

// ============ ISIM ENCODER TESTS ============

func TestEncodeIMPI(t *testing.T) {
	impi := "250880000000017@ims.mnc088.mcc250.3gppnetwork.org"
	maxLen := 128

	got := EncodeIMPI(impi, maxLen)

	if len(got) != maxLen {
		t.Errorf("EncodeIMPI() length = %d, want %d", len(got), maxLen)
	}

	// Should start with TLV tag 0x80
	if got[0] != 0x80 {
		t.Errorf("EncodeIMPI() first byte = %02X, want 0x80", got[0])
	}
}

func TestEncodeIMPU(t *testing.T) {
	impu := "sip:250880000000017@ims.mnc088.mcc250.3gppnetwork.org"
	maxLen := 128

	got := EncodeIMPU(impu, maxLen)

	if len(got) != maxLen {
		t.Errorf("EncodeIMPU() length = %d, want %d", len(got), maxLen)
	}

	// Should start with TLV tag 0x80
	if got[0] != 0x80 {
		t.Errorf("EncodeIMPU() first byte = %02X, want 0x80", got[0])
	}
}

func TestEncodeDomain(t *testing.T) {
	domain := "ims.mnc088.mcc250.3gppnetwork.org"
	maxLen := 64

	got := EncodeDomain(domain, maxLen)

	if len(got) != maxLen {
		t.Errorf("EncodeDomain() length = %d, want %d", len(got), maxLen)
	}

	// Should start with TLV tag 0x80
	if got[0] != 0x80 {
		t.Errorf("EncodeDomain() first byte = %02X, want 0x80", got[0])
	}
}

func TestEncodePCSCF(t *testing.T) {
	pcscf := "pcscf.ims.mnc088.mcc250.3gppnetwork.org"
	maxLen := 64

	got := EncodePCSCF(pcscf, maxLen)

	if len(got) != maxLen {
		t.Errorf("EncodePCSCF() length = %d, want %d", len(got), maxLen)
	}
}

// ============ ROUNDTRIP ENCODER/DECODER TESTS ============

func TestIMSI_Roundtrip(t *testing.T) {
	imsis := []string{
		"250880000000001",
		"250880000000017",
		"310410123456789",
		"001010000000001",
	}

	for _, imsi := range imsis {
		t.Run(imsi, func(t *testing.T) {
			encoded, err := EncodeIMSI(imsi)
			if err != nil {
				t.Fatalf("EncodeIMSI() error = %v", err)
			}
			decoded := DecodeIMSI(encoded)
			if decoded != imsi {
				t.Errorf("Roundtrip: %s -> %X -> %s", imsi, encoded, decoded)
			}
		})
	}
}

func TestPLMN_Roundtrip(t *testing.T) {
	plmns := []struct{ mcc, mnc string }{
		{"250", "88"},
		{"250", "02"},
		{"310", "410"},
		{"311", "480"},
		{"001", "01"},
	}

	for _, p := range plmns {
		t.Run(p.mcc+"/"+p.mnc, func(t *testing.T) {
			encoded, err := EncodePLMN(p.mcc, p.mnc)
			if err != nil {
				t.Fatalf("EncodePLMN() error = %v", err)
			}
			gotMCC, gotMNC := DecodePLMN(encoded)
			if gotMCC != p.mcc || gotMNC != p.mnc {
				t.Errorf("Roundtrip: %s/%s -> %X -> %s/%s", p.mcc, p.mnc, encoded, gotMCC, gotMNC)
			}
		})
	}
}
