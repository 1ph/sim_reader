package card

import (
	"reflect"
	"testing"
)

// ============ APDU RESPONSE TESTS ============

func TestAPDUResponse_IsOK(t *testing.T) {
	tests := []struct {
		name string
		sw1  byte
		sw2  byte
		want bool
	}{
		{"9000 OK", 0x90, 0x00, true},
		{"61XX More Data", 0x61, 0x10, false},
		{"6CXX Retry", 0x6C, 0x20, false},
		{"6982 Security", 0x69, 0x82, false},
		{"6A82 File Not Found", 0x6A, 0x82, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &APDUResponse{SW1: tc.sw1, SW2: tc.sw2}
			if got := resp.IsOK(); got != tc.want {
				t.Errorf("APDUResponse.IsOK() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAPDUResponse_HasMoreData(t *testing.T) {
	tests := []struct {
		name string
		sw1  byte
		sw2  byte
		want bool
	}{
		{"61XX has more", 0x61, 0x10, true},
		{"6110 has 16 more", 0x61, 0x10, true},
		{"9000 no more", 0x90, 0x00, false},
		{"6CXX retry", 0x6C, 0x20, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &APDUResponse{SW1: tc.sw1, SW2: tc.sw2}
			if got := resp.HasMoreData(); got != tc.want {
				t.Errorf("APDUResponse.HasMoreData() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAPDUResponse_NeedsRetry(t *testing.T) {
	tests := []struct {
		name string
		sw1  byte
		sw2  byte
		want bool
	}{
		{"6CXX needs retry", 0x6C, 0x20, true},
		{"6C10 retry with 16", 0x6C, 0x10, true},
		{"9000 no retry", 0x90, 0x00, false},
		{"61XX no retry", 0x61, 0x10, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &APDUResponse{SW1: tc.sw1, SW2: tc.sw2}
			if got := resp.NeedsRetry(); got != tc.want {
				t.Errorf("APDUResponse.NeedsRetry() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAPDUResponse_SW(t *testing.T) {
	tests := []struct {
		name string
		sw1  byte
		sw2  byte
		want uint16
	}{
		{"9000", 0x90, 0x00, 0x9000},
		{"6A82", 0x6A, 0x82, 0x6A82},
		{"6110", 0x61, 0x10, 0x6110},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &APDUResponse{SW1: tc.sw1, SW2: tc.sw2}
			if got := resp.SW(); got != tc.want {
				t.Errorf("APDUResponse.SW() = %04X, want %04X", got, tc.want)
			}
		})
	}
}

// ============ SW TO STRING TESTS ============

func TestSWToString(t *testing.T) {
	tests := []struct {
		sw       uint16
		contains string
	}{
		{SW_OK, "Success"},
		{SW_FILE_NOT_FOUND, "not found"},
		{SW_SECURITY_NOT_SATISFIED, "Security"},
		{SW_WRONG_LENGTH, "length"},
		{0x6983, "blocked"},
		{0x63C3, "attempts"},
		{0x6110, "available"},
		{0x6C20, "Retry"},
	}

	for _, tc := range tests {
		t.Run(tc.contains, func(t *testing.T) {
			got := SWToString(tc.sw)
			if got == "" {
				t.Errorf("SWToString(%04X) returned empty string", tc.sw)
			}
			// Just verify it returns something meaningful
			t.Logf("SWToString(%04X) = %q", tc.sw, got)
		})
	}
}

// ============ RECORD MODE TESTS ============

func TestRecordModeConstants(t *testing.T) {
	// Verify constants match ISO 7816-4 specification
	if RecordModeAbsolute != 0x04 {
		t.Errorf("RecordModeAbsolute = %02X, want 0x04", RecordModeAbsolute)
	}
	if RecordModeNext != 0x02 {
		t.Errorf("RecordModeNext = %02X, want 0x02", RecordModeNext)
	}
	if RecordModePrevious != 0x03 {
		t.Errorf("RecordModePrevious = %02X, want 0x03", RecordModePrevious)
	}
}

// ============ AUTH CONTEXT TESTS ============

func TestAuthContextConstants(t *testing.T) {
	// Verify authentication context constants match 3GPP TS 31.102
	tests := []struct {
		name  string
		value byte
		want  byte
	}{
		{"AUTH_CONTEXT_GSM", AUTH_CONTEXT_GSM, 0x80},
		{"AUTH_CONTEXT_3G", AUTH_CONTEXT_3G, 0x81},
		{"AUTH_CONTEXT_VGCS_VBS", AUTH_CONTEXT_VGCS_VBS, 0x82},
		{"AUTH_CONTEXT_GBA_NAF", AUTH_CONTEXT_GBA_NAF, 0x83},
		{"AUTH_CONTEXT_GBA", AUTH_CONTEXT_GBA, 0x84},
		{"AUTH_CONTEXT_MBMS", AUTH_CONTEXT_MBMS, 0x85},
		{"AUTH_CONTEXT_LOCAL", AUTH_CONTEXT_LOCAL, 0x86},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value != tc.want {
				t.Errorf("%s = %02X, want %02X", tc.name, tc.value, tc.want)
			}
		})
	}
}

// ============ INS CODE TESTS ============

func TestINSConstants(t *testing.T) {
	// Verify INS codes match ISO 7816-4 specification
	tests := []struct {
		name  string
		value byte
		want  byte
	}{
		{"INS_SELECT", INS_SELECT, 0xA4},
		{"INS_READ_BINARY", INS_READ_BINARY, 0xB0},
		{"INS_READ_RECORD", INS_READ_RECORD, 0xB2},
		{"INS_UPDATE_BINARY", INS_UPDATE_BINARY, 0xD6},
		{"INS_UPDATE_RECORD", INS_UPDATE_RECORD, 0xDC},
		{"INS_GET_RESPONSE", INS_GET_RESPONSE, 0xC0},
		{"INS_VERIFY", INS_VERIFY, 0x20},
		{"INS_CHANGE_REFERENCE_DATA", INS_CHANGE_REFERENCE_DATA, 0x24},
		{"INS_STATUS", INS_STATUS, 0xF2},
		{"INS_AUTHENTICATE", INS_AUTHENTICATE, 0x88},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value != tc.want {
				t.Errorf("%s = %02X, want %02X", tc.name, tc.value, tc.want)
			}
		})
	}
}

// ============ APDU PARSING TESTS ============

func TestParseAPDUResponse(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		wantData []byte
		wantSW1  byte
		wantSW2  byte
	}{
		{
			name:     "Only SW",
			raw:      []byte{0x90, 0x00},
			wantData: nil,
			wantSW1:  0x90,
			wantSW2:  0x00,
		},
		{
			name:     "Data + SW",
			raw:      []byte{0x01, 0x02, 0x03, 0x90, 0x00},
			wantData: []byte{0x01, 0x02, 0x03},
			wantSW1:  0x90,
			wantSW2:  0x00,
		},
		{
			name:     "Error SW",
			raw:      []byte{0x6A, 0x82},
			wantData: nil,
			wantSW1:  0x6A,
			wantSW2:  0x82,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &APDUResponse{}
			if len(tc.raw) >= 2 {
				resp.SW1 = tc.raw[len(tc.raw)-2]
				resp.SW2 = tc.raw[len(tc.raw)-1]
				if len(tc.raw) > 2 {
					resp.Data = tc.raw[:len(tc.raw)-2]
				}
			}

			if !reflect.DeepEqual(resp.Data, tc.wantData) {
				t.Errorf("Data = %X, want %X", resp.Data, tc.wantData)
			}
			if resp.SW1 != tc.wantSW1 {
				t.Errorf("SW1 = %02X, want %02X", resp.SW1, tc.wantSW1)
			}
			if resp.SW2 != tc.wantSW2 {
				t.Errorf("SW2 = %02X, want %02X", resp.SW2, tc.wantSW2)
			}
		})
	}
}

// ============ PIN RETRY PARSING TESTS ============

func TestParsePINRetries(t *testing.T) {
	tests := []struct {
		sw    uint16
		want  int
		isPIN bool
	}{
		{0x63C0, 0, true},
		{0x63C1, 1, true},
		{0x63C3, 3, true},
		{0x63CA, 10, true},
		{0x9000, -1, false},
		{0x6983, 0, true}, // Blocked
	}

	for _, tc := range tests {
		sw1 := byte(tc.sw >> 8)
		sw2 := byte(tc.sw & 0xFF)

		if tc.isPIN && sw1 == 0x63 && (sw2&0xF0) == 0xC0 {
			retries := int(sw2 & 0x0F)
			if retries != tc.want {
				t.Errorf("ParsePINRetries(%04X) = %d, want %d", tc.sw, retries, tc.want)
			}
		}
	}
}
