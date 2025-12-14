package sim

import (
	"testing"
)

// ============ FCP PARSING TESTS ============
// Tests for File Control Parameters parsing per ETSI TS 102 221

// TestParseTLVLength tests extended length format parsing
func TestParseTLVLength(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		offset    int
		wantLen   int
		wantBytes int
	}{
		// Short form (< 0x80)
		{"Short 0", []byte{0x00}, 0, 0, 1},
		{"Short 10", []byte{0x0A}, 0, 10, 1},
		{"Short 127", []byte{0x7F}, 0, 127, 1},

		// Extended form 0x81 (1 byte follows)
		{"Extended 0x81 128", []byte{0x81, 0x80}, 0, 128, 2},
		{"Extended 0x81 255", []byte{0x81, 0xFF}, 0, 255, 2},

		// Extended form 0x82 (2 bytes follow)
		{"Extended 0x82 256", []byte{0x82, 0x01, 0x00}, 0, 256, 3},
		{"Extended 0x82 1000", []byte{0x82, 0x03, 0xE8}, 0, 1000, 3},
		{"Extended 0x82 65535", []byte{0x82, 0xFF, 0xFF}, 0, 65535, 3},

		// Extended form 0x83 (3 bytes follow)
		{"Extended 0x83 65536", []byte{0x83, 0x01, 0x00, 0x00}, 0, 65536, 4},

		// With offset
		{"Offset 1", []byte{0xFF, 0x10}, 1, 16, 1},
		{"Offset 2", []byte{0xFF, 0xFF, 0x81, 0x80}, 2, 128, 2},

		// Error cases
		{"Empty", []byte{}, 0, 0, 0},
		{"Offset out of bounds", []byte{0x10}, 5, 0, 0},
		{"0x81 truncated", []byte{0x81}, 0, 0, 0},
		{"0x82 truncated", []byte{0x82, 0x01}, 0, 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLen, gotBytes := parseTLVLength(tc.data, tc.offset)
			if gotLen != tc.wantLen {
				t.Errorf("parseTLVLength() length = %d, want %d", gotLen, tc.wantLen)
			}
			if gotBytes != tc.wantBytes {
				t.Errorf("parseTLVLength() bytes consumed = %d, want %d", gotBytes, tc.wantBytes)
			}
		})
	}
}

// TestParseFCPFileSize tests file size extraction from FCP template
func TestParseFCPFileSize(t *testing.T) {
	tests := []struct {
		name string
		fcp  []byte
		want int
	}{
		// Standard FCP with tag 0x80 (file size)
		{
			name: "Simple FCP 256 bytes",
			fcp:  []byte{0x62, 0x06, 0x80, 0x02, 0x01, 0x00, 0x82, 0x02},
			want: 256,
		},
		{
			name: "Simple FCP 17 bytes",
			fcp:  []byte{0x62, 0x06, 0x80, 0x02, 0x00, 0x11, 0x82, 0x02},
			want: 17,
		},
		{
			name: "FCP with multiple tags",
			fcp:  []byte{0x62, 0x0C, 0x82, 0x02, 0x01, 0x02, 0x80, 0x02, 0x00, 0x50, 0x83, 0x02, 0x6F, 0x07},
			want: 80,
		},

		// FCP with tag 0x81 (alternative file size - some cards)
		{
			name: "FCP with tag 0x81",
			fcp:  []byte{0x62, 0x06, 0x81, 0x02, 0x02, 0x00, 0x82, 0x02},
			want: 512,
		},

		// Extended length FCP
		{
			name: "FCP with extended length",
			fcp:  []byte{0x62, 0x81, 0x08, 0x80, 0x02, 0x10, 0x00, 0x82, 0x02, 0x01, 0x02},
			want: 4096,
		},

		// Empty / invalid cases
		{
			name: "Empty FCP",
			fcp:  []byte{},
			want: 0,
		},
		{
			name: "Too short FCP",
			fcp:  []byte{0x62, 0x02},
			want: 0,
		},
		{
			name: "No file size tag",
			fcp:  []byte{0x62, 0x04, 0x82, 0x02, 0x01, 0x02},
			want: 0,
		},

		// Real card FCP examples
		{
			name: "Real EF_IMSI FCP",
			fcp:  []byte{0x62, 0x17, 0x82, 0x02, 0x41, 0x21, 0x83, 0x02, 0x6F, 0x07, 0xA5, 0x03, 0x80, 0x01, 0x71, 0x8A, 0x01, 0x05, 0x8B, 0x03, 0x6F, 0x06, 0x02, 0x80, 0x02, 0x00, 0x09},
			want: 9,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseFCPFileSize(tc.fcp)
			if got != tc.want {
				t.Errorf("parseFCPFileSize() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestParseFCPRecordSize tests record size extraction from FCP template
func TestParseFCPRecordSize(t *testing.T) {
	tests := []struct {
		name string
		fcp  []byte
		want int
	}{
		// Linear fixed file with 5-byte file descriptor
		{
			name: "Linear fixed record size 128",
			fcp:  []byte{0x62, 0x0A, 0x82, 0x05, 0x02, 0x21, 0x00, 0x80, 0x0A, 0x80, 0x02},
			want: 128,
		},
		{
			name: "Linear fixed record size 34",
			fcp:  []byte{0x62, 0x0A, 0x82, 0x05, 0x02, 0x21, 0x00, 0x22, 0x05, 0x80, 0x02},
			want: 34,
		},

		// Short format (3-byte file descriptor)
		{
			name: "Short format record size 64",
			fcp:  []byte{0x62, 0x08, 0x82, 0x03, 0x02, 0x00, 0x40, 0x80, 0x02, 0x01, 0x00},
			want: 64,
		},

		// Transparent file (no record size)
		{
			name: "Transparent file",
			fcp:  []byte{0x62, 0x0A, 0x82, 0x02, 0x41, 0x21, 0x80, 0x02, 0x00, 0x09},
			want: 0,
		},

		// Empty / invalid
		{
			name: "Empty FCP",
			fcp:  []byte{},
			want: 0,
		},
		{
			name: "No file descriptor",
			fcp:  []byte{0x62, 0x04, 0x80, 0x02, 0x01, 0x00},
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseFCPRecordSize(tc.fcp)
			if got != tc.want {
				t.Errorf("parseFCPRecordSize() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestParseFCPNumRecords tests number of records extraction
func TestParseFCPNumRecords(t *testing.T) {
	tests := []struct {
		name string
		fcp  []byte
		want int
	}{
		{
			name: "5 records",
			fcp:  []byte{0x62, 0x0A, 0x82, 0x05, 0x02, 0x21, 0x00, 0x80, 0x05, 0x80, 0x02},
			want: 5,
		},
		{
			name: "10 records",
			fcp:  []byte{0x62, 0x0A, 0x82, 0x05, 0x02, 0x21, 0x00, 0x40, 0x0A, 0x80, 0x02},
			want: 10,
		},
		{
			name: "No records (transparent)",
			fcp:  []byte{0x62, 0x06, 0x82, 0x02, 0x41, 0x21, 0x80, 0x02},
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseFCPNumRecords(tc.fcp)
			if got != tc.want {
				t.Errorf("parseFCPNumRecords() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ============ FCP TAG CONSTANTS TESTS ============

func TestFCPTagConstants(t *testing.T) {
	// Verify FCP tags match ETSI TS 102 221
	expectedTags := map[string]byte{
		"FCP Template":     0x62,
		"File Size":        0x80,
		"File Size Alt":    0x81,
		"File Descriptor":  0x82,
		"File ID":          0x83,
		"DF Name (AID)":    0x84,
		"Proprietary":      0x85,
		"Lifecycle Status": 0x8A,
		"Security Compact": 0x8C,
		"Security Exp":     0xAB,
		"Security Ref":     0x8B,
		"PIN Status":       0xC6,
	}

	// These are just documentation tests - the actual parsing uses literal values
	for name, expectedTag := range expectedTags {
		t.Logf("FCP Tag %s: 0x%02X", name, expectedTag)
	}
}
