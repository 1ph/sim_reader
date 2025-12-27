package esim

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Minimal profile example for unit tests (header + end)
// A0 18 = ProfileHeader [0], length 24 (0x18)
// 80 01 02 = [0] major-version = 2
// 81 01 03 = [1] minor-version = 3
// 82 04 54657374 = [2] profileType = "Test"
// 83 0A 89000123456789012341 = [3] iccid (normal BCD)
// AA 05 = End [10] constructed, length 5
// A0 03 80 01 1F = end-header with identification = 31
var minimalProfileHex = "A018" + // ProfileHeader [0], length 24
	"8001" + "02" + // major-version = 2 (3 bytes)
	"8101" + "03" + // minor-version = 3 (3 bytes)
	"8204" + "54657374" + // profileType = "Test" (6 bytes)
	"830A" + "89000123456789012341" + // iccid (12 bytes) = 24 total, normal BCD
	"AA05" + // End [10] constructed, length 5
	"A003" + // end-header [0], length 3
	"8101" + "1F" // identification = 31 (not mandated, so use [1])

func TestDecodeMinimalProfile(t *testing.T) {
	data, err := hex.DecodeString(minimalProfileHex)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}

	profile, err := DecodeProfile(data)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Check Header
	if profile.Header == nil {
		t.Fatal("header is nil")
	}

	if profile.Header.MajorVersion != 2 {
		t.Errorf("wrong major version: got %d, want 2", profile.Header.MajorVersion)
	}

	if profile.Header.MinorVersion != 3 {
		t.Errorf("wrong minor version: got %d, want 3", profile.Header.MinorVersion)
	}

	if profile.Header.ProfileType != "Test" {
		t.Errorf("wrong profile type: got %s, want Test", profile.Header.ProfileType)
	}

	// Check ICCID
	iccid := profile.GetICCID()
	if iccid != "89000123456789012341" {
		t.Errorf("wrong ICCID: got %s, want 89000123456789012341", iccid)
	}

	// Check End
	if profile.End == nil {
		t.Error("end element is nil")
	}

	// Check elements count
	if len(profile.Elements) != 2 {
		t.Errorf("wrong elements count: got %d, want 2", len(profile.Elements))
	}
}

func TestDecodeOID(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected OID
	}{
		{
			name:     "simple OID",
			input:    []byte{0x55, 0x04, 0x03}, // 2.5.4.3
			expected: OID{2, 5, 4, 3},
		},
		{
			name:     "GSMA template OID",
			input:    []byte{0x67, 0x81, 0x0F, 0x01, 0x02, 0x01}, // 2.23.143.1.2.1
			expected: OID{2, 23, 143, 1, 2, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeOID(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("wrong OID length: got %d, want %d", len(result), len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("wrong OID component [%d]: got %d, want %d", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestEncodeOID(t *testing.T) {
	tests := []struct {
		name     string
		input    OID
		expected []byte
	}{
		{
			name:     "simple OID",
			input:    OID{2, 5, 4, 3},
			expected: []byte{0x55, 0x04, 0x03},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeOID(tt.input)
			if hex.EncodeToString(result) != hex.EncodeToString(tt.expected) {
				t.Errorf("wrong OID encoding: got %s, want %s",
					hex.EncodeToString(result), hex.EncodeToString(tt.expected))
			}
		})
	}
}

func TestDecodeSwappedBCD(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "ICCID",
			input:    []byte{0x98, 0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x14},
			expected: "89000123456789012341",
		},
		{
			name:     "with padding",
			input:    []byte{0x09, 0x10, 0x10, 0xF1},
			expected: "9001011",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeSwappedBCD(tt.input)
			if result != tt.expected {
				t.Errorf("wrong BCD: got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestEncodeSwappedBCD(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "even length",
			input:    "1234",
			expected: []byte{0x21, 0x43},
		},
		{
			name:     "odd length",
			input:    "123",
			expected: []byte{0x21, 0xF3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeSwappedBCD(tt.input)
			if hex.EncodeToString(result) != hex.EncodeToString(tt.expected) {
				t.Errorf("wrong BCD encoding: got %s, want %s",
					hex.EncodeToString(result), hex.EncodeToString(tt.expected))
			}
		})
	}
}

func TestDecodeIMSI(t *testing.T) {
	// EF_IMSI format: length + swapped BCD with parity
	input := []byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98}
	// First nibble is parity, the rest is IMSI
	result := decodeIMSI(input)
	expected := "001010123456789"

	if result != expected {
		t.Errorf("wrong IMSI: got %s, want %s", result, expected)
	}
}

func TestEncodeInteger(t *testing.T) {
	tests := []struct {
		input    int
		expected []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{127, []byte{127}},
		{128, []byte{0, 128}}, // needs leading zero for unsigned
		{255, []byte{0, 255}},
		{256, []byte{1, 0}},
		{65535, []byte{0, 255, 255}},
	}

	for _, tt := range tests {
		result := encodeInteger(tt.input)
		if hex.EncodeToString(result) != hex.EncodeToString(tt.expected) {
			t.Errorf("encodeInteger(%d): got %s, want %s",
				tt.input, hex.EncodeToString(result), hex.EncodeToString(tt.expected))
		}
	}
}

func TestRoundTripMinimalProfile(t *testing.T) {
	original, err := hex.DecodeString(minimalProfileHex)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}

	// Decode
	profile, err := DecodeProfile(original)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Encode back
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	// Compare (sizes may differ due to optional fields)
	t.Logf("Original: %s", hex.EncodeToString(original))
	t.Logf("Encoded:  %s", hex.EncodeToString(encoded))

	// Verify we can decode again
	profile2, err := DecodeProfile(encoded)
	if err != nil {
		t.Fatalf("decode of encoded failed: %v", err)
	}

	// Check key fields
	if profile2.GetICCID() != profile.GetICCID() {
		t.Errorf("ICCID mismatch after round-trip")
	}
}

func TestProfileHelperMethods(t *testing.T) {
	profile := &Profile{
		Header: &ProfileHeader{
			MajorVersion: 2,
			MinorVersion: 3,
			ProfileType:  "Test Profile",
			ICCID:        []byte{0x89, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x41}, // normal BCD
		},
		AKAParams: []*AKAParameter{
			{
				AlgoConfig: &AlgoConfiguration{
					AlgorithmID: AlgoMilenage,
					Key:         make([]byte, 16),
					OPC:         make([]byte, 16),
				},
			},
		},
		PukCodes: &PUKCodes{
			Codes: []PUKCode{
				{KeyReference: 0x01, PUKValue: []byte("12345678")},
			},
		},
		PinCodes: []*PINCodes{
			{
				Configs: []PINConfig{
					{KeyReference: 0x01, PINValue: []byte("1234\xFF\xFF\xFF\xFF")},
					{KeyReference: 0x0A, PINValue: []byte("55555555")},
				},
			},
		},
	}

	// Test GetICCID
	if iccid := profile.GetICCID(); iccid != "89000123456789012341" {
		t.Errorf("GetICCID: got %s", iccid)
	}

	// Test GetVersion
	major, minor := profile.GetVersion()
	if major != 2 || minor != 3 {
		t.Errorf("GetVersion: got %d.%d", major, minor)
	}

	// Test GetAlgorithmName
	if name := profile.GetAlgorithmName(); name != "Milenage" {
		t.Errorf("GetAlgorithmName: got %s", name)
	}

	// Test GetPIN1
	if pin := profile.GetPIN1(); pin != "1234" {
		t.Errorf("GetPIN1: got %s", pin)
	}

	// Test GetPUK1
	if puk := profile.GetPUK1(); puk != "12345678" {
		t.Errorf("GetPUK1: got %s", puk)
	}

	// Test GetADM1
	if adm := profile.GetADM1(); adm != "55555555" {
		t.Errorf("GetADM1: got %s", adm)
	}

	// Test String
	str := profile.String()
	if str == "" {
		t.Error("String() returned empty")
	}
	t.Log(str)
}

func TestLoadProfileFromFile(t *testing.T) {
	// Look for test files
	testDataDir := "testdata"
	if _, err := os.Stat(testDataDir); os.IsNotExist(err) {
		t.Skip("testdata directory not found, skipping file tests")
	}

	files, err := filepath.Glob(filepath.Join(testDataDir, "*.der"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}

	if len(files) == 0 {
		t.Skip("no .der files in testdata")
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			profile, err := LoadProfile(file)
			if err != nil {
				t.Fatalf("LoadProfile failed: %v", err)
			}

			t.Logf("Profile: %s", profile.String())
			t.Logf("Elements: %d", len(profile.Elements))

			// Basic checks
			if profile.Header == nil {
				t.Error("Header is nil")
			}

			if iccid := profile.GetICCID(); iccid == "" {
				t.Error("ICCID is empty")
			}
		})
	}
}

func TestGetProfileElementName(t *testing.T) {
	tests := []struct {
		tag      int
		expected string
	}{
		{TagProfileHeader, "header"},
		{TagMF, "mf"},
		{TagUSIM, "usim"},
		{TagISIM, "isim"},
		{TagAKAParameter, "akaParameter"},
		{TagSecurityDomain, "securityDomain"},
		{TagEnd, "end"},
		{999, "unknown"},
	}

	for _, tt := range tests {
		result := GetProfileElementName(tt.tag)
		if result != tt.expected {
			t.Errorf("GetProfileElementName(%d): got %s, want %s", tt.tag, result, tt.expected)
		}
	}
}

func TestClone(t *testing.T) {
	original := &Profile{
		Header: &ProfileHeader{
			MajorVersion: 2,
			MinorVersion: 3,
			ProfileType:  "Test",
			ICCID:        []byte{0x98, 0x00, 0x10},
		},
		Elements: []ProfileElement{
			{Tag: TagProfileHeader, Value: nil},
		},
	}
	original.Elements[0].Value = original.Header

	clone, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}

	// Modify original
	original.Header.MajorVersion = 99

	// Verify clone was not modified
	if clone.Header.MajorVersion == 99 {
		t.Error("Clone was affected by original modification")
	}
}

func TestSetIMSI(t *testing.T) {
	profile := &Profile{
		USIM: &USIMApplication{
			EF_IMSI: &ElementaryFile{
				FillContents: []FillContent{
					{Content: []byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98}},
				},
			},
		},
	}

	newIMSI := "123456789012345"
	err := profile.SetIMSI(newIMSI)
	if err != nil {
		t.Fatalf("SetIMSI failed: %v", err)
	}

	// Verify IMSI was changed
	got := profile.GetIMSI()
	if got != newIMSI {
		t.Errorf("GetIMSI after SetIMSI: got %s, want %s", got, newIMSI)
	}
}
