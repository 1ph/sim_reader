package esim

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestDecodeRealProfile tests decoding of real GSMA test profile
// Reference: TS48 V7.0 eSIM_GTP_SAIP2.3_BERTLV_SUCI
func TestDecodeRealProfile(t *testing.T) {
	// testFile := filepath.Join("testdata", "TS48_SAIP2.3_BERTLV_SUCI.der")
	testFile := filepath.Join("testdata", "applet-only.der")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("Test file not found, skipping real profile test")
	}

	profile, err := LoadProfile(testFile)
	if err != nil {
		t.Fatalf("Failed to load profile: %v", err)
	}

	// Verify profile header according to ASN.1 value notation:
	// major-version 2, minor-version 3
	t.Run("Header", func(t *testing.T) {
		if profile.Header == nil {
			t.Fatal("Header is nil")
		}

		if profile.Header.MajorVersion != 2 {
			t.Errorf("MajorVersion: got %d, want 2", profile.Header.MajorVersion)
		}

		if profile.Header.MinorVersion != 3 {
			t.Errorf("MinorVersion: got %d, want 3", profile.Header.MinorVersion)
		}

		// profileType "GSMA Generic eUICC Test Profile"
		expectedType := "GSMA Generic eUICC Test Profile"
		if profile.Header.ProfileType != expectedType {
			t.Errorf("ProfileType: got %q, want %q", profile.Header.ProfileType, expectedType)
		}

		// iccid '89000123456789012341'H (BCD)
		expectedICCID := "89000123456789012341"
		if iccid := profile.GetICCID(); iccid != expectedICCID {
			t.Errorf("ICCID: got %s, want %s", iccid, expectedICCID)
		}
	})

	// Verify mandatory services
	t.Run("MandatoryServices", func(t *testing.T) {
		if profile.Header.MandatoryServices == nil {
			t.Fatal("MandatoryServices is nil")
		}
		ms := profile.Header.MandatoryServices

		// usim NULL, isim NULL, csim NULL
		if !ms.USIM {
			t.Error("USIM should be mandatory")
		}
		if !ms.ISIM {
			t.Error("ISIM should be mandatory")
		}
		if !ms.CSIM {
			t.Error("CSIM should be mandatory")
		}
		if !ms.USIMTestAlgorithm {
			t.Error("USIMTestAlgorithm should be mandatory")
		}
		if !ms.BERTLV {
			t.Error("BERTLV should be mandatory")
		}
		if !ms.GetIdentity {
			t.Error("GetIdentity should be mandatory")
		}
		if !ms.ProfileAX25519 {
			t.Error("ProfileAX25519 should be mandatory")
		}
		if !ms.ProfileBP256 {
			t.Error("ProfileBP256 should be mandatory")
		}
	})

	// Verify MF
	t.Run("MasterFile", func(t *testing.T) {
		if profile.MF == nil {
			t.Fatal("MF is nil")
		}

		// mf-header identification 4
		if profile.MF.MFHeader != nil {
			if !profile.MF.MFHeader.Mandated {
				t.Error("MF should be mandated")
			}
			if profile.MF.MFHeader.Identification != 4 {
				t.Errorf("MF identification: got %d, want 4", profile.MF.MFHeader.Identification)
			}
		}

		// templateID { 2 23 143 1 2 1 }
		expectedOID := OID{2, 23, 143, 1, 2, 1}
		if len(profile.MF.TemplateID) >= len(expectedOID) {
			for i := range expectedOID {
				if profile.MF.TemplateID[i] != expectedOID[i] {
					t.Errorf("MF templateID[%d]: got %d, want %d", i, profile.MF.TemplateID[i], expectedOID[i])
				}
			}
		}
	})

	// Verify PUK codes
	t.Run("PUKCodes", func(t *testing.T) {
		if profile.PukCodes == nil {
			t.Fatal("PukCodes is nil")
		}

		// puk-Header identification 5
		if profile.PukCodes.Header != nil {
			if profile.PukCodes.Header.Identification != 5 {
				t.Errorf("PUK identification: got %d, want 5", profile.PukCodes.Header.Identification)
			}
		}
	})

	// Verify applications are detected
	t.Run("Applications", func(t *testing.T) {
		if !profile.HasUSIM() {
			t.Error("USIM should be present")
		}
		if !profile.HasISIM() {
			t.Error("ISIM should be present")
		}
		if !profile.HasCSIM() {
			t.Error("CSIM should be present")
		}
	})

	// Verify End element
	t.Run("End", func(t *testing.T) {
		if profile.End == nil {
			t.Fatal("End is nil")
		}

		// end-header identification 31
		if profile.End.Header != nil {
			if profile.End.Header.Identification != 31 {
				t.Errorf("End identification: got %d, want 31", profile.End.Header.Identification)
			}
		}
	})

	// Verify element count
	t.Run("ElementCount", func(t *testing.T) {
		// According to value notation: 30 profile elements
		expectedCount := 30
		if len(profile.Elements) != expectedCount {
			t.Errorf("Element count: got %d, want %d", len(profile.Elements), expectedCount)
		}
	})

	// Log profile summary
	t.Logf("Profile summary:\n%s", profile.Summary())
}

// TestDecodeEncodeCompareElements compares individual elements
func TestDecodeEncodeCompareElements(t *testing.T) {
	testFile := filepath.Join("testdata", "TS48_SAIP2.3_BERTLV_SUCI.der")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("Test file not found")
	}

	original, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	profile, err := DecodeProfile(original)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	t.Logf("Decoded %d elements:", len(profile.Elements))
	for i, elem := range profile.Elements {
		name := GetProfileElementName(elem.Tag)
		t.Logf("  [%2d] Tag=%2d (%s)", i, elem.Tag, name)
	}
}

// TestProfileHelperMethodsRealProfile tests helper methods with real data
func TestProfileHelperMethodsRealProfile(t *testing.T) {
	testFile := filepath.Join("testdata", "TS48_SAIP2.3_BERTLV_SUCI.der")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("Test file not found")
	}

	profile, err := LoadProfile(testFile)
	if err != nil {
		t.Fatalf("Failed to load: %v", err)
	}

	// Test basic helper methods that should work
	t.Run("GetICCID", func(t *testing.T) {
		iccid := profile.GetICCID()
		if iccid != "89000123456789012341" {
			t.Errorf("got %s", iccid)
		}
	})

	t.Run("GetProfileType", func(t *testing.T) {
		ptype := profile.GetProfileType()
		if ptype != "GSMA Generic eUICC Test Profile" {
			t.Errorf("got %s", ptype)
		}
	})

	t.Run("GetVersion", func(t *testing.T) {
		major, minor := profile.GetVersion()
		if major != 2 || minor != 3 {
			t.Errorf("got %d.%d", major, minor)
		}
	})

	t.Run("HasApplications", func(t *testing.T) {
		if !profile.HasUSIM() {
			t.Error("should have USIM")
		}
		if !profile.HasISIM() {
			t.Error("should have ISIM")
		}
		if !profile.HasCSIM() {
			t.Error("should have CSIM")
		}
	})
}

// TestProfileElementsOrder verifies the order of profile elements matches specification
func TestProfileElementsOrder(t *testing.T) {
	testFile := filepath.Join("testdata", "TS48_SAIP2.3_BERTLV_SUCI.der")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("Test file not found")
	}

	profile, err := LoadProfile(testFile)
	if err != nil {
		t.Fatalf("Failed to load: %v", err)
	}

	// Expected order from text value notation:
	// value1=header, value2=mf, value3=pukCodes, value4=pinCodes, value5=telecom,
	// value6=pinCodes, value7=genericFileManagement, value8=usim, value9=opt-usim,
	// value10=pinCodes, value11=akaParameter, value12=gsm-access, value13=df-5gs,
	// value14=df-saip, value15=csim, value16=opt-csim, value17=pinCodes,
	// value18=cdmaParameter, value19=isim, value20=opt-isim, value21=pinCodes,
	// value22=akaParameter, value23=genericFileManagement, value24=genericFileManagement,
	// value25=securityDomain, value26=rfm, value27=rfm, value28=rfm, value29=rfm, value30=end

	expectedTags := []int{
		TagProfileHeader,         // 0 - header
		TagMF,                    // 16 - mf
		TagPukCodes,              // 3 - pukCodes
		TagPinCodes,              // 2 - pinCodes
		TagTelecom,               // 18 - telecom
		TagPinCodes,              // 2 - pinCodes
		TagGenericFileManagement, // 1 - genericFileManagement
		TagUSIM,                  // 19 - usim
		TagOptUSIM,               // 20 - opt-usim
		TagPinCodes,              // 2 - pinCodes
		TagAKAParameter,          // 4 - akaParameter
		TagGSMAccess,             // 24 - gsm-access
		TagDF5GS,                 // 28 - df-5gs
		TagDFSAIP,                // 29 - df-saip
		TagCSIM,                  // 25 - csim
		TagOptCSIM,               // 26 - opt-csim
		TagPinCodes,              // 2 - pinCodes
		TagCDMAParameter,         // 5 - cdmaParameter
		TagISIM,                  // 21 - isim
		TagOptISIM,               // 22 - opt-isim
		TagPinCodes,              // 2 - pinCodes
		TagAKAParameter,          // 4 - akaParameter
		TagGenericFileManagement, // 1 - genericFileManagement
		TagGenericFileManagement, // 1 - genericFileManagement
		TagSecurityDomain,        // 6 - securityDomain
		TagRFM,                   // 7 - rfm
		TagRFM,                   // 7 - rfm
		TagRFM,                   // 7 - rfm
		TagRFM,                   // 7 - rfm
		TagEnd,                   // 10 - end
	}

	if len(profile.Elements) != len(expectedTags) {
		t.Fatalf("Element count mismatch: got %d, want %d", len(profile.Elements), len(expectedTags))
	}

	for i, expected := range expectedTags {
		actual := profile.Elements[i].Tag
		if actual != expected {
			t.Errorf("Element[%d]: got tag %d (%s), want %d (%s)",
				i, actual, GetProfileElementName(actual),
				expected, GetProfileElementName(expected))
		}
	}
}

// TestRawBytesAccess tests that we can access raw element data
func TestRawBytesAccess(t *testing.T) {
	testFile := filepath.Join("testdata", "TS48_SAIP2.3_BERTLV_SUCI.der")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("Test file not found")
	}

	data, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	profile, err := DecodeProfile(data)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Print file size and element count
	t.Logf("File size: %d bytes", len(data))
	t.Logf("Elements: %d", len(profile.Elements))

	// Show raw hex of first few bytes of each element type
	for i, elem := range profile.Elements {
		if raw, ok := elem.Value.([]byte); ok && len(raw) > 0 {
			preview := raw
			if len(preview) > 20 {
				preview = preview[:20]
			}
			t.Logf("Element[%d] Tag=%d (%s): raw[%d bytes] = %s...",
				i, elem.Tag, GetProfileElementName(elem.Tag),
				len(raw), hex.EncodeToString(preview))
		}
	}
}

// =============================================================================
// ENCODER TESTS - Round-trip and encoding verification
// =============================================================================

// TestRoundTripProfile tests that encode(decode(data)) preserves key data
// Note: Full byte-level round-trip is not yet supported because encoder
// doesn't fully implement all internal structures (File, FCP, etc.)
// This test verifies that key fields are preserved after round-trip.
func TestRoundTripProfile(t *testing.T) {
	testFile := filepath.Join("testdata", "TS48_SAIP2.3_BERTLV_SUCI.der")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("Test file not found, skipping round-trip test")
	}

	// Read original file
	original, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	// Decode
	profile, err := DecodeProfile(original)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Encode back
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	// Compare sizes
	t.Logf("Original size: %d bytes", len(original))
	t.Logf("Encoded size:  %d bytes", len(encoded))
	t.Logf("Compression:   %.1f%% (encoder doesn't fully implement internal structures yet)",
		100.0*float64(len(encoded))/float64(len(original)))

	// Verify that re-decoded profile has same key fields
	t.Run("VerifyKeyFields", func(t *testing.T) {
		profile2, err := DecodeProfile(encoded)
		if err != nil {
			t.Fatalf("Failed to decode encoded data: %v", err)
		}

		// ICCID must match
		if profile.GetICCID() != profile2.GetICCID() {
			t.Errorf("ICCID mismatch: %s vs %s", profile.GetICCID(), profile2.GetICCID())
		} else {
			t.Logf("ICCID preserved: %s", profile.GetICCID())
		}

		// ProfileType must match
		if profile.GetProfileType() != profile2.GetProfileType() {
			t.Errorf("ProfileType mismatch: %s vs %s", profile.GetProfileType(), profile2.GetProfileType())
		} else {
			t.Logf("ProfileType preserved: %s", profile.GetProfileType())
		}

		// Version must match
		maj1, min1 := profile.GetVersion()
		maj2, min2 := profile2.GetVersion()
		if maj1 != maj2 || min1 != min2 {
			t.Errorf("Version mismatch: %d.%d vs %d.%d", maj1, min1, maj2, min2)
		} else {
			t.Logf("Version preserved: %d.%d", maj1, min1)
		}

		// Element count must match
		if len(profile.Elements) != len(profile2.Elements) {
			t.Errorf("Element count mismatch: %d vs %d", len(profile.Elements), len(profile2.Elements))
		} else {
			t.Logf("Element count preserved: %d", len(profile.Elements))
		}

		// All element tags must match
		for i := range profile.Elements {
			if i >= len(profile2.Elements) {
				break
			}
			if profile.Elements[i].Tag != profile2.Elements[i].Tag {
				t.Errorf("Element[%d] tag mismatch: %d vs %d",
					i, profile.Elements[i].Tag, profile2.Elements[i].Tag)
			}
		}
		t.Log("All element tags preserved")

		// Applications must match
		if profile.HasUSIM() != profile2.HasUSIM() {
			t.Error("USIM presence mismatch")
		}
		if profile.HasISIM() != profile2.HasISIM() {
			t.Error("ISIM presence mismatch")
		}
		if profile.HasCSIM() != profile2.HasCSIM() {
			t.Error("CSIM presence mismatch")
		}
		t.Logf("Applications preserved: USIM=%v, ISIM=%v, CSIM=%v",
			profile2.HasUSIM(), profile2.HasISIM(), profile2.HasCSIM())
	})

	// Test full byte-level round-trip with RawBytes preservation
	t.Run("ByteLevelComparison", func(t *testing.T) {
		if !bytes.Equal(original, encoded) {
			t.Errorf("Round-trip encoding does not match original!")
			t.Logf("Original size: %d, Encoded size: %d", len(original), len(encoded))

			// Find first difference
			minLen := len(original)
			if len(encoded) < minLen {
				minLen = len(encoded)
			}
			for i := 0; i < minLen; i++ {
				if original[i] != encoded[i] {
					t.Logf("First diff at offset 0x%04x: original=0x%02x, encoded=0x%02x", i, original[i], encoded[i])
					break
				}
			}

			// Count total differences
			differences := 0
			for i := 0; i < minLen; i++ {
				if original[i] != encoded[i] {
					differences++
				}
			}
			differences += abs(len(original) - len(encoded))
			t.Logf("Total byte differences: %d", differences)
		} else {
			t.Log("Full byte-level round-trip: PASS - encoded matches original exactly")
		}
	})

	// Element-by-element comparison
	t.Run("ElementByElementComparison", func(t *testing.T) {
		// Parse encoded data to compare elements
		profile2, err := DecodeProfile(encoded)
		if err != nil {
			t.Fatalf("Failed to decode encoded profile: %v", err)
		}

		if len(profile.Elements) != len(profile2.Elements) {
			t.Fatalf("Element count mismatch: original=%d, encoded=%d",
				len(profile.Elements), len(profile2.Elements))
		}

		mismatchCount := 0
		for i := range profile.Elements {
			elem1 := &profile.Elements[i]
			elem2 := &profile2.Elements[i]

			if !bytes.Equal(elem1.RawBytes, elem2.RawBytes) {
				mismatchCount++
				t.Logf("Element[%d] Tag=%d: RawBytes mismatch (orig=%d bytes, re-decoded=%d bytes)",
					i, elem1.Tag, len(elem1.RawBytes), len(elem2.RawBytes))
			}
		}

		if mismatchCount == 0 {
			t.Logf("All %d elements have matching RawBytes", len(profile.Elements))
		} else {
			t.Errorf("%d elements have mismatched RawBytes", mismatchCount)
		}
	})
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// TestEncodeProfileHeader tests encoding of ProfileHeader element
func TestEncodeProfileHeader(t *testing.T) {
	header := &ProfileHeader{
		MajorVersion: 2,
		MinorVersion: 3,
		ProfileType:  "Test Profile",
		ICCID:        []byte{0x89, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x41},
		MandatoryServices: &MandatoryServices{
			USIM: true,
			ISIM: true,
		},
	}

	// Create profile with just header
	profile := &Profile{
		Header: header,
		Elements: []ProfileElement{
			{Tag: TagProfileHeader, Value: header},
		},
	}

	// Encode
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	t.Logf("Encoded header: %s", hex.EncodeToString(encoded))

	// Verify we can decode it back
	decoded, err := DecodeProfile(encoded)
	if err != nil {
		t.Fatalf("Failed to decode encoded data: %v", err)
	}

	// Verify fields
	if decoded.Header == nil {
		t.Fatal("Decoded header is nil")
	}

	if decoded.Header.MajorVersion != 2 {
		t.Errorf("MajorVersion: got %d, want 2", decoded.Header.MajorVersion)
	}

	if decoded.Header.MinorVersion != 3 {
		t.Errorf("MinorVersion: got %d, want 3", decoded.Header.MinorVersion)
	}

	if decoded.Header.ProfileType != "Test Profile" {
		t.Errorf("ProfileType: got %s, want 'Test Profile'", decoded.Header.ProfileType)
	}

	if decoded.GetICCID() != "89000123456789012341" {
		t.Errorf("ICCID: got %s, want 89000123456789012341", decoded.GetICCID())
	}
}

// TestEncodeMinimalProfile tests encoding a minimal valid profile
func TestEncodeMinimalProfile(t *testing.T) {
	// Create minimal profile: header + end
	profile := &Profile{
		Header: &ProfileHeader{
			MajorVersion: 2,
			MinorVersion: 3,
			ProfileType:  "Minimal Test",
			ICCID:        []byte{0x89, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x41},
		},
		End: &EndElement{
			Header: &ElementHeader{
				Mandated:       true,
				Identification: 31,
			},
		},
		Elements: []ProfileElement{
			{Tag: TagProfileHeader, Value: nil}, // Will be filled from Header
			{Tag: TagEnd, Value: nil},           // Will be filled from End
		},
	}
	profile.Elements[0].Value = profile.Header
	profile.Elements[1].Value = profile.End

	// Encode
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	t.Logf("Encoded minimal profile (%d bytes): %s", len(encoded), hex.EncodeToString(encoded))

	// Decode back
	decoded, err := DecodeProfile(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Verify
	if decoded.Header == nil {
		t.Fatal("Header is nil")
	}
	if decoded.End == nil {
		t.Fatal("End is nil")
	}
	if decoded.GetICCID() != "89000123456789012341" {
		t.Errorf("ICCID: got %s", decoded.GetICCID())
	}
	if len(decoded.Elements) != 2 {
		t.Errorf("Element count: got %d, want 2", len(decoded.Elements))
	}
}

// TestEncodeWithPINPUK tests encoding profile with PIN/PUK codes
func TestEncodeWithPINPUK(t *testing.T) {
	profile := &Profile{
		Header: &ProfileHeader{
			MajorVersion: 2,
			MinorVersion: 3,
			ProfileType:  "PIN/PUK Test",
			ICCID:        []byte{0x89, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x41},
		},
		PukCodes: &PUKCodes{
			Header: &ElementHeader{Mandated: true, Identification: 1},
			Codes: []PUKCode{
				{KeyReference: 0x01, PUKValue: []byte("11111111"), MaxNumOfAttempsRetryNumLeft: 0xAA},
				{KeyReference: 0x81, PUKValue: []byte("22222222"), MaxNumOfAttempsRetryNumLeft: 0xAA},
			},
		},
		PinCodes: []*PINCodes{
			{
				Header: &ElementHeader{Mandated: true, Identification: 2},
				Configs: []PINConfig{
					{
						KeyReference:                0x01,
						PINValue:                    []byte{0x30, 0x30, 0x30, 0x30, 0xFF, 0xFF, 0xFF, 0xFF},
						UnblockingPINReference:      0x01,
						PINAttributes:               0x06,
						MaxNumOfAttempsRetryNumLeft: 0x33,
					},
					{
						KeyReference:                0x0A,
						PINValue:                    []byte("55555555"),
						PINAttributes:               0x03,
						MaxNumOfAttempsRetryNumLeft: 0xAA,
					},
				},
			},
		},
		End: &EndElement{
			Header: &ElementHeader{Mandated: true, Identification: 31},
		},
	}

	// Build Elements slice
	profile.Elements = []ProfileElement{
		{Tag: TagProfileHeader, Value: profile.Header},
		{Tag: TagPukCodes, Value: profile.PukCodes},
		{Tag: TagPinCodes, Value: profile.PinCodes[0]},
		{Tag: TagEnd, Value: profile.End},
	}

	// Encode
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	t.Logf("Encoded profile with PIN/PUK (%d bytes)", len(encoded))

	// Decode back
	decoded, err := DecodeProfile(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Verify PIN/PUK
	if decoded.PukCodes == nil {
		t.Fatal("PukCodes is nil")
	}
	if len(decoded.PukCodes.Codes) != 2 {
		t.Errorf("PUK count: got %d, want 2", len(decoded.PukCodes.Codes))
	}

	if len(decoded.PinCodes) == 0 {
		t.Fatal("PinCodes is empty")
	}
	if len(decoded.PinCodes[0].Configs) != 2 {
		t.Errorf("PIN config count: got %d, want 2", len(decoded.PinCodes[0].Configs))
	}

	// Check PUK1 value
	if decoded.GetPUK1() != "11111111" {
		t.Errorf("PUK1: got %s, want 11111111", decoded.GetPUK1())
	}

	// Check PIN1 value
	if decoded.GetPIN1() != "0000" {
		t.Errorf("PIN1: got %s, want 0000", decoded.GetPIN1())
	}

	// Check ADM1 value
	if decoded.GetADM1() != "55555555" {
		t.Errorf("ADM1: got %s, want 55555555", decoded.GetADM1())
	}
}

// TestEncodeAKAParameter tests encoding AKA authentication parameters
func TestEncodeAKAParameter(t *testing.T) {
	ki := make([]byte, 16)
	opc := make([]byte, 16)
	for i := 0; i < 16; i++ {
		ki[i] = byte(i)
		opc[i] = byte(i + 0x10)
	}

	profile := &Profile{
		Header: &ProfileHeader{
			MajorVersion: 2,
			MinorVersion: 3,
			ICCID:        []byte{0x89, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x41},
		},
		AKAParams: []*AKAParameter{
			{
				Header: &ElementHeader{Mandated: true, Identification: 11},
				AlgoConfig: &AlgoConfiguration{
					AlgorithmID: AlgoMilenage,
					Key:         ki,
					OPC:         opc,
				},
			},
		},
		End: &EndElement{
			Header: &ElementHeader{Mandated: true, Identification: 31},
		},
	}

	profile.Elements = []ProfileElement{
		{Tag: TagProfileHeader, Value: profile.Header},
		{Tag: TagAKAParameter, Value: profile.AKAParams[0]},
		{Tag: TagEnd, Value: profile.End},
	}

	// Encode
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	t.Logf("Encoded profile with AKA (%d bytes): %s...", len(encoded), hex.EncodeToString(encoded[:min(len(encoded), 100)]))

	// Decode back
	decoded, err := DecodeProfile(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Verify AKA
	if len(decoded.AKAParams) == 0 {
		t.Fatal("AKAParams is empty")
	}

	aka := decoded.AKAParams[0]
	if aka.AlgoConfig == nil {
		t.Fatal("AlgoConfig is nil")
	}

	if aka.AlgoConfig.AlgorithmID != AlgoMilenage {
		t.Errorf("AlgorithmID: got %d, want %d", aka.AlgoConfig.AlgorithmID, AlgoMilenage)
	}

	gotKi := hex.EncodeToString(decoded.GetKi())
	wantKi := hex.EncodeToString(ki)
	if gotKi != wantKi {
		t.Errorf("Ki: got %s, want %s", gotKi, wantKi)
	}

	gotOPc := hex.EncodeToString(decoded.GetOPC())
	wantOPc := hex.EncodeToString(opc)
	if gotOPc != wantOPc {
		t.Errorf("OPc: got %s, want %s", gotOPc, wantOPc)
	}
}

// TestSaveAndLoadProfile tests saving and loading profile to/from file
func TestSaveAndLoadProfile(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "test_profile.der")

	// Create profile
	profile := &Profile{
		Header: &ProfileHeader{
			MajorVersion: 2,
			MinorVersion: 3,
			ProfileType:  "Save/Load Test",
			ICCID:        []byte{0x89, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22},
		},
		End: &EndElement{
			Header: &ElementHeader{Mandated: true, Identification: 31},
		},
	}
	profile.Elements = []ProfileElement{
		{Tag: TagProfileHeader, Value: profile.Header},
		{Tag: TagEnd, Value: profile.End},
	}

	// Save
	err := SaveProfile(profile, testPath)
	if err != nil {
		t.Fatalf("Failed to save: %v", err)
	}

	// Check file exists
	info, err := os.Stat(testPath)
	if err != nil {
		t.Fatalf("File not created: %v", err)
	}
	t.Logf("Saved profile: %d bytes", info.Size())

	// Load
	loaded, err := LoadProfile(testPath)
	if err != nil {
		t.Fatalf("Failed to load: %v", err)
	}

	// Verify
	if loaded.GetICCID() != "89009988776655443322" {
		t.Errorf("ICCID: got %s", loaded.GetICCID())
	}

	if loaded.GetProfileType() != "Save/Load Test" {
		t.Errorf("ProfileType: got %s", loaded.GetProfileType())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
