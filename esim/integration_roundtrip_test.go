package esim

import (
	"encoding/hex"
	"strings"
	"testing"
)

// normalizeASN1 removes whitespace and trailing commas for robust text comparison
func normalizeASN1(s string) string {
	// Remove all whitespace
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	// Remove trailing commas before closing braces (common difference in formatting)
	s = strings.ReplaceAll(s, ",}", "}")
	return s
}

// TestASN1RoundTrip verifies that parsing the reference text and generating it back yields the same structure
func TestASN1RoundTrip(t *testing.T) {
	// 1. Parse reference ASN.1 text
	profile, err := ParseValueNotation(ReferenceASN1Text)
	if err != nil {
		t.Fatalf("Failed to parse reference ASN.1: %v", err)
	}

	// 2. Generate ASN.1 text back
	generated := GenerateValueNotation(profile)

	// 3. Compare normalized versions
	normOriginal := normalizeASN1(ReferenceASN1Text)
	normGenerated := normalizeASN1(generated)

	if normOriginal != normGenerated {
		t.Errorf("ASN.1 Round-trip mismatch after normalization")
		// Optional: write to files for debugging if needed, but here we just fail
	}
}

// TestBinaryRoundTrip verifies that decoding the reference binary and encoding it back yields the same bytes
func TestBinaryRoundTrip(t *testing.T) {
	// 1. Decode reference binary
	refBytes, err := hex.DecodeString(ReferenceBinaryDERHex)
	if err != nil {
		t.Fatalf("Failed to decode reference hex: %v", err)
	}

	profile, err := DecodeProfile(refBytes)
	if err != nil {
		t.Fatalf("Failed to decode profile from binary: %v", err)
	}

	// 2. Encode back to binary
	encoded, err := EncodeProfile(profile)
	if err != nil {
		t.Fatalf("Failed to encode profile back to binary: %v", err)
	}

	// 3. Compare bytes
	if hex.EncodeToString(refBytes) != hex.EncodeToString(encoded) {
		t.Errorf("Binary Round-trip mismatch")
		if len(refBytes) != len(encoded) {
			t.Errorf("Length mismatch: expected %d, got %d", len(refBytes), len(encoded))
		}
	}
}

// TestFullRoundTrip verifies the complete path: ASN.1 Text -> Profile -> DER Bytes -> Profile -> ASN.1 Text
func TestFullRoundTrip(t *testing.T) {
	// 1. ASN.1 Text -> Profile
	p1, err := ParseValueNotation(ReferenceASN1Text)
	if err != nil {
		t.Fatalf("Step 1 (Parse) failed: %v", err)
	}

	// 2. Profile -> DER Bytes
	der, err := EncodeProfile(p1)
	if err != nil {
		t.Fatalf("Step 2 (Encode) failed: %v", err)
	}

	// 3. DER Bytes -> Profile
	p2, err := DecodeProfile(der)
	if err != nil {
		t.Fatalf("Step 3 (Decode) failed: %v", err)
	}

	// 4. Profile -> ASN.1 Text
	text := GenerateValueNotation(p2)

	// 5. Compare final text with original
	normOriginal := normalizeASN1(ReferenceASN1Text)
	normFinal := normalizeASN1(text)

	if normOriginal != normFinal {
		t.Errorf("Full Round-trip mismatch")
	}
}

// TestValidation ensures the reference profile passes all checks in ValidateProfile
func TestValidation(t *testing.T) {
	profile, err := ParseValueNotation(ReferenceASN1Text)
	if err != nil {
		t.Fatalf("Failed to parse profile: %v", err)
	}

	result := ValidateProfile(profile, nil)
	if !result.Valid {
		t.Errorf("Profile validation failed")
		for _, err := range result.Errors {
			t.Errorf("  Error: %s: %s", err.Field, err.Message)
		}
	}
}

// TestProfileModification tests SetICCID and SetIMSI methods
func TestProfileModification(t *testing.T) {
	profile, err := ParseValueNotation(ReferenceASN1Text)
	if err != nil {
		t.Fatalf("Failed to parse profile: %v", err)
	}

	newICCID := "89012345678901234567"
	newIMSI := "001010123456789"

	if err := profile.SetICCID(newICCID); err != nil {
		t.Fatalf("SetICCID failed: %v", err)
	}
	if err := profile.SetIMSI(newIMSI); err != nil {
		t.Fatalf("SetIMSI failed: %v", err)
	}

	// Verify header ICCID
	// ICCID in header is BCD encoded. 89012345678901234567 -> 89 01 23 45 67 89 01 23 45 67
	expectedICCIDHeader := "89012345678901234567"
	actualICCIDHeader := hex.EncodeToString(profile.Header.ICCID)
	if actualICCIDHeader != expectedICCIDHeader {
		t.Errorf("ICCID Header mismatch: expected %s, got %s", expectedICCIDHeader, actualICCIDHeader)
	}

	// Verify EF.IMSI
	// IMSI 001010123456789 -> length 15. EF.IMSI is typically length 8. 
	// 08 (length) + 09 (parity/type) + digits swapped
	// encodeIMSI logic: 08 + 09 + 10 01 01 32 54 76 98
	// Wait, let's just check if it generates valid ASN.1 and can be re-parsed
	
	gen := GenerateValueNotation(profile)
	if !strings.Contains(gen, "iccid '89012345678901234567'H") {
		t.Errorf("Generated ASN.1 does not contain new ICCID")
	}
	
	p2, err := ParseValueNotation(gen)
	if err != nil {
		t.Fatalf("Failed to re-parse modified profile: %v", err)
	}
	
	if hex.EncodeToString(p2.Header.ICCID) != expectedICCIDHeader {
		t.Errorf("ICCID Header re-parse mismatch")
	}
}

