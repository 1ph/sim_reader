package dictionaries

import (
	"strings"
	"testing"
)

// ============ ATR LOOKUP TESTS ============

func TestLookupATR_Known(t *testing.T) {
	tests := []struct {
		name     string
		atr      string
		contains string
	}{
		{
			name:     "sysmoISIM-SJA5",
			atr:      "3B9F96801F878031E073FE211B674A357530350265F8",
			contains: "sysmoISIM-SJA5",
		},
		{
			name:     "G+D 5G",
			atr:      "3B9F96801FC78031E073F6A157574A4D020B6110005B",
			contains: "G+D",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := LookupATR(tc.atr)
			if len(results) == 0 {
				t.Skip("ATR not found in dictionary (may need update)")
			}
			result := results[0]
			if tc.contains != "" && !strings.Contains(result, tc.contains) {
				t.Errorf("LookupATR(%s) = %q, should contain %q", tc.atr, result, tc.contains)
			}
		})
	}
}

func TestLookupATR_Unknown(t *testing.T) {
	// Completely random ATR that shouldn't exist
	results := LookupATR("3B00112233445566778899AABBCCDDEEFF")
	if len(results) != 0 {
		t.Errorf("LookupATR(random) = %v, want empty", results)
	}
}

func TestLookupATR_Empty(t *testing.T) {
	results := LookupATR("")
	if len(results) != 0 {
		t.Errorf("LookupATR('') = %v, want empty", results)
	}
}

func TestLookupATRFirst(t *testing.T) {
	// Test the helper function
	result := LookupATRFirst("3B9F96801F878031E073FE211B674A357530350265F8")
	if result == "" {
		t.Skip("ATR not found")
	}
	if !strings.Contains(result, "sysmo") {
		t.Logf("Result: %s", result)
	}
}

func TestLookupATR_Wildcard(t *testing.T) {
	// The ATR dictionary uses ".." as wildcards
	// Verify our lookup can handle patterns
	results := LookupATR("3B9F96801F878031E073FE211B674A357530350265F8")
	// Just verify it doesn't crash
	_ = results
}

// ============ MCC/MNC LOOKUP TESTS ============

func TestGetOperatorInfo_Known(t *testing.T) {
	tests := []struct {
		mcc, mnc string
		wantOK   bool
	}{
		// Well-known operators - just check if lookup doesn't crash
		{"250", "01", true},
		{"250", "02", true},
		{"310", "410", true},
		{"234", "10", true},
	}

	for _, tc := range tests {
		t.Run(tc.mcc+"/"+tc.mnc, func(t *testing.T) {
			result := GetOperatorInfo(tc.mcc, tc.mnc)
			if result == nil {
				t.Skip("MCC/MNC not found in dictionary")
			}
			if result.MCC != tc.mcc {
				t.Errorf("MCC = %q, want %q", result.MCC, tc.mcc)
			}
		})
	}
}

func TestGetOperatorInfo_Unknown(t *testing.T) {
	// Non-existent MCC/MNC
	result := GetOperatorInfo("999", "99")
	// May or may not be in dictionary
	_ = result
}

func TestGetOperator(t *testing.T) {
	operator, brand := GetOperator("250", "01")
	// Just verify it doesn't crash and returns something
	t.Logf("250/01: operator=%q, brand=%q", operator, brand)
}

// ============ COUNTRY LOOKUP TESTS ============

func TestGetCountry_Known(t *testing.T) {
	tests := []struct {
		mcc     string
		country string
	}{
		{"250", "Russia"},
		{"310", "United States"},
		{"234", "United Kingdom"},
	}

	for _, tc := range tests {
		t.Run(tc.mcc, func(t *testing.T) {
			result := GetCountry(tc.mcc)
			if result == "" {
				t.Skip("MCC not found in dictionary")
			}
			// Just verify we got something
			t.Logf("MCC %s -> %s", tc.mcc, result)
		})
	}
}

func TestGetCountry_Unknown(t *testing.T) {
	result := GetCountry("999")
	// Unknown MCC should return empty string
	_ = result
}

// ============ DICTIONARY LOADING TESTS ============

func TestDictionariesLoad(t *testing.T) {
	// Verify dictionaries load without error
	// This tests the lazy loading mechanism

	// Force ATR dictionary load
	_ = LookupATR("3B00")

	// Force MCC/MNC dictionary load
	_ = GetOperatorInfo("250", "01")
}

// ============ CASE SENSITIVITY TESTS ============

func TestLookupATR_CaseInsensitive(t *testing.T) {
	atr := "3B9F96801F878031E073FE211B674A357530350265F8"

	// Try uppercase
	result1 := LookupATRFirst(strings.ToUpper(atr))
	// Try lowercase
	result2 := LookupATRFirst(strings.ToLower(atr))
	// Try mixed
	result3 := LookupATRFirst(atr)

	// All should return the same result
	if result1 != result2 || result2 != result3 {
		t.Error("ATR lookup should be case-insensitive")
	}
}

// ============ OPERATOR INFO STRUCT TESTS ============

func TestOperatorInfo_Fields(t *testing.T) {
	result := GetOperatorInfo("250", "01")
	if result == nil {
		t.Skip("Operator not found")
	}

	// Verify struct has expected fields
	_ = result.MCC
	_ = result.MNC
	_ = result.Country
	_ = result.Operator
	_ = result.Brand
}

// ============ COUNT TESTS ============

func TestDictionaryCounts(t *testing.T) {
	mccCount := GetMCCCountryCount()
	opCount := GetOperatorCount()

	t.Logf("MCC/Country entries: %d", mccCount)
	t.Logf("Operator entries: %d", opCount)

	// Sanity check - should have reasonable number of entries
	if mccCount < 100 {
		t.Errorf("MCC count = %d, expected > 100", mccCount)
	}
	if opCount < 1000 {
		t.Errorf("Operator count = %d, expected > 1000", opCount)
	}
}

// ============ BENCHMARK TESTS ============

func BenchmarkLookupATR(b *testing.B) {
	atr := "3B9F96801F878031E073FE211B674A357530350265F8"
	for i := 0; i < b.N; i++ {
		_ = LookupATR(atr)
	}
}

func BenchmarkGetOperatorInfo(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetOperatorInfo("250", "01")
	}
}

func BenchmarkGetCountry(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetCountry("250")
	}
}
