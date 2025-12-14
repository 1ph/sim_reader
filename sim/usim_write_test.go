package sim

import (
	"testing"
)

// ============ HPLMN PARSING TESTS ============

func TestParseHPLMNString_Valid(t *testing.T) {
	tests := []struct {
		input   string
		wantMCC string
		wantMNC string
		wantACT uint16
	}{
		// Single technology
		{"250:88:eutran", "250", "88", ACT_E_UTRAN},
		{"250:88:utran", "250", "88", ACT_UTRAN},
		{"250:88:gsm", "250", "88", ACT_GSM},
		{"250:88:nr", "250", "88", ACT_NR},
		{"250:88:ngran", "250", "88", ACT_NG_RAN},

		// Multiple technologies
		{"250:88:eutran,utran", "250", "88", ACT_E_UTRAN | ACT_UTRAN},
		{"250:88:eutran,utran,gsm", "250", "88", ACT_E_UTRAN | ACT_UTRAN | ACT_GSM},
		{"250:88:all", "250", "88", ACT_ALL},

		// Without ACT (defaults to all)
		{"250:88", "250", "88", ACT_ALL},
		{"250:88:", "250", "88", ACT_ALL},

		// 3-digit MNC
		{"310:410:eutran", "310", "410", ACT_E_UTRAN},

		// Alternative names
		{"250:88:lte", "250", "88", ACT_E_UTRAN},
		{"250:88:4g", "250", "88", ACT_E_UTRAN},
		{"250:88:3g", "250", "88", ACT_UTRAN},
		{"250:88:2g", "250", "88", ACT_GSM},
		{"250:88:5g", "250", "88", ACT_NR},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			mcc, mnc, act, err := ParseHPLMNString(tc.input)
			if err != nil {
				t.Fatalf("ParseHPLMNString() error = %v", err)
			}
			if mcc != tc.wantMCC {
				t.Errorf("MCC = %q, want %q", mcc, tc.wantMCC)
			}
			if mnc != tc.wantMNC {
				t.Errorf("MNC = %q, want %q", mnc, tc.wantMNC)
			}
			if act != tc.wantACT {
				t.Errorf("ACT = %04X, want %04X", act, tc.wantACT)
			}
		})
	}
}

func TestParseHPLMNString_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"Empty", ""},
		{"No separator", "25088"},
		{"Single part", "250"},
		{"Invalid MCC length", "25:88:gsm"},
		{"Invalid MCC 4 digits", "2500:88:gsm"},
		{"Invalid MNC single digit", "250:8:gsm"},
		{"Invalid MNC 4 digits", "250:8888:gsm"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ParseHPLMNString(tc.input)
			if err == nil {
				t.Errorf("ParseHPLMNString(%q) should return error", tc.input)
			}
		})
	}
}

// ============ ACT PARSING TESTS ============

func TestParseACTString(t *testing.T) {
	tests := []struct {
		input string
		want  uint16
	}{
		// Single values
		{"eutran", ACT_E_UTRAN},
		{"e-utran", ACT_E_UTRAN},
		{"lte", ACT_E_UTRAN},
		{"4g", ACT_E_UTRAN},
		{"utran", ACT_UTRAN},
		{"umts", ACT_UTRAN},
		{"3g", ACT_UTRAN},
		{"gsm", ACT_GSM},
		{"2g", ACT_GSM},
		{"nr", ACT_NR},
		{"5g", ACT_NR},
		{"ngran", ACT_NG_RAN},
		{"ng-ran", ACT_NG_RAN},
		{"5gsa", ACT_NG_RAN},
		{"all", ACT_ALL},

		// Combinations
		{"eutran,utran", ACT_E_UTRAN | ACT_UTRAN},
		{"eutran,utran,gsm", ACT_E_UTRAN | ACT_UTRAN | ACT_GSM},
		{"lte,3g,2g", ACT_E_UTRAN | ACT_UTRAN | ACT_GSM},
		{"nr,ngran", ACT_NR | ACT_NG_RAN},

		// With spaces
		{"eutran, utran, gsm", ACT_E_UTRAN | ACT_UTRAN | ACT_GSM},

		// Case insensitive
		{"EUTRAN", ACT_E_UTRAN},
		{"EuTrAn", ACT_E_UTRAN},

		// Unknown (returns 0)
		{"unknown", 0},
		{"", 0},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ParseACTString(tc.input)
			if got != tc.want {
				t.Errorf("ParseACTString(%q) = %04X, want %04X", tc.input, got, tc.want)
			}
		})
	}
}

// ============ OPERATION MODE TESTS ============

func TestParseOperationMode_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  byte
	}{
		{"normal", OP_MODE_NORMAL},
		{"Normal", OP_MODE_NORMAL},
		{"NORMAL", OP_MODE_NORMAL},
		{"0", OP_MODE_NORMAL},
		{"0x00", OP_MODE_NORMAL},

		{"type-approval", OP_MODE_TYPE_APPROVAL},
		{"typeapproval", OP_MODE_TYPE_APPROVAL},
		{"approval", OP_MODE_TYPE_APPROVAL},
		{"1", OP_MODE_TYPE_APPROVAL},
		{"0x01", OP_MODE_TYPE_APPROVAL},

		{"normal-specific", OP_MODE_NORMAL_SPECIFIC},
		{"normalspecific", OP_MODE_NORMAL_SPECIFIC},
		{"2", OP_MODE_NORMAL_SPECIFIC},
		{"0x02", OP_MODE_NORMAL_SPECIFIC},

		{"type-approval-specific", OP_MODE_TYPE_APPROVAL_SPECIFIC},
		{"typeapprovalspecific", OP_MODE_TYPE_APPROVAL_SPECIFIC},
		{"4", OP_MODE_TYPE_APPROVAL_SPECIFIC},
		{"0x04", OP_MODE_TYPE_APPROVAL_SPECIFIC},

		{"maintenance", OP_MODE_MAINTENANCE},
		{"offline", OP_MODE_MAINTENANCE},
		{"8", OP_MODE_MAINTENANCE},
		{"0x08", OP_MODE_MAINTENANCE},

		{"cell-test", OP_MODE_CELL_TEST},
		{"celltest", OP_MODE_CELL_TEST},
		{"test", OP_MODE_CELL_TEST},
		{"128", OP_MODE_CELL_TEST},
		{"0x80", OP_MODE_CELL_TEST},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseOperationMode(tc.input)
			if err != nil {
				t.Fatalf("ParseOperationMode() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("ParseOperationMode(%q) = %02X, want %02X", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseOperationMode_Invalid(t *testing.T) {
	tests := []string{
		"invalid",
		"random",
		"256",
		"0x100",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := ParseOperationMode(input)
			if err == nil {
				t.Errorf("ParseOperationMode(%q) should return error", input)
			}
		})
	}
}

// ============ ACT CONSTANTS TESTS ============

func TestACTConstants(t *testing.T) {
	// Verify ACT constants match 3GPP TS 31.102
	if ACT_UTRAN != 0x8000 {
		t.Errorf("ACT_UTRAN = %04X, want 0x8000", ACT_UTRAN)
	}
	if ACT_E_UTRAN != 0x4000 {
		t.Errorf("ACT_E_UTRAN = %04X, want 0x4000", ACT_E_UTRAN)
	}
	if ACT_GSM != 0x0080 {
		t.Errorf("ACT_GSM = %04X, want 0x0080", ACT_GSM)
	}
}

// ============ OPERATION MODE CONSTANTS TESTS ============

func TestOperationModeConstants(t *testing.T) {
	// Verify constants match 3GPP TS 31.102
	if OP_MODE_NORMAL != 0x00 {
		t.Errorf("OP_MODE_NORMAL = %02X, want 0x00", OP_MODE_NORMAL)
	}
	if OP_MODE_TYPE_APPROVAL != 0x01 {
		t.Errorf("OP_MODE_TYPE_APPROVAL = %02X, want 0x01", OP_MODE_TYPE_APPROVAL)
	}
	if OP_MODE_CELL_TEST != 0x80 {
		t.Errorf("OP_MODE_CELL_TEST = %02X, want 0x80", OP_MODE_CELL_TEST)
	}
}

// ============ HELPER FUNCTION TESTS ============

func TestSplitString(t *testing.T) {
	tests := []struct {
		input string
		sep   byte
		want  []string
	}{
		{"a:b:c", ':', []string{"a", "b", "c"}},
		{"a,b,c", ',', []string{"a", "b", "c"}},
		{"single", ':', []string{"single"}},
		{"", ':', []string{""}},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := splitString(tc.input, tc.sep)
			if len(got) != len(tc.want) {
				t.Errorf("splitString() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"  hello  ", "hello"},
		{"\thello\t", "hello"},
		{"hello", "hello"},
		{"", ""},
		{"   ", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := trimSpace(tc.input)
			if got != tc.want {
				t.Errorf("trimSpace(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"HELLO", "hello"},
		{"Hello", "hello"},
		{"hello", "hello"},
		{"HeLLo WoRLd", "hello world"},
		{"123ABC", "123abc"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := toLower(tc.input)
			if got != tc.want {
				t.Errorf("toLower(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
