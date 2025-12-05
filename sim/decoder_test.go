package sim

import (
	"reflect"
	"testing"
)

// TestCard represents a test case from a real SIM card
type TestCard struct {
	Name        string
	ATR         string
	CardType    string
	RawICCID    []byte
	ICCID       string
	RawIMSI     []byte
	IMSI        string
	RawSPN      []byte
	SPN         string
	RawAD       []byte
	MNCLength   int
	RawUST      []byte
	USTServices []int // List of enabled services
	RawHPLMN    []byte
	HPLMN       []PLMNwACT
	RawFPLMN    []byte
	FPLMN       []string
}

// Real test data from commercial SIM cards
// ============================================================================
// HOW TO ADD YOUR CARD DATA:
// 1. Run: ./sim_reader -adm YOUR_KEY -raw -analyze
// 2. Copy raw hex values from output
// 3. Add TestCard entry with raw bytes AND expected decoded values
// ============================================================================
var testCards = []TestCard{
	// === ATR identification tests (no raw data needed) ===
	// Note: CardType values must match the embedded smartcard_list.txt dictionary
	// Source: https://pcsc-tools.apdu.fr/smartcard_list.txt
	{
		Name:     "G+D Mobile Security 5G",
		ATR:      "3B9F96801FC78031E073F6A157574A4D020B6110005B",
		CardType: "G+D Mobile Security for private 5G USIM (Telecommunication)",
	},

	// ============================================================================
	// VERIFIED CARD DATA FROM REAL CARDS
	// ============================================================================

	// NovaCard - dumped 2025-11-27
	// Note: This specific ATR is not in the standard smartcard_list.txt
	{
		Name:        "NovaCard",
		ATR:         "3B9F96803FC7008031E073FE2113676FA5021B0000012A",
		CardType:    "Unknown card type",
		RawICCID:    []byte{0x98, 0x07, 0x81, 0x08, 0x00, 0x00, 0x00, 0x00, 0x10, 0x67},
		ICCID:       "89701880000000000176",
		RawIMSI:     []byte{0x08, 0x29, 0x05, 0x88, 0x00, 0x00, 0x00, 0x00, 0x71},
		IMSI:        "250880000000017",
		RawSPN:      []byte{0x01, 0x53, 0x55, 0x50, 0x45, 0x52, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		SPN:         "SUPER",
		RawAD:       []byte{0x00, 0x00, 0x01, 0x02},
		MNCLength:   2,
		RawUST:      []byte{0x1E, 0xFA, 0x1C, 0x1C, 0x23, 0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00},
		USTServices: []int{2, 3, 4, 5, 10, 12, 13, 14, 15, 16, 19, 20, 21, 27, 28, 29, 33, 34, 38, 42, 43, 85},
		RawHPLMN:    []byte{0x52, 0xF0, 0x88, 0x40, 0x00, 0x52, 0xF0, 0x88, 0x80, 0x00, 0x52, 0xF0, 0x88, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00},
		HPLMN: []PLMNwACT{
			{MCC: "250", MNC: "88", ACT: 0x4000, Tech: []string{"E-UTRAN"}},
			{MCC: "250", MNC: "88", ACT: 0x8000, Tech: []string{"UTRAN"}},
			{MCC: "250", MNC: "88", ACT: 0x0080, Tech: []string{"GSM"}},
		},
		RawFPLMN: []byte{0x52, 0xF0, 0x02, 0x52, 0xF0, 0x10, 0x52, 0xF0, 0x20, 0x52, 0xF0, 0x99},
		FPLMN:    []string{"25020", "25001", "25002", "25099"},
	},

	// Sysmocom sysmoISIM-SJA5 - dumped 2025-11-27
	// CardType from smartcard_list.txt: https://pcsc-tools.apdu.fr/smartcard_list.txt
	{
		Name:        "Sysmocom SJA5",
		ATR:         "3B9F96801F878031E073FE211B674A357530350265F8",
		CardType:    "sysmoISIM-SJA5 (Telecommunication)",
		RawICCID:    []byte{0x98, 0x94, 0x44, 0x00, 0x00, 0x00, 0x11, 0x57, 0x01, 0xF6},
		ICCID:       "8949440000001175106",
		RawIMSI:     []byte{0x08, 0x29, 0x05, 0x88, 0x00, 0x00, 0x00, 0x00, 0x30},
		IMSI:        "250880000000003",
		RawSPN:      []byte{0x03, 0x53, 0x55, 0x50, 0x45, 0x52, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		SPN:         "SUPER",
		RawAD:       []byte{0x01, 0x00, 0x08, 0x02, 0xFF},
		MNCLength:   2,
		RawUST:      []byte{0xBE, 0xFF, 0x9F, 0x9D, 0xE7, 0x3E, 0x04, 0x08, 0x00, 0x00, 0xFF, 0x33, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00},
		USTServices: []int{2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 24, 25, 27, 28, 29, 32, 33, 34, 35, 38, 39, 40, 42, 43, 44, 45, 46, 51, 60, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 93, 94, 122, 123},
		RawHPLMN:    []byte{0x52, 0xF0, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00},
		HPLMN: []PLMNwACT{
			{MCC: "250", MNC: "88", ACT: 0xFFFF, Tech: []string{"UTRAN", "E-UTRAN", "GSM", "GSM COMPACT", "cdma2000 HRPD", "cdma2000 1xRTT", "NR", "NG-RAN"}},
		},
		RawFPLMN: []byte{0x52, 0xF0, 0x02, 0x52, 0xF0, 0x99, 0x52, 0xF0, 0x20, 0x52, 0xF0, 0x10},
		FPLMN:    []string{"25020", "25099", "25002", "25001"},
	},
}

// ============ DECODER TESTS ============

func TestDecodeICCID(t *testing.T) {
	for _, tc := range testCards {
		if tc.RawICCID == nil {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			got := DecodeICCID(tc.RawICCID)
			if got != tc.ICCID {
				t.Errorf("DecodeICCID() = %q, want %q", got, tc.ICCID)
			}
		})
	}
}

func TestDecodeIMSI(t *testing.T) {
	for _, tc := range testCards {
		if tc.RawIMSI == nil {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			got := DecodeIMSI(tc.RawIMSI)
			if got != tc.IMSI {
				t.Errorf("DecodeIMSI() = %q, want %q", got, tc.IMSI)
			}
		})
	}
}

func TestDecodeSPN(t *testing.T) {
	for _, tc := range testCards {
		if tc.RawSPN == nil {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			got := DecodeSPN(tc.RawSPN)
			if got != tc.SPN {
				t.Errorf("DecodeSPN() = %q, want %q", got, tc.SPN)
			}
		})
	}
}

func TestDecodeAD(t *testing.T) {
	for _, tc := range testCards {
		if tc.RawAD == nil {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			got := DecodeAD(tc.RawAD)
			if got.MNCLength != tc.MNCLength {
				t.Errorf("DecodeAD().MNCLength = %d, want %d", got.MNCLength, tc.MNCLength)
			}
		})
	}
}

func TestDecodeFPLMN(t *testing.T) {
	for _, tc := range testCards {
		if tc.RawFPLMN == nil {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			got := DecodePLMNList(tc.RawFPLMN)
			if !reflect.DeepEqual(got, tc.FPLMN) {
				t.Errorf("DecodePLMNList() = %v, want %v", got, tc.FPLMN)
			}
		})
	}
}

func TestDecodePLMNwACT(t *testing.T) {
	for _, tc := range testCards {
		if tc.RawHPLMN == nil {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			got := DecodePLMNwACT(tc.RawHPLMN)
			if len(got) != len(tc.HPLMN) {
				t.Errorf("DecodePLMNwACT() got %d entries, want %d", len(got), len(tc.HPLMN))
				return
			}
			for i, g := range got {
				if g.MCC != tc.HPLMN[i].MCC || g.MNC != tc.HPLMN[i].MNC {
					t.Errorf("DecodePLMNwACT()[%d] = %s/%s, want %s/%s",
						i, g.MCC, g.MNC, tc.HPLMN[i].MCC, tc.HPLMN[i].MNC)
				}
			}
		})
	}
}

// ============ ATR IDENTIFICATION TESTS ============

func TestIdentifyCardByATR(t *testing.T) {
	for _, tc := range testCards {
		if tc.ATR == "" {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			got := IdentifyCardByATR(tc.ATR)
			if got != tc.CardType {
				t.Errorf("IdentifyCardByATR(%s) = %q, want %q", tc.ATR, got, tc.CardType)
			}
		})
	}
}

// ============ ENCODER TESTS ============

func TestEncodeIMSI(t *testing.T) {
	for _, tc := range testCards {
		if tc.IMSI == "" || tc.RawIMSI == nil {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			got, err := EncodeIMSI(tc.IMSI)
			if err != nil {
				t.Errorf("EncodeIMSI() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tc.RawIMSI) {
				t.Errorf("EncodeIMSI(%s) = %X, want %X", tc.IMSI, got, tc.RawIMSI)
			}
		})
	}
}

func TestEncodePLMN(t *testing.T) {
	// PLMN encoding: MCC2|MCC1, MNC3|MCC3, MNC2|MNC1
	// For 2-digit MNC, MNC3 = F
	tests := []struct {
		mcc, mnc string
		want     []byte
	}{
		{"250", "88", []byte{0x52, 0xF0, 0x88}},  // MCC=250, MNC=88 (2-digit)
		{"250", "02", []byte{0x52, 0xF0, 0x20}},  // MCC=250, MNC=02 (2-digit)
		{"310", "410", []byte{0x13, 0x00, 0x14}}, // MCC=310, MNC=410 (3-digit)
		{"001", "01", []byte{0x00, 0xF1, 0x10}},  // MCC=001, MNC=01 (2-digit)
	}

	for _, tc := range tests {
		t.Run(tc.mcc+"/"+tc.mnc, func(t *testing.T) {
			got, err := EncodePLMN(tc.mcc, tc.mnc)
			if err != nil {
				t.Errorf("EncodePLMN() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("EncodePLMN(%s, %s) = %X, want %X", tc.mcc, tc.mnc, got, tc.want)
			}
		})
	}
}

// ============ ROUNDTRIP TESTS ============

func TestIMSIRoundtrip(t *testing.T) {
	imsis := []string{
		"250880000000017",
		"250026931721000",
		"310410123456789",
		"001010000000001",
	}

	for _, imsi := range imsis {
		t.Run(imsi, func(t *testing.T) {
			encoded, err := EncodeIMSI(imsi)
			if err != nil {
				t.Errorf("EncodeIMSI() error = %v", err)
				return
			}
			decoded := DecodeIMSI(encoded)
			if decoded != imsi {
				t.Errorf("Roundtrip failed: %s -> %X -> %s", imsi, encoded, decoded)
			}
		})
	}
}

func TestPLMNRoundtrip(t *testing.T) {
	plmns := []struct {
		mcc, mnc string
	}{
		{"250", "88"},
		{"250", "02"},
		{"310", "410"},
		{"001", "01"},
	}

	for _, p := range plmns {
		t.Run(p.mcc+"/"+p.mnc, func(t *testing.T) {
			encoded, err := EncodePLMN(p.mcc, p.mnc)
			if err != nil {
				t.Errorf("EncodePLMN() error = %v", err)
				return
			}
			gotMCC, gotMNC := DecodePLMN(encoded)
			if gotMCC != p.mcc || gotMNC != p.mnc {
				t.Errorf("Roundtrip failed: %s/%s -> %X -> %s/%s",
					p.mcc, p.mnc, encoded, gotMCC, gotMNC)
			}
		})
	}
}

// ============ HPLMN PARSING TESTS ============

func TestParseHPLMNString(t *testing.T) {
	tests := []struct {
		input   string
		wantMCC string
		wantMNC string
		wantACT uint16
		wantErr bool
	}{
		{"250:88:eutran", "250", "88", ACT_E_UTRAN, false},
		{"250:88:eutran,utran,gsm", "250", "88", ACT_E_UTRAN | ACT_UTRAN | ACT_GSM, false},
		{"250:88:all", "250", "88", ACT_ALL, false},
		{"250:88", "250", "88", ACT_ALL, false}, // Default to all
		{"invalid", "", "", 0, true},
		{"25:88:gsm", "", "", 0, true}, // Invalid MCC
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			mcc, mnc, act, err := ParseHPLMNString(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ParseHPLMNString() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr {
				if mcc != tc.wantMCC || mnc != tc.wantMNC || act != tc.wantACT {
					t.Errorf("ParseHPLMNString(%s) = (%s, %s, %04X), want (%s, %s, %04X)",
						tc.input, mcc, mnc, act, tc.wantMCC, tc.wantMNC, tc.wantACT)
				}
			}
		})
	}
}
