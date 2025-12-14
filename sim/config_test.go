package sim

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// ============ JSON CONFIG SERIALIZATION TESTS ============

func TestSIMConfig_JSONRoundtrip(t *testing.T) {
	boolTrue := true
	boolFalse := false

	original := &SIMConfig{
		ICCID:         "89701880000000000176",
		MSISDN:        "+79001234567",
		IMSI:          "250880000000017",
		SPN:           "Test Operator",
		MCC:           "250",
		MNC:           "88",
		OperationMode: "normal",
		Languages:     []string{"en", "ru"},
		ACC:           []int{0, 5, 10},
		HPLMNPeriod:   60,
		HPLMN: []HPLMNConfig{
			{MCC: "250", MNC: "88", ACT: []string{"eutran", "utran", "gsm"}},
		},
		OPLMN: []HPLMNConfig{
			{MCC: "250", MNC: "02", ACT: []string{"eutran"}},
		},
		UserPLMN: []HPLMNConfig{
			{MCC: "001", MNC: "01", ACT: []string{"eutran", "utran", "gsm"}},
		},
		FPLMN:      []string{"25099", "25020"},
		ClearFPLMN: true,
		ISIM: &ISIMConfig{
			IMPI:   "250880000000017@ims.mnc088.mcc250.3gppnetwork.org",
			IMPU:   []string{"sip:250880000000017@ims.mnc088.mcc250.3gppnetwork.org"},
			Domain: "ims.mnc088.mcc250.3gppnetwork.org",
			PCSCF:  []string{"pcscf.ims.mnc088.mcc250.3gppnetwork.org"},
		},
		Services: &ServicesConfig{
			VoLTE:               &boolTrue,
			VoWiFi:              &boolTrue,
			SMSOverIP:           &boolTrue,
			GSMAccess:           &boolTrue,
			CallControl:         &boolFalse,
			GBA:                 &boolTrue,
			NAS5GConfig:         &boolFalse,
			NSSAI5G:             &boolFalse,
			SUCICalc:            &boolTrue,
			ISIMPcscf:           &boolTrue,
			ISIMSmsOverIP:       &boolTrue,
			ISIMVoiceDomainPref: &boolTrue,
			ISIMGBA:             &boolTrue,
			ISIMHttpDigest:      &boolFalse,
		},
	}

	// Serialize to JSON
	jsonData, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	t.Logf("JSON output:\n%s", string(jsonData))

	// Deserialize back
	var restored SIMConfig
	if err := json.Unmarshal(jsonData, &restored); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Compare
	if !reflect.DeepEqual(original.IMSI, restored.IMSI) {
		t.Errorf("IMSI mismatch: got %q, want %q", restored.IMSI, original.IMSI)
	}
	if !reflect.DeepEqual(original.SPN, restored.SPN) {
		t.Errorf("SPN mismatch: got %q, want %q", restored.SPN, original.SPN)
	}
	if !reflect.DeepEqual(original.HPLMN, restored.HPLMN) {
		t.Errorf("HPLMN mismatch: got %+v, want %+v", restored.HPLMN, original.HPLMN)
	}
	if !reflect.DeepEqual(original.ISIM, restored.ISIM) {
		t.Errorf("ISIM mismatch: got %+v, want %+v", restored.ISIM, original.ISIM)
	}
}

func TestSIMConfig_LoadSave(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.json")

	boolTrue := true
	original := &SIMConfig{
		IMSI:          "250880000000001",
		SPN:           "TestOp",
		OperationMode: "cell-test",
		HPLMN: []HPLMNConfig{
			{MCC: "250", MNC: "88", ACT: []string{"eutran"}},
		},
		Services: &ServicesConfig{
			VoLTE: &boolTrue,
		},
	}

	// Save
	if err := SaveConfig(configPath, original); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("Config file was not created")
	}

	// Load
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Compare
	if loaded.IMSI != original.IMSI {
		t.Errorf("IMSI = %q, want %q", loaded.IMSI, original.IMSI)
	}
	if loaded.SPN != original.SPN {
		t.Errorf("SPN = %q, want %q", loaded.SPN, original.SPN)
	}
	if loaded.OperationMode != original.OperationMode {
		t.Errorf("OperationMode = %q, want %q", loaded.OperationMode, original.OperationMode)
	}
}

func TestSIMConfig_LoadNonExistent(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestSIMConfig_LoadInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.json")

	// Write invalid JSON
	if err := os.WriteFile(configPath, []byte("{ invalid json }"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// ============ HPLMN CONFIG TESTS ============

func TestHPLMNConfig_ACTStrings(t *testing.T) {
	config := HPLMNConfig{
		MCC: "250",
		MNC: "88",
		ACT: []string{"eutran", "utran", "gsm"},
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	var restored HPLMNConfig
	if err := json.Unmarshal(jsonData, &restored); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(config.ACT, restored.ACT) {
		t.Errorf("ACT = %v, want %v", restored.ACT, config.ACT)
	}
}

// ============ SERVICES CONFIG TESTS ============

func TestServicesConfig_NilValues(t *testing.T) {
	// Test that nil service values don't cause issues
	config := &ServicesConfig{
		VoLTE: nil, // Not specified
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	var restored ServicesConfig
	if err := json.Unmarshal(jsonData, &restored); err != nil {
		t.Fatal(err)
	}

	if restored.VoLTE != nil {
		t.Error("VoLTE should be nil when not specified")
	}
}

// ============ EXPORT TO CONFIG TESTS ============

func TestExportToConfig_Empty(t *testing.T) {
	// Test with nil data
	config := ExportToConfig(nil, nil)
	if config == nil {
		t.Fatal("ExportToConfig should return non-nil config")
	}
}

func TestExportToConfig_USIMOnly(t *testing.T) {
	usimData := &USIMData{
		ICCID:  "89701880000000000176",
		IMSI:   "250880000000017",
		MSISDN: "+79001234567",
		SPN:    "TestOp",
		MCC:    "250",
		MNC:    "88",
		AdminData: AdminData{
			UEMode: "Normal",
		},
		UST: map[int]bool{
			27:  true, // GSM Access
			87:  true, // VoLTE
			89:  true, // ePDG
			90:  true, // ePDG PLMN
			124: true, // WLAN
		},
	}

	config := ExportToConfig(usimData, nil)

	if config.ICCID != usimData.ICCID {
		t.Errorf("ICCID = %q, want %q", config.ICCID, usimData.ICCID)
	}
	if config.IMSI != usimData.IMSI {
		t.Errorf("IMSI = %q, want %q", config.IMSI, usimData.IMSI)
	}
	if config.OperationMode != "normal" {
		t.Errorf("OperationMode = %q, want %q", config.OperationMode, "normal")
	}
	if config.Services == nil {
		t.Fatal("Services should not be nil")
	}
	if config.Services.GSMAccess == nil || !*config.Services.GSMAccess {
		t.Error("GSMAccess should be true")
	}
}

func TestExportToConfig_WithISIM(t *testing.T) {
	usimData := &USIMData{
		IMSI: "250880000000017",
		UST:  map[int]bool{},
	}

	isimData := &ISIMData{
		Available: true,
		IMPI:      "250880000000017@ims.mnc088.mcc250.3gppnetwork.org",
		IMPU:      []string{"sip:250880000000017@ims.mnc088.mcc250.3gppnetwork.org"},
		Domain:    "ims.mnc088.mcc250.3gppnetwork.org",
		PCSCF:     []string{"pcscf.example.com"},
		IST:       map[int]bool{1: true, 7: true, 12: true},
	}

	config := ExportToConfig(usimData, isimData)

	if config.ISIM == nil {
		t.Fatal("ISIM config should not be nil")
	}
	if config.ISIM.IMPI != isimData.IMPI {
		t.Errorf("IMPI = %q, want %q", config.ISIM.IMPI, isimData.IMPI)
	}
	if len(config.ISIM.IMPU) != 1 {
		t.Errorf("IMPU count = %d, want 1", len(config.ISIM.IMPU))
	}
}

// ============ PLMN ACT TO STRINGS TESTS ============

func TestPlmnActToStrings(t *testing.T) {
	tests := []struct {
		act  uint16
		want []string
	}{
		{0x8000, []string{"utran"}},
		{0x4000, []string{"eutran"}},
		{0x0080, []string{"gsm"}},
		{0x0800, []string{"nr"}},
		{0x0400, []string{"ngran"}},
		{0xC080, []string{"utran", "eutran", "gsm"}},
		{0xCC80, []string{"utran", "eutran", "gsm", "nr", "ngran"}},
		{0x0000, nil},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			got := plmnActToStrings(tc.act)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("plmnActToStrings(0x%04X) = %v, want %v", tc.act, got, tc.want)
			}
		})
	}
}

// ============ OPERATION MODE TESTS ============

func TestOperationModeMapping(t *testing.T) {
	tests := []struct {
		ueMode string
		want   string
	}{
		{"Normal", "normal"},
		{"Type Approval", "type-approval"},
		{"Normal + specific facilities", "normal-specific"},
		{"Type Approval + specific facilities", "type-approval-specific"},
		{"Maintenance (off-line)", "maintenance"},
		{"Cell Test", "cell-test"},
	}

	for _, tc := range tests {
		t.Run(tc.ueMode, func(t *testing.T) {
			usimData := &USIMData{
				AdminData: AdminData{UEMode: tc.ueMode},
				UST:       map[int]bool{},
			}
			config := ExportToConfig(usimData, nil)
			if config.OperationMode != tc.want {
				t.Errorf("OperationMode = %q, want %q", config.OperationMode, tc.want)
			}
		})
	}
}
