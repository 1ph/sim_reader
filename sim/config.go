package sim

import (
	"encoding/json"
	"fmt"
	"os"
	"sim_reader/card"
)

// SIMConfig represents the configuration for writing to a SIM card
type SIMConfig struct {
	// USIM parameters
	IMSI string `json:"imsi,omitempty"`
	SPN  string `json:"spn,omitempty"`
	MCC  string `json:"mcc,omitempty"`
	MNC  string `json:"mnc,omitempty"`

	// HPLMN configuration
	HPLMN []HPLMNConfig `json:"hplmn,omitempty"`

	// ISIM parameters
	ISIM *ISIMConfig `json:"isim,omitempty"`

	// Services
	Services *ServicesConfig `json:"services,omitempty"`

	// PLMN options
	ClearFPLMN bool `json:"clear_fplmn,omitempty"`
}

// HPLMNConfig represents HPLMN entry configuration
type HPLMNConfig struct {
	MCC string   `json:"mcc"`
	MNC string   `json:"mnc"`
	ACT []string `json:"act"` // e.g., ["eutran", "utran", "gsm"]
}

// ISIMConfig represents ISIM-specific configuration
type ISIMConfig struct {
	IMPI   string   `json:"impi,omitempty"`
	IMPU   []string `json:"impu,omitempty"`
	Domain string   `json:"domain,omitempty"`
	PCSCF  []string `json:"pcscf,omitempty"`
}

// ServicesConfig represents service enable/disable flags
type ServicesConfig struct {
	// USIM services
	VoLTE       *bool `json:"volte,omitempty"`
	VoWiFi      *bool `json:"vowifi,omitempty"`
	SMSOverIP   *bool `json:"sms_over_ip,omitempty"`
	GSMAccess   *bool `json:"gsm_access,omitempty"`
	CallControl *bool `json:"call_control,omitempty"`
	GBA         *bool `json:"gba,omitempty"`
	NAS5GConfig *bool `json:"5g_nas_config,omitempty"`
	NSSAI5G     *bool `json:"5g_nssai,omitempty"`
	SUCICalc    *bool `json:"suci_calculation,omitempty"`

	// ISIM services
	ISIMPcscf           *bool `json:"isim_pcscf,omitempty"`
	ISIMSmsOverIP       *bool `json:"isim_sms_over_ip,omitempty"`
	ISIMVoiceDomainPref *bool `json:"isim_voice_domain_pref,omitempty"`
	ISIMGBA             *bool `json:"isim_gba,omitempty"`
	ISIMHttpDigest      *bool `json:"isim_http_digest,omitempty"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(filename string) (*SIMConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config SIMConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to a JSON file
func SaveConfig(filename string, config *SIMConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// ApplyConfig applies the configuration to the SIM card
func ApplyConfig(reader *card.Reader, config *SIMConfig) error {
	var errors []string

	// Write IMSI
	if config.IMSI != "" {
		if err := WriteIMSI(reader, config.IMSI); err != nil {
			errors = append(errors, fmt.Sprintf("IMSI: %v", err))
		} else {
			fmt.Println("✓ IMSI written successfully")
		}
	}

	// Write SPN
	if config.SPN != "" {
		if err := WriteSPN(reader, config.SPN, 0x00); err != nil {
			errors = append(errors, fmt.Sprintf("SPN: %v", err))
		} else {
			fmt.Println("✓ SPN written successfully")
		}
	}

	// Update MNC length if MNC is specified
	if config.MNC != "" {
		mncLen := len(config.MNC)
		if mncLen >= 2 && mncLen <= 3 {
			if err := UpdateMNCLength(reader, mncLen); err != nil {
				errors = append(errors, fmt.Sprintf("MNC length: %v", err))
			} else {
				fmt.Printf("✓ MNC length set to %d\n", mncLen)
			}
		}
	}

	// Clear FPLMN
	if config.ClearFPLMN {
		if err := ClearForbiddenPLMN(reader); err != nil {
			errors = append(errors, fmt.Sprintf("Clear FPLMN: %v", err))
		} else {
			fmt.Println("✓ Forbidden PLMN list cleared")
		}
	}

	// Write HPLMN
	if len(config.HPLMN) > 0 {
		entries := make([]HPLMNEntry, 0, len(config.HPLMN))
		for _, h := range config.HPLMN {
			actStr := ""
			for i, a := range h.ACT {
				if i > 0 {
					actStr += ","
				}
				actStr += a
			}
			act := ParseACTString(actStr)
			entries = append(entries, HPLMNEntry{
				MCC: h.MCC,
				MNC: h.MNC,
				ACT: act,
			})
		}
		if err := WriteHPLMNList(reader, entries); err != nil {
			errors = append(errors, fmt.Sprintf("HPLMN: %v", err))
		} else {
			fmt.Printf("✓ HPLMN written (%d entries)\n", len(entries))
		}
	}

	// Apply USIM services
	if config.Services != nil {
		if err := applyUSIMServices(reader, config.Services); err != nil {
			errors = append(errors, fmt.Sprintf("USIM services: %v", err))
		}
	}

	// Apply ISIM parameters
	if config.ISIM != nil {
		if err := applyISIMConfig(reader, config.ISIM); err != nil {
			errors = append(errors, fmt.Sprintf("ISIM: %v", err))
		}

		// Apply ISIM services
		if config.Services != nil {
			if err := applyISIMServices(reader, config.Services); err != nil {
				errors = append(errors, fmt.Sprintf("ISIM services: %v", err))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("some operations failed:\n  - %s",
			joinErrors(errors))
	}

	return nil
}

func applyUSIMServices(reader *card.Reader, services *ServicesConfig) error {
	ustChanges := make(map[int]bool)

	if services.VoLTE != nil {
		ustChanges[UST_IMS_CALL_DISCONNECT] = *services.VoLTE
	}
	if services.VoWiFi != nil {
		ustChanges[UST_WLAN_OFFLOADING] = *services.VoWiFi
		ustChanges[UST_EPDG_CONFIG] = *services.VoWiFi
		ustChanges[UST_EPDG_CONFIG_PLMN] = *services.VoWiFi
	}
	if services.GSMAccess != nil {
		ustChanges[UST_GSM_ACCESS] = *services.GSMAccess
	}
	if services.CallControl != nil {
		ustChanges[UST_CALL_CONTROL] = *services.CallControl
	}
	if services.GBA != nil {
		ustChanges[UST_GBA] = *services.GBA
	}
	if services.NAS5GConfig != nil {
		ustChanges[UST_5G_NAS_CONFIG] = *services.NAS5GConfig
	}
	if services.NSSAI5G != nil {
		ustChanges[UST_5G_NSSAI] = *services.NSSAI5G
	}
	if services.SUCICalc != nil {
		ustChanges[UST_SUCI_CALCULATION] = *services.SUCICalc
	}

	if len(ustChanges) > 0 {
		if err := SetUSIMServices(reader, ustChanges); err != nil {
			return err
		}
		fmt.Println("✓ USIM services updated")
	}

	return nil
}

func applyISIMConfig(reader *card.Reader, isim *ISIMConfig) error {
	if isim.IMPI != "" {
		if err := WriteIMPI(reader, isim.IMPI); err != nil {
			return fmt.Errorf("IMPI: %w", err)
		}
		fmt.Println("✓ IMPI written successfully")
	}

	if len(isim.IMPU) > 0 {
		for i, impu := range isim.IMPU {
			if err := WriteIMPURecord(reader, impu, byte(i+1)); err != nil {
				return fmt.Errorf("IMPU[%d]: %w", i, err)
			}
			fmt.Printf("✓ IMPU %d written successfully\n", i+1)
		}
	}

	if isim.Domain != "" {
		if err := WriteDomain(reader, isim.Domain); err != nil {
			return fmt.Errorf("Domain: %w", err)
		}
		fmt.Println("✓ Domain written successfully")
	}

	if len(isim.PCSCF) > 0 {
		for i, pcscf := range isim.PCSCF {
			if err := WritePCSCFRecord(reader, pcscf, byte(i+1)); err != nil {
				return fmt.Errorf("P-CSCF[%d]: %w", i, err)
			}
			fmt.Printf("✓ P-CSCF %d written successfully\n", i+1)
		}
	}

	return nil
}

func applyISIMServices(reader *card.Reader, services *ServicesConfig) error {
	istChanges := make(map[int]bool)

	if services.ISIMPcscf != nil {
		istChanges[IST_PCSCF_ADDRESS] = *services.ISIMPcscf
	}
	if services.ISIMSmsOverIP != nil {
		istChanges[IST_SMS_OVER_IP] = *services.ISIMSmsOverIP
	}
	if services.ISIMVoiceDomainPref != nil {
		istChanges[IST_VOICE_DOMAIN_PREF] = *services.ISIMVoiceDomainPref
	}
	if services.ISIMGBA != nil {
		istChanges[IST_GBA] = *services.ISIMGBA
	}
	if services.ISIMHttpDigest != nil {
		istChanges[IST_HTTP_DIGEST] = *services.ISIMHttpDigest
	}

	if len(istChanges) > 0 {
		if err := SetISIMServices(reader, istChanges); err != nil {
			return err
		}
		fmt.Println("✓ ISIM services updated")
	}

	return nil
}

func joinErrors(errors []string) string {
	result := ""
	for i, e := range errors {
		if i > 0 {
			result += "\n  - "
		}
		result += e
	}
	return result
}

// CreateSampleConfig creates a sample configuration file
func CreateSampleConfig(filename string) error {
	boolTrue := true

	config := &SIMConfig{
		IMSI: "250880000000001",
		SPN:  "My Operator",
		MCC:  "250",
		MNC:  "88",
		HPLMN: []HPLMNConfig{
			{MCC: "250", MNC: "88", ACT: []string{"eutran", "utran", "gsm"}},
		},
		ISIM: &ISIMConfig{
			IMPI:   "250880000000001@ims.mnc088.mcc250.3gppnetwork.org",
			IMPU:   []string{"sip:250880000000001@ims.mnc088.mcc250.3gppnetwork.org"},
			Domain: "ims.mnc088.mcc250.3gppnetwork.org",
			PCSCF:  []string{"pcscf.ims.mnc088.mcc250.3gppnetwork.org"},
		},
		Services: &ServicesConfig{
			VoLTE:               &boolTrue,
			VoWiFi:              &boolTrue,
			ISIMPcscf:           &boolTrue,
			ISIMVoiceDomainPref: &boolTrue,
		},
		ClearFPLMN: true,
	}

	return SaveConfig(filename, config)
}
