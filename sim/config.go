package sim

import (
	"encoding/json"
	"fmt"
	"os"
	"sim_reader/algorithms"
	"sim_reader/card"
)

// SIMConfig represents the configuration for writing to a SIM card
type SIMConfig struct {
	// Identity fields (writable on programmable cards)
	ICCID  string `json:"iccid,omitempty"`  // Card ID (18-20 digits, programmable cards only)
	MSISDN string `json:"msisdn,omitempty"` // Phone number

	// USIM parameters (writable)
	IMSI string `json:"imsi,omitempty"`
	SPN  string `json:"spn,omitempty"`
	MCC  string `json:"mcc,omitempty"`
	MNC  string `json:"mnc,omitempty"`

	// UE Operation Mode (3GPP TS 31.102)
	// Values: normal, type-approval, normal-specific, type-approval-specific, maintenance, cell-test
	OperationMode string `json:"operation_mode,omitempty"`

	// Languages preference (EF_LI)
	Languages []string `json:"languages,omitempty"`

	// Access Control Classes
	// For reading: []int with class numbers
	// For writing on programmable cards: use ACCHex (4 hex chars)
	ACC    []int  `json:"acc,omitempty"`
	ACCHex string `json:"acc_hex,omitempty"` // Access Control Class for writing (4 hex chars)

	// HPLMN search period in minutes (EF_HPPLMN, 0x6F31)
	HPLMNPeriod int `json:"hplmn_period,omitempty"`

	// HPLMN configuration (EF_HPLMNwACT, 0x6F62)
	HPLMN []HPLMNConfig `json:"hplmn,omitempty"`

	// Operator PLMN configuration (EF_OPLMNwACT, 0x6F61)
	OPLMN []HPLMNConfig `json:"oplmn,omitempty"`

	// User Controlled PLMN configuration (EF_PLMNwAcT, 0x6F60)
	UserPLMN []HPLMNConfig `json:"user_plmn,omitempty"`

	// Forbidden PLMNs (read-only, use clear_fplmn to clear)
	FPLMN []string `json:"fplmn,omitempty"`

	// ISIM parameters
	ISIM *ISIMConfig `json:"isim,omitempty"`

	// Services
	Services *ServicesConfig `json:"services,omitempty"`

	// Cryptographic keys (programmable cards only - DANGEROUS!)
	Ki  string `json:"ki,omitempty"`  // Subscriber key (32 hex chars)
	OP  string `json:"op,omitempty"`  // Operator key OP (32 hex chars, OPc will be computed)
	OPc string `json:"opc,omitempty"` // Operator key OPc (32 hex chars)

	// Authentication algorithm (programmable cards only)
	// Values: milenage, xor, tuak, s3g-128, s3g-256
	Algorithm string `json:"algorithm,omitempty"`

	// Security codes (programmable cards only)
	PIN1 string `json:"pin1,omitempty"` // PIN1 code (4-8 digits)
	PUK1 string `json:"puk1,omitempty"` // PUK1 code (8 digits)
	PIN2 string `json:"pin2,omitempty"` // PIN2 code (4-8 digits)
	PUK2 string `json:"puk2,omitempty"` // PUK2 code (8 digits)

	// Deprecated: use top-level fields instead
	// Kept for backward compatibility with old config files
	Programmable *ProgrammableConfig `json:"programmable,omitempty"`

	// GlobalPlatform parameters (experimental; used for applet management and ARA-M rules)
	GlobalPlatform *GlobalPlatformConfig `json:"global_platform,omitempty"`

	// PLMN options
	ClearFPLMN bool `json:"clear_fplmn,omitempty"`
}

// GlobalPlatformConfig contains configuration for GP secure channel operations and key storage.
//
// This section is primarily intended for future workflows (including eSIM-related tooling),
// where the same config file may carry both UICC filesystem parameters and GP key material.
//
// NOTE: Storing real GP keys in plaintext JSON files is sensitive. Treat them as secrets.
type GlobalPlatformConfig struct {
	// SDAID is the Security Domain / Card Manager AID (hex).
	// If empty, callers typically try common defaults depending on platform.
	SDAID string `json:"sd_aid,omitempty"`

	// SecurityLevel is the Secure Channel security level, e.g. "mac" or "mac+enc".
	SecurityLevel string `json:"security_level,omitempty"`

	// KVN is the Key Version Number (0..255) used for INITIALIZE UPDATE.
	// If omitted, tooling may try 0 or auto-probe.
	KVN *int `json:"kvn,omitempty"`

	// SCP can be "auto", "scp02", or "scp03".
	// If omitted, tooling should auto-detect based on INITIALIZE UPDATE response.
	SCP string `json:"scp,omitempty"`

	// KeySets is a list of known GP keysets for this environment.
	// Tooling may select one by name and/or auto-probe.
	KeySets []GPKeySetConfig `json:"keysets,omitempty"`

	// DefaultKeySet selects a KeySets entry by Name.
	DefaultKeySet string `json:"default_keyset,omitempty"`

	// DMS is an optional mapping to an external per-card key database (var_out format).
	DMS *GPDMSConfig `json:"dms,omitempty"`

	// ARAM optionally contains Access Rules (ARA-M) definitions.
	ARAM *GPARAMConfig `json:"aram,omitempty"`

	// Applets describes CAP load/install operations to be performed via GlobalPlatform.
	// This is intended for Java Card / UICC applet management workflows.
	Applets *GPAppletsConfig `json:"applets,omitempty"`
}

// GPAppletsConfig is a collection of GP applet/package management operations.
type GPAppletsConfig struct {
	// Loads is a list of CAP load+install operations.
	Loads []GPAppletLoadConfig `json:"loads,omitempty"`
}

// GPAppletLoadConfig describes one CAP load and applet installation operation.
//
// AIDs are hex strings (no spaces). CAPPath must point to a .cap ZIP file.
// NOTE: LOAD/INSTALL operations are destructive and may brick the card if misused.
type GPAppletLoadConfig struct {
	// CAPPath is the path to the CAP file (ZIP) on disk.
	CAPPath string `json:"cap_path,omitempty"`

	// PackageAID is the Executable Load File AID (package AID) used in INSTALL [for load].
	PackageAID string `json:"package_aid,omitempty"`

	// AppletAID is the Executable Module / Applet Class AID used in INSTALL [for install].
	AppletAID string `json:"applet_aid,omitempty"`

	// InstanceAID is the application instance AID (may equal AppletAID). If empty, tooling should default to AppletAID.
	InstanceAID string `json:"instance_aid,omitempty"`

	// Optional: target Security Domain AID to use for INSTALL [for load] (hex).
	// If empty, tooling should use GlobalPlatformConfig.SDAID.
	SDAID string `json:"sd_aid,omitempty"`

	// Optional: install parameters and privileges are not implemented in the minimal loader yet,
	// but reserved here for future compatibility (e.g., delegated management, ARA-M params, etc.).
	InstallParameters string   `json:"install_parameters,omitempty"`
	Privileges        []string `json:"privileges,omitempty"`

	// Personalization contains applet-specific personalization configuration.
	// Used for post-install STORE DATA commands or similar operations.
	Personalization *AppletPersonalizationConfig `json:"personalization,omitempty"`
}

// AppletPersonalizationConfig contains applet personalization settings.
// This is used to configure applets after installation, typically via STORE DATA APDUs.
type AppletPersonalizationConfig struct {
	// APDUs is a list of personalization APDUs in hex format.
	// These are sent to the applet after installation (e.g., via STORE DATA).
	APDUs []string `json:"apdus,omitempty"`

	// MilenageUSIM contains structured configuration for Milenage USIM applets.
	// If set, APDUs will be generated automatically for Ki, OPc, etc.
	MilenageUSIM *MilenageUSIMPersonalization `json:"milenage_usim,omitempty"`

	// Generic contains key-value parameters for other applet types.
	// Keys are tag names (e.g., "ki", "opc"), values are hex data.
	Generic map[string]string `json:"generic,omitempty"`
}

// MilenageUSIMPersonalization contains parameters for Milenage USIM applet personalization.
// This is compatible with common Java Card USIM applets that implement Milenage authentication.
type MilenageUSIMPersonalization struct {
	// Ki is the 128-bit subscriber key (32 hex chars).
	Ki string `json:"ki"`

	// OPc is the 128-bit derived operator key (32 hex chars).
	// Either OPc or OP should be provided.
	OPc string `json:"opc,omitempty"`

	// OP is the 128-bit operator key (32 hex chars).
	// If provided without OPc, OPc will be computed from OP and Ki.
	OP string `json:"op,omitempty"`

	// AMF is the 16-bit Authentication Management Field (4 hex chars).
	// Default: "8000" if not specified.
	AMF string `json:"amf,omitempty"`

	// SQN is the initial Sequence Number (12 hex chars = 6 bytes).
	// Used for replay protection in AKA. Default: "000000000000".
	SQN string `json:"sqn,omitempty"`

	// IMSI is the subscriber identity (15 digits).
	// Some applets require IMSI for personalization.
	IMSI string `json:"imsi,omitempty"`
}

// GPKeySetConfig represents one GlobalPlatform static keyset.
// Typical mapping for SCP02/SCP03 is KID=01 ENC, KID=02 MAC, KID=03 DEK within a given KVN.
type GPKeySetConfig struct {
	Name string `json:"name,omitempty"`

	// KVN is the Key Version Number (0..255) for this keyset.
	KVN int `json:"kvn,omitempty"`

	// SCP may be set per-keyset: "auto", "scp02", "scp03".
	SCP string `json:"scp,omitempty"`

	// Keys holds key material.
	Keys GPKeysConfig `json:"keys,omitempty"`
}

// GPKeysConfig holds GlobalPlatform key material.
//
// Provide either ENC+MAC (and optional DEK), or PSK (ENC=MAC=PSK), or legacy OTA-style aliases.
// All fields are hex strings.
type GPKeysConfig struct {
	// Standard GP naming
	ENC string `json:"enc,omitempty"`
	MAC string `json:"mac,omitempty"`
	DEK string `json:"dek,omitempty"`

	// PSK convenience: if set, ENC=MAC=PSK (DEK optional).
	PSK string `json:"psk,omitempty"`

	// Legacy/OTA-style aliases sometimes used by vendors (mapped as ENC/MAC/DEK by tooling)
	KIC string `json:"kic,omitempty"`
	KID string `json:"kid,omitempty"`
	KIK string `json:"kik,omitempty"`
}

// GPDMSConfig describes how to resolve key material from an external DMS-style file (var_out).
type GPDMSConfig struct {
	// Path to the var_out file
	Path string `json:"path,omitempty"`

	// Selector chooses a row (either ICCID or IMSI).
	ICCID string `json:"iccid,omitempty"`
	IMSI  string `json:"imsi,omitempty"`

	// Keyset names match the CLI conventions: cm, psk40, psk41, a..h, auto.
	Keyset string `json:"keyset,omitempty"`
}

// GPARAMConfig describes ARA-M access rules to be pushed via GP STORE DATA.
type GPARAMConfig struct {
	// AID of the ARA-M applet, typically A00000015141434C00.
	AID string `json:"aid,omitempty"`

	// Rules is a list of access rules.
	Rules []GPARAMRuleConfig `json:"rules,omitempty"`
}

// GPARAMRuleConfig is a JSON-friendly definition of a single ARA-M rule.
type GPARAMRuleConfig struct {
	// TargetAID is the AID of the applet this rule applies to (hex).
	// Use FFFFFFFFFFFF to match any AID (wildcard).
	TargetAID string `json:"target_aid,omitempty"`

	// CertHash is the SHA-1 (20 bytes) or SHA-256 (32 bytes) of an Android signing certificate (hex).
	CertHash string `json:"cert_hash,omitempty"`

	// Perm is PERM-AR-DO value (hex, commonly 8 bytes).
	Perm string `json:"perm,omitempty"`

	// ApduRule is APDU-AR-DO value (hex, commonly 01 for ALWAYS allow).
	ApduRule string `json:"apdu_rule,omitempty"`
}

// ProgrammableConfig represents programmable card parameters
type ProgrammableConfig struct {
	Ki        string `json:"ki,omitempty"`        // Subscriber key (32 hex chars)
	OP        string `json:"op,omitempty"`        // Operator key OP (32 hex chars, OPc computed)
	OPc       string `json:"opc,omitempty"`       // Operator key OPc (32 hex chars)
	ICCID     string `json:"iccid,omitempty"`     // Card identifier (18-20 digits)
	MSISDN    string `json:"msisdn,omitempty"`    // Phone number
	ACC       string `json:"acc,omitempty"`       // Access Control Class (4 hex chars)
	PIN1      string `json:"pin1,omitempty"`      // PIN1 code (4-8 digits)
	PUK1      string `json:"puk1,omitempty"`      // PUK1 code (8 digits)
	PIN2      string `json:"pin2,omitempty"`      // PIN2 code (4-8 digits)
	PUK2      string `json:"puk2,omitempty"`      // PUK2 code (8 digits)
	Algorithm string `json:"algorithm,omitempty"` // Algorithm: milenage, xor (default: milenage)
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

	// Migrate deprecated "programmable" section to top-level fields
	config.migrateFromProgrammable()

	return &config, nil
}

// migrateFromProgrammable migrates fields from deprecated Programmable section
// to top-level SIMConfig fields for backward compatibility
func (c *SIMConfig) migrateFromProgrammable() {
	if c.Programmable == nil {
		return
	}

	// Migrate fields only if top-level fields are empty
	if c.Ki == "" && c.Programmable.Ki != "" {
		c.Ki = c.Programmable.Ki
	}
	if c.OP == "" && c.Programmable.OP != "" {
		c.OP = c.Programmable.OP
	}
	if c.OPc == "" && c.Programmable.OPc != "" {
		c.OPc = c.Programmable.OPc
	}
	if c.ICCID == "" && c.Programmable.ICCID != "" {
		c.ICCID = c.Programmable.ICCID
	}
	if c.MSISDN == "" && c.Programmable.MSISDN != "" {
		c.MSISDN = c.Programmable.MSISDN
	}
	if c.ACCHex == "" && c.Programmable.ACC != "" {
		c.ACCHex = c.Programmable.ACC
	}
	if c.PIN1 == "" && c.Programmable.PIN1 != "" {
		c.PIN1 = c.Programmable.PIN1
	}
	if c.PUK1 == "" && c.Programmable.PUK1 != "" {
		c.PUK1 = c.Programmable.PUK1
	}
	if c.PIN2 == "" && c.Programmable.PIN2 != "" {
		c.PIN2 = c.Programmable.PIN2
	}
	if c.PUK2 == "" && c.Programmable.PUK2 != "" {
		c.PUK2 = c.Programmable.PUK2
	}
	if c.Algorithm == "" && c.Programmable.Algorithm != "" {
		c.Algorithm = c.Programmable.Algorithm
	}

	// Print deprecation warning
	fmt.Println("⚠ Warning: 'programmable' section is deprecated. Please use top-level fields instead.")
}

// HasProgrammableFields returns true if any programmable-only fields are set
func (c *SIMConfig) HasProgrammableFields() bool {
	return c.Ki != "" || c.OP != "" || c.OPc != "" ||
		c.PIN1 != "" || c.PIN2 != "" ||
		c.Algorithm != ""
}

// RequiresProgrammableCard returns true if the config requires a programmable card
func (c *SIMConfig) RequiresProgrammableCard() bool {
	return c.HasProgrammableFields()
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
// If dryRun is true, programmable card operations will be simulated without writing
// If force is true, programmable card operations will be forced on unrecognized cards
func ApplyConfig(reader *card.Reader, config *SIMConfig, dryRun, force bool) error {
	var errors []string

	// Detect programmable card driver once
	drv := FindDriver(reader)
	isProgrammable := drv != nil

	// Show card type info if programmable fields are present
	if config.RequiresProgrammableCard() {
		if isProgrammable {
			fmt.Printf("✓ Detected programmable card: %s\n", drv.Name())
		} else if force {
			// Fallback to first registered driver if forced
			driversMu.RLock()
			if len(registeredDrivers) > 0 {
				drv = registeredDrivers[0]
			}
			driversMu.RUnlock()
			if drv != nil {
				fmt.Printf("⚠ Warning: Using fallback driver %s (forced)\n", drv.Name())
			}
		} else {
			errors = append(errors, "card is not recognized as programmable. Use --force to override (DANGEROUS!)")
		}
	}

	// Apply programmable card operations first
	if err := applyProgrammableFields(reader, config, drv, dryRun, force); err != nil {
		errors = append(errors, fmt.Sprintf("Programmable: %v", err))
	}

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

	// Set operation mode if specified
	if config.OperationMode != "" {
		if err := SetOperationModeFromString(reader, config.OperationMode); err != nil {
			errors = append(errors, fmt.Sprintf("Operation mode: %v", err))
		} else {
			fmt.Printf("✓ Operation mode set to: %s\n", config.OperationMode)
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

	// Write Operator PLMN
	if len(config.OPLMN) > 0 {
		entries := make([]HPLMNEntry, 0, len(config.OPLMN))
		for _, h := range config.OPLMN {
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
		if err := WriteOPLMNList(reader, entries); err != nil {
			errors = append(errors, fmt.Sprintf("OPLMN: %v", err))
		} else {
			fmt.Printf("✓ OPLMN written (%d entries)\n", len(entries))
		}
	}

	// Write User Controlled PLMN
	if len(config.UserPLMN) > 0 {
		entries := make([]HPLMNEntry, 0, len(config.UserPLMN))
		for _, h := range config.UserPLMN {
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
		if err := WriteUserPLMNList(reader, entries); err != nil {
			errors = append(errors, fmt.Sprintf("User PLMN: %v", err))
		} else {
			fmt.Printf("✓ User PLMN written (%d entries)\n", len(entries))
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
		// Operation mode: normal, type-approval, cell-test, etc.
		// Use "cell-test" for test PLMNs (001-01, 999-99)
		OperationMode: "normal",
		HPLMN: []HPLMNConfig{
			{MCC: "250", MNC: "88", ACT: []string{"eutran", "utran", "gsm"}},
		},
		// User Controlled PLMN - preferred networks selected by user
		// Useful for test PLMNs
		UserPLMN: []HPLMNConfig{
			{MCC: "001", MNC: "01", ACT: []string{"eutran", "utran", "gsm"}},
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

// ExportToConfig creates a SIMConfig from current card data
// This can be saved to JSON and edited, then loaded back with -write
// All readable parameters are exported to ensure full round-trip capability
func ExportToConfig(usimData *USIMData, isimData *ISIMData) *SIMConfig {
	config := &SIMConfig{}

	if usimData != nil {
		// Read-only identity fields (for reference)
		config.ICCID = usimData.ICCID
		config.MSISDN = usimData.MSISDN

		// Writable identity fields
		config.IMSI = usimData.IMSI
		config.SPN = usimData.SPN
		config.MCC = usimData.MCC
		config.MNC = usimData.MNC

		// Languages preference
		if len(usimData.Languages) > 0 {
			config.Languages = usimData.Languages
		}

		// Access Control Classes (read-only, for reference)
		if len(usimData.ACC) > 0 {
			config.ACC = usimData.ACC
		}

		// HPLMN search period
		if usimData.HPLMNPeriod > 0 {
			config.HPLMNPeriod = usimData.HPLMNPeriod
		}

		// Forbidden PLMNs (read-only, use clear_fplmn to clear)
		if len(usimData.FPLMN) > 0 {
			config.FPLMN = usimData.FPLMN
		}

		// Operation mode from AdminData
		switch usimData.AdminData.UEMode {
		case "Normal":
			config.OperationMode = "normal"
		case "Type Approval":
			config.OperationMode = "type-approval"
		case "Normal + specific facilities":
			config.OperationMode = "normal-specific"
		case "Type Approval + specific facilities":
			config.OperationMode = "type-approval-specific"
		case "Maintenance (off-line)":
			config.OperationMode = "maintenance"
		case "Cell Test":
			config.OperationMode = "cell-test"
		default:
			// Store raw value if not recognized
			if usimData.AdminData.UEMode != "" {
				config.OperationMode = usimData.AdminData.UEMode
			}
		}

		// HPLMN
		for _, p := range usimData.HPLMN {
			config.HPLMN = append(config.HPLMN, HPLMNConfig{
				MCC: p.MCC,
				MNC: p.MNC,
				ACT: plmnActToStrings(p.ACT),
			})
		}

		// OPLMN
		for _, p := range usimData.OPLMN {
			config.OPLMN = append(config.OPLMN, HPLMNConfig{
				MCC: p.MCC,
				MNC: p.MNC,
				ACT: plmnActToStrings(p.ACT),
			})
		}

		// User PLMN
		for _, p := range usimData.UserPLMN {
			config.UserPLMN = append(config.UserPLMN, HPLMNConfig{
				MCC: p.MCC,
				MNC: p.MNC,
				ACT: plmnActToStrings(p.ACT),
			})
		}

		// Services from UST - export all known services
		if usimData.UST != nil {
			config.Services = &ServicesConfig{}
			volte := usimData.HasVoLTE()
			vowifi := usimData.HasVoWiFi()
			smsip := usimData.HasSMSOverIP()
			gsm := usimData.HasService(27)
			callctrl := usimData.HasService(30)
			gba := usimData.HasService(67)
			nas5g := usimData.HasService(104)
			nssai := usimData.HasService(108)
			suci := usimData.HasService(112)

			config.Services.VoLTE = &volte
			config.Services.VoWiFi = &vowifi
			config.Services.SMSOverIP = &smsip
			config.Services.GSMAccess = &gsm
			config.Services.CallControl = &callctrl
			config.Services.GBA = &gba
			config.Services.NAS5GConfig = &nas5g
			config.Services.NSSAI5G = &nssai
			config.Services.SUCICalc = &suci
		}
	}

	if isimData != nil && isimData.Available {
		config.ISIM = &ISIMConfig{
			IMPI:   isimData.IMPI,
			IMPU:   isimData.IMPU,
			Domain: isimData.Domain,
			PCSCF:  isimData.PCSCF,
		}

		// ISIM services
		if config.Services == nil {
			config.Services = &ServicesConfig{}
		}
		pcscf := isimData.HasPCSCF()
		isimSms := isimData.HasSMSOverIP()
		voicePref := isimData.HasVoiceDomainPreference()
		isimGba := isimData.HasGBA()
		httpDigest := isimData.HasHTTPDigest()

		config.Services.ISIMPcscf = &pcscf
		config.Services.ISIMSmsOverIP = &isimSms
		config.Services.ISIMVoiceDomainPref = &voicePref
		config.Services.ISIMGBA = &isimGba
		config.Services.ISIMHttpDigest = &httpDigest
	}

	return config
}

// plmnActToStrings converts ACT bitmask to string slice
func plmnActToStrings(act uint16) []string {
	var result []string
	if act&0x8000 != 0 {
		result = append(result, "utran")
	}
	if act&0x4000 != 0 {
		result = append(result, "eutran")
	}
	if act&0x0080 != 0 {
		result = append(result, "gsm")
	}
	if act&0x0800 != 0 {
		result = append(result, "nr")
	}
	if act&0x0400 != 0 {
		result = append(result, "ngran")
	}
	return result
}

// applyProgrammableFields applies programmable card fields from SIMConfig
// drv can be nil if no programmable card detected (operations will be skipped)
func applyProgrammableFields(reader *card.Reader, config *SIMConfig, drv ProgrammableDriver, dryRun, force bool) error {
	// Skip if no programmable fields are set
	if !config.HasProgrammableFields() && config.ICCID == "" && config.MSISDN == "" && config.ACCHex == "" {
		return nil
	}

	// Check if driver is available for operations that require it
	requiresDriver := config.Ki != "" || config.OP != "" || config.OPc != "" ||
		config.PIN1 != "" || config.PIN2 != "" || config.Algorithm != ""

	if requiresDriver && drv == nil && !force {
		return fmt.Errorf("no programmable card driver detected")
	}

	// Write Ki
	if config.Ki != "" && drv != nil {
		if dryRun {
			fmt.Printf("[DRY RUN] Would write Ki: %s\n", config.Ki)
		} else {
			kiBytes, err := algorithms.ValidateKi(config.Ki)
			if err != nil {
				return err
			}
			if err := WriteKi(reader, drv, kiBytes); err != nil {
				return fmt.Errorf("failed to write Ki: %w", err)
			}
			fmt.Println("✓ Ki written successfully")
		}
	}

	// Write OPc (or compute from OP)
	if config.OPc != "" && drv != nil {
		if dryRun {
			fmt.Printf("[DRY RUN] Would write OPc: %s\n", config.OPc)
		} else {
			opcBytes, err := algorithms.ValidateOPc(config.OPc)
			if err != nil {
				return err
			}
			if err := WriteOPc(reader, drv, opcBytes); err != nil {
				return fmt.Errorf("failed to write OPc: %w", err)
			}
			fmt.Println("✓ OPc written successfully")
		}
	} else if config.OP != "" && drv != nil {
		if dryRun {
			fmt.Printf("[DRY RUN] Would compute and write OPc from OP: %s\n", config.OP)
		} else {
			if config.Ki == "" {
				return fmt.Errorf("Ki must be provided to compute OPc from OP")
			}
			kiBytes, err := algorithms.ValidateKi(config.Ki)
			if err != nil {
				return err
			}
			opBytes, err := algorithms.ValidateOPc(config.OP) // OP has same format as OPc
			if err != nil {
				return fmt.Errorf("invalid OP: %w", err)
			}
			if err := ComputeAndWriteOPc(reader, drv, kiBytes, opBytes); err != nil {
				return fmt.Errorf("failed to compute and write OPc: %w", err)
			}
			fmt.Println("✓ OPc computed and written successfully")
		}
	}

	// Write Milenage R and C constants
	if (config.Ki != "" || config.OPc != "" || config.OP != "") && drv != nil {
		if dryRun {
			fmt.Println("[DRY RUN] Would write Milenage R and C constants")
		} else {
			if err := WriteMilenageRAndC(reader, drv); err != nil {
				return fmt.Errorf("failed to write Milenage R/C: %w", err)
			}
			fmt.Println("✓ Milenage R and C constants written successfully")
		}
	}

	// Set algorithm type
	if config.Algorithm != "" && drv != nil {
		if dryRun {
			fmt.Printf("[DRY RUN] Would set algorithm type: %s\n", config.Algorithm)
		} else {
			if err := SetMilenageAlgorithmType(reader, drv, config.Algorithm); err != nil {
				return fmt.Errorf("failed to set algorithm type: %w", err)
			}
			fmt.Printf("✓ Algorithm type set to: %s\n", config.Algorithm)
		}
	}

	// Write ICCID (requires programmable card)
	if config.ICCID != "" && drv != nil {
		if dryRun {
			fmt.Printf("[DRY RUN] Would write ICCID: %s\n", config.ICCID)
		} else {
			if err := WriteICCID(reader, drv, config.ICCID); err != nil {
				return fmt.Errorf("failed to write ICCID: %w", err)
			}
			fmt.Println("✓ ICCID written successfully")
		}
	}

	// Write MSISDN
	if config.MSISDN != "" {
		if drv != nil {
			// Use driver method for programmable cards
			if dryRun {
				fmt.Printf("[DRY RUN] Would write MSISDN: %s\n", config.MSISDN)
			} else {
				if err := WriteMSISDN(reader, drv, config.MSISDN); err != nil {
					return fmt.Errorf("failed to write MSISDN: %w", err)
				}
				fmt.Println("✓ MSISDN written successfully")
			}
		} else {
			// Try generic MSISDN write for standard cards
			if dryRun {
				fmt.Printf("[DRY RUN] Would write MSISDN: %s\n", config.MSISDN)
			} else {
				if err := WriteMSISDNGeneric(reader, config.MSISDN); err != nil {
					return fmt.Errorf("failed to write MSISDN: %w", err)
				}
				fmt.Println("✓ MSISDN written successfully")
			}
		}
	}

	// Write ACC
	if config.ACCHex != "" && drv != nil {
		if dryRun {
			fmt.Printf("[DRY RUN] Would write ACC: %s\n", config.ACCHex)
		} else {
			if err := WriteACC(reader, drv, config.ACCHex); err != nil {
				return fmt.Errorf("failed to write ACC: %w", err)
			}
			fmt.Println("✓ ACC written successfully")
		}
	}

	// Write PIN/PUK codes
	if (config.PIN1 != "" || config.PIN2 != "") && drv != nil {
		if dryRun {
			fmt.Println("[DRY RUN] Would write PIN/PUK codes")
		} else {
			if err := WritePINs(reader, drv, config.PIN1, config.PUK1, config.PIN2, config.PUK2); err != nil {
				return fmt.Errorf("failed to write PIN/PUK codes: %w", err)
			}
			fmt.Println("✓ PIN/PUK codes written successfully")
		}
	}

	return nil
}
