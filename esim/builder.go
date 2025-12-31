package esim

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sim_reader/sim"
)

// LoadTemplate loads a profile template from file (DER or ASN.1 text format)
// File format is determined by extension: .der for binary, .txt/.asn1 for text
func LoadTemplate(templatePath string) (*Profile, error) {
	ext := strings.ToLower(filepath.Ext(templatePath))

	switch ext {
	case ".der":
		return LoadProfile(templatePath)
	case ".txt", ".asn1", ".asn":
		return ParseValueNotationFile(templatePath)
	default:
		// Try to detect by reading first bytes
		data, err := os.ReadFile(templatePath)
		if err != nil {
			return nil, fmt.Errorf("read template: %w", err)
		}

		// ASN.1 text starts with "value" or whitespace/comments
		if len(data) > 0 && (data[0] == 'v' || data[0] == ' ' || data[0] == '\t' || data[0] == '\n' || data[0] == '\r' || data[0] == '-') {
			return ParseValueNotation(string(data))
		}

		// Assume DER binary
		return DecodeProfile(data)
	}
}

// BuildProfileFromSIMConfig builds an eSIM profile from template and SIMConfig
// This is the main entry point for profile building using the unified config structure
func BuildProfileFromSIMConfig(template *Profile, config *sim.SIMConfig) (*Profile, error) {
	// Clone template
	profile, err := template.Clone()
	if err != nil {
		return nil, fmt.Errorf("clone template: %w", err)
	}

	// Sanitize cloned template - clear all template keys/IMSI/PINs
	profile.Sanitize()

	// Apply configuration
	if err := ApplyConfigToProfile(profile, config); err != nil {
		return nil, err
	}

	return profile, nil
}

// ApplyConfigToProfile applies SIMConfig values to an existing profile
func ApplyConfigToProfile(profile *Profile, config *sim.SIMConfig) error {
	// Set ICCID
	if config.ICCID != "" {
		if err := profile.SetICCID(config.ICCID); err != nil {
			return fmt.Errorf("set ICCID: %w", err)
		}
	}

	// Set IMSI
	if config.IMSI != "" {
		if err := profile.SetIMSI(config.IMSI); err != nil {
			return fmt.Errorf("set IMSI: %w", err)
		}
	}

	// Handle applet authentication delegation
	if config.UseAppletAuth {
		// Find applet with MilenageUSIM personalization to get keys
		appletKeys := findAppletMilenageKeys(config)
		if appletKeys != nil {
			if appletKeys.Ki != "" {
				ki, err := hex.DecodeString(appletKeys.Ki)
				if err != nil {
					return fmt.Errorf("parse applet Ki: %w", err)
				}
				if err := profile.SetKi(ki); err != nil {
					return fmt.Errorf("set applet Ki: %w", err)
				}
			}

			if appletKeys.OPc != "" {
				opc, err := hex.DecodeString(appletKeys.OPc)
				if err != nil {
					return fmt.Errorf("parse applet OPc: %w", err)
				}
				if err := profile.SetOPC(opc); err != nil {
					return fmt.Errorf("set applet OPc: %w", err)
				}
			}
		}

		// Set algorithm to delegate to applet
		for _, aka := range profile.AKAParams {
			if aka.AlgoConfig != nil {
				aka.AlgoConfig.AlgorithmID = AlgoUSIMTestAlgorithm
			}
		}
		profile.invalidate(TagAKAParameter)
	} else {
		// Standard mode: use root ki/opc for AKA parameters

		// Set Ki
		if config.Ki != "" {
			ki, err := hex.DecodeString(config.Ki)
			if err != nil {
				return fmt.Errorf("parse Ki: %w", err)
			}
			if err := profile.SetKi(ki); err != nil {
				return fmt.Errorf("set Ki: %w", err)
			}
		}

		// Set OPc
		if config.OPc != "" {
			opc, err := hex.DecodeString(config.OPc)
			if err != nil {
				return fmt.Errorf("parse OPc: %w", err)
			}
			if err := profile.SetOPC(opc); err != nil {
				return fmt.Errorf("set OPc: %w", err)
			}
		}

		// Set algorithm ID if specified
		if config.AlgorithmID > 0 {
			for _, aka := range profile.AKAParams {
				if aka.AlgoConfig != nil {
					aka.AlgoConfig.AlgorithmID = AlgorithmID(config.AlgorithmID)
				}
			}
			profile.invalidate(TagAKAParameter)
		}
	}

	// Set ISIM parameters
	if config.ISIM != nil {
		if err := applyISIMConfig(profile, config.ISIM); err != nil {
			return fmt.Errorf("set ISIM params: %w", err)
		}
	}

	// Set security codes
	if err := applySecurityCodes(profile, config); err != nil {
		return fmt.Errorf("set security codes: %w", err)
	}

	// Set profile type
	if config.ProfileType != "" && profile.Header != nil {
		profile.Header.ProfileType = config.ProfileType
		profile.invalidate(TagProfileHeader)
	}

	// Add applets from GlobalPlatform config
	if config.GlobalPlatform != nil && config.GlobalPlatform.Applets != nil {
		for _, appletCfg := range config.GlobalPlatform.Applets.Loads {
			if appletCfg.UseForESIM {
				if err := addAppletFromGPConfig(profile, &appletCfg); err != nil {
					return fmt.Errorf("add applet %s: %w", appletCfg.PackageAID, err)
				}
			}
		}
	}

	return nil
}

// findAppletMilenageKeys finds MilenageUSIM personalization from GlobalPlatform config
func findAppletMilenageKeys(config *sim.SIMConfig) *sim.MilenageUSIMPersonalization {
	if config.GlobalPlatform == nil || config.GlobalPlatform.Applets == nil {
		return nil
	}

	for _, applet := range config.GlobalPlatform.Applets.Loads {
		if applet.UseForESIM && applet.Personalization != nil && applet.Personalization.MilenageUSIM != nil {
			return applet.Personalization.MilenageUSIM
		}
	}

	return nil
}

// applyISIMConfig applies ISIM parameters to profile
func applyISIMConfig(profile *Profile, isim *sim.ISIMConfig) error {
	if profile.ISIM == nil {
		return nil // ISIM not present in template, skip
	}

	// Set IMPI
	if isim.IMPI != "" && profile.ISIM.EF_IMPI != nil {
		impiBytes := encodeIMPI(isim.IMPI)
		if len(profile.ISIM.EF_IMPI.FillContents) > 0 {
			profile.ISIM.EF_IMPI.FillContents[0].Content = impiBytes
		} else {
			profile.ISIM.EF_IMPI.FillContents = append(profile.ISIM.EF_IMPI.FillContents, FillContent{
				Content: impiBytes,
			})
		}
		profile.ISIM.EF_IMPI.Raw = nil
	}

	// Set IMPU
	if len(isim.IMPU) > 0 && profile.ISIM.EF_IMPU != nil {
		impuBytes := encodeIMPUList(isim.IMPU)
		if len(profile.ISIM.EF_IMPU.FillContents) > 0 {
			profile.ISIM.EF_IMPU.FillContents[0].Content = impuBytes
		} else {
			profile.ISIM.EF_IMPU.FillContents = append(profile.ISIM.EF_IMPU.FillContents, FillContent{
				Content: impuBytes,
			})
		}
		profile.ISIM.EF_IMPU.Raw = nil
	}

	// Set Domain
	if isim.Domain != "" && profile.ISIM.EF_DOMAIN != nil {
		domainBytes := encodeDomain(isim.Domain)
		if len(profile.ISIM.EF_DOMAIN.FillContents) > 0 {
			profile.ISIM.EF_DOMAIN.FillContents[0].Content = domainBytes
		} else {
			profile.ISIM.EF_DOMAIN.FillContents = append(profile.ISIM.EF_DOMAIN.FillContents, FillContent{
				Content: domainBytes,
			})
		}
		profile.ISIM.EF_DOMAIN.Raw = nil
	}

	profile.invalidate(TagISIM)
	return nil
}

// applySecurityCodes applies PIN/PUK/ADM codes to profile
func applySecurityCodes(profile *Profile, config *sim.SIMConfig) error {
	modified := false

	// Set PIN1
	if config.PIN1 != "" {
		if err := setPIN(profile, 0x01, config.PIN1); err != nil {
			return fmt.Errorf("set PIN1: %w", err)
		}
		modified = true
	}

	// Set PIN2
	if config.PIN2 != "" {
		if err := setPIN(profile, 0x81, config.PIN2); err != nil {
			return fmt.Errorf("set PIN2: %w", err)
		}
		modified = true
	}

	// Set PUK1
	if config.PUK1 != "" {
		if err := setPUK(profile, 0x01, config.PUK1); err != nil {
			return fmt.Errorf("set PUK1: %w", err)
		}
		profile.invalidate(TagPukCodes)
	}

	// Set PUK2
	if config.PUK2 != "" {
		if err := setPUK(profile, 0x81, config.PUK2); err != nil {
			return fmt.Errorf("set PUK2: %w", err)
		}
		profile.invalidate(TagPukCodes)
	}

	// Set ADM1
	if config.ADM1 != "" {
		if err := setPIN(profile, 0x0A, config.ADM1); err != nil {
			return fmt.Errorf("set ADM1: %w", err)
		}
		modified = true
	}

	if modified {
		profile.invalidate(TagPinCodes)
	}

	return nil
}

// addAppletFromGPConfig adds an applet to profile from GPAppletLoadConfig
func addAppletFromGPConfig(profile *Profile, cfg *sim.GPAppletLoadConfig) error {
	if cfg.CAPPath == "" {
		return fmt.Errorf("cap_path is required")
	}

	// Read CAP file
	capData, err := os.ReadFile(cfg.CAPPath)
	if err != nil {
		return fmt.Errorf("read CAP file: %w", err)
	}

	// Parse AIDs
	packageAID, err := hex.DecodeString(strings.ReplaceAll(cfg.PackageAID, ":", ""))
	if err != nil {
		return fmt.Errorf("parse package AID: %w", err)
	}

	classAID, err := hex.DecodeString(strings.ReplaceAll(cfg.AppletAID, ":", ""))
	if err != nil {
		return fmt.Errorf("parse class AID: %w", err)
	}

	instanceAID := classAID
	if cfg.InstanceAID != "" {
		instanceAID, err = hex.DecodeString(strings.ReplaceAll(cfg.InstanceAID, ":", ""))
		if err != nil {
			return fmt.Errorf("parse instance AID: %w", err)
		}
	}

	var sdAID []byte
	if cfg.SDAID != "" {
		sdAID, err = hex.DecodeString(strings.ReplaceAll(cfg.SDAID, ":", ""))
		if err != nil {
			return fmt.Errorf("parse SD AID: %w", err)
		}
	}

	// Build ProcessData APDUs from personalization config
	var processData [][]byte

	if cfg.Personalization != nil {
		// Use explicit APDUs if provided
		for _, apduHex := range cfg.Personalization.APDUs {
			apdu, err := hex.DecodeString(strings.ReplaceAll(apduHex, " ", ""))
			if err != nil {
				return fmt.Errorf("parse APDU: %w", err)
			}
			processData = append(processData, apdu)
		}

		// Or build from structured Milenage config
		if cfg.Personalization.MilenageUSIM != nil {
			apdus, err := buildMilenageAPDUs(cfg.Personalization.MilenageUSIM)
			if err != nil {
				return fmt.Errorf("build Milenage APDUs: %w", err)
			}
			processData = append(processData, apdus...)
		}
	}

	// Create Application element
	app := &Application{
		Header: &ElementHeader{
			Mandated: true,
		},
		LoadBlock: &ApplicationLoadPackage{
			LoadPackageAID:    packageAID,
			SecurityDomainAID: sdAID,
			LoadBlockObject:   capData,
		},
		InstanceList: []*ApplicationInstance{
			{
				ApplicationLoadPackageAID:   packageAID,
				ClassAID:                    classAID,
				InstanceAID:                 instanceAID,
				ApplicationPrivileges:       []byte{0x00, 0x00, 0x00}, // Default: no privileges
				LifeCycleState:              0x07,                     // Selectable
				ApplicationSpecificParamsC9: []byte{0x81, 0x00},      // Default C9
				ProcessData:                 processData,
			},
		},
	}

	// Add to profile before End element
	profile.Applications = append(profile.Applications, app)

	// Add to Elements list before End
	appElem := ProfileElement{
		Tag:   TagApplication,
		Value: app,
	}

	// Find End element index and insert before it
	endIdx := -1
	for i, elem := range profile.Elements {
		if elem.Tag == TagEnd {
			endIdx = i
			break
		}
	}

	if endIdx >= 0 {
		// Insert before End
		profile.Elements = append(profile.Elements[:endIdx],
			append([]ProfileElement{appElem}, profile.Elements[endIdx:]...)...)
	} else {
		// Append if no End found
		profile.Elements = append(profile.Elements, appElem)
	}

	return nil
}

// buildMilenageAPDUs builds personalization APDUs for Milenage USIM applet
func buildMilenageAPDUs(cfg *sim.MilenageUSIMPersonalization) ([][]byte, error) {
	var apdus [][]byte

	// Parse Ki
	ki, err := hex.DecodeString(cfg.Ki)
	if err != nil {
		return nil, fmt.Errorf("parse Ki: %w", err)
	}
	if len(ki) != 16 && len(ki) != 32 {
		return nil, fmt.Errorf("Ki must be 16 or 32 bytes, got %d", len(ki))
	}

	// Parse OPc or OP
	var opcOrOP []byte
	var useOP bool
	if cfg.OPc != "" {
		opcOrOP, err = hex.DecodeString(cfg.OPc)
		if err != nil {
			return nil, fmt.Errorf("parse OPc: %w", err)
		}
		useOP = false
	} else if cfg.OP != "" {
		opcOrOP, err = hex.DecodeString(cfg.OP)
		if err != nil {
			return nil, fmt.Errorf("parse OP: %w", err)
		}
		useOP = true
	}

	// AMF default
	amf := []byte{0x80, 0x00}
	if cfg.AMF != "" {
		amf, err = hex.DecodeString(cfg.AMF)
		if err != nil {
			return nil, fmt.Errorf("parse AMF: %w", err)
		}
	}

	// Build STORE DATA APDUs for Milenage USIM applet
	// Format: CLA INS P1 P2 Lc Data
	// CLA=80, INS=E2 (STORE DATA), P1=sequence, P2=params

	// APDU 1: Store Ki (Tag 01)
	kiAPDU := []byte{0x80, 0xE2, 0x00, 0x00}
	kiData := append([]byte{0x01, byte(len(ki))}, ki...)
	kiAPDU = append(kiAPDU, byte(len(kiData)))
	kiAPDU = append(kiAPDU, kiData...)
	apdus = append(apdus, kiAPDU)

	// APDU 2: Store OPc or OP
	if len(opcOrOP) > 0 {
		opcAPDU := []byte{0x80, 0xE2, 0x00, 0x00}
		tag := byte(0x02) // OPc
		if useOP {
			tag = 0x03 // OP
		}
		opcData := append([]byte{tag, byte(len(opcOrOP))}, opcOrOP...)
		opcAPDU = append(opcAPDU, byte(len(opcData)))
		opcAPDU = append(opcAPDU, opcData...)
		apdus = append(apdus, opcAPDU)
	}

	// APDU 3: Store AMF (Tag 04)
	amfAPDU := []byte{0x80, 0xE2, 0x00, 0x00}
	amfData := append([]byte{0x04, byte(len(amf))}, amf...)
	amfAPDU = append(amfAPDU, byte(len(amfData)))
	amfAPDU = append(amfAPDU, amfData...)
	apdus = append(apdus, amfAPDU)

	// APDU 4: Store SQN if provided (Tag 05)
	if cfg.SQN != "" {
		sqn, err := hex.DecodeString(cfg.SQN)
		if err != nil {
			return nil, fmt.Errorf("parse SQN: %w", err)
		}
		sqnAPDU := []byte{0x80, 0xE2, 0x00, 0x00}
		sqnData := append([]byte{0x05, byte(len(sqn))}, sqn...)
		sqnAPDU = append(sqnAPDU, byte(len(sqnData)))
		sqnAPDU = append(sqnAPDU, sqnData...)
		apdus = append(apdus, sqnAPDU)
	}

	return apdus, nil
}

// ============================================================================
// Helper functions for encoding profile data
// ============================================================================

func setPIN(profile *Profile, keyRef byte, value string) error {
	encoded := encodePINValue(value)

	for _, pc := range profile.PinCodes {
		for i := range pc.Configs {
			if pc.Configs[i].KeyReference == keyRef {
				pc.Configs[i].PINValue = encoded
				return nil
			}
		}
	}

	return fmt.Errorf("PIN with KeyReference 0x%02X not found", keyRef)
}

func setPUK(profile *Profile, keyRef byte, value string) error {
	encoded := encodePINValue(value)

	if profile.PukCodes != nil {
		for i := range profile.PukCodes.Codes {
			if profile.PukCodes.Codes[i].KeyReference == keyRef {
				profile.PukCodes.Codes[i].PUKValue = encoded
				return nil
			}
		}
	}

	return fmt.Errorf("PUK with KeyReference 0x%02X not found", keyRef)
}

func encodePINValue(value string) []byte {
	result := make([]byte, 8)
	for i := range result {
		result[i] = 0xFF
	}
	for i := 0; i < len(value) && i < 8; i++ {
		result[i] = value[i]
	}
	return result
}

// ISIM encoding helpers

func encodeIMPI(impi string) []byte {
	// IMPI is stored as TLV: tag 80, length, value (UTF-8)
	data := []byte(impi)
	result := []byte{0x80, byte(len(data))}
	return append(result, data...)
}

func encodeIMPUList(impus []string) []byte {
	// Each IMPU is TLV: tag 80, length, value
	// Multiple IMPUs are concatenated
	var result []byte
	for _, impu := range impus {
		data := []byte(impu)
		tlv := []byte{0x80, byte(len(data))}
		tlv = append(tlv, data...)
		result = append(result, tlv...)
	}
	return result
}

func encodeDomain(domain string) []byte {
	// Domain is stored as TLV: tag 80, length, value (UTF-8)
	data := []byte(domain)
	result := []byte{0x80, byte(len(data))}
	return append(result, data...)
}

// ============================================================================
// Deprecated: BuildConfig-based API (for backward compatibility)
// Use BuildProfileFromSIMConfig and SIMConfig instead
// ============================================================================

// BuildConfig represents configuration for building an eSIM profile
// Deprecated: Use sim.SIMConfig with BuildProfileFromSIMConfig instead
type BuildConfig struct {
	ICCID         string                       `json:"iccid"`
	IMSI          string                       `json:"imsi"`
	Ki            string                       `json:"ki"`
	OPc           string                       `json:"opc"`
	OP            string                       `json:"op"`
	IMPI          string                       `json:"impi,omitempty"`
	IMPU          []string                     `json:"impu,omitempty"`
	Domain        string                       `json:"domain,omitempty"`
	PIN1          string                       `json:"pin1,omitempty"`
	PIN2          string                       `json:"pin2,omitempty"`
	PUK1          string                       `json:"puk1,omitempty"`
	PUK2          string                       `json:"puk2,omitempty"`
	ADM1          string                       `json:"adm1,omitempty"`
	AppletCAP     string                       `json:"applet_cap,omitempty"`
	AppletConfig  *AppletPersonalizationConfig `json:"applet_config,omitempty"`
	UseAppletAuth bool                         `json:"use_applet_auth,omitempty"`
	AlgorithmID   int                          `json:"algorithm_id,omitempty"`
	ProfileType   string                       `json:"profile_type,omitempty"`
}

// AppletPersonalizationConfig represents applet-specific configuration
// Deprecated: Use sim.GPAppletLoadConfig.Personalization instead
type AppletPersonalizationConfig struct {
	PackageAID        string                    `json:"package_aid"`
	ClassAID          string                    `json:"class_aid"`
	InstanceAID       string                    `json:"instance_aid"`
	SecurityDomainAID string                    `json:"sd_aid,omitempty"`
	APDUs             []string                  `json:"apdus,omitempty"`
	MilenageUSIM      *MilenageUSIMAppletConfig `json:"milenage_usim,omitempty"`
}

// MilenageUSIMAppletConfig represents Milenage USIM applet configuration
// Deprecated: Use sim.MilenageUSIMPersonalization instead
type MilenageUSIMAppletConfig struct {
	Ki  string `json:"ki"`
	OPc string `json:"opc,omitempty"`
	OP  string `json:"op,omitempty"`
	AMF string `json:"amf,omitempty"`
	SQN string `json:"sqn,omitempty"`
}

// BuildProfile builds a new profile from template and configuration
// Deprecated: Use BuildProfileFromSIMConfig instead
func BuildProfile(template *Profile, config *BuildConfig) (*Profile, error) {
	// Convert to SIMConfig
	simConfig := &sim.SIMConfig{
		ICCID:         config.ICCID,
		IMSI:          config.IMSI,
		Ki:            config.Ki,
		OPc:           config.OPc,
		OP:            config.OP,
		PIN1:          config.PIN1,
		PIN2:          config.PIN2,
		PUK1:          config.PUK1,
		PUK2:          config.PUK2,
		ADM1:          config.ADM1,
		ProfileType:   config.ProfileType,
		AlgorithmID:   config.AlgorithmID,
		UseAppletAuth: config.UseAppletAuth,
	}

	// Set ISIM config
	if config.IMPI != "" || len(config.IMPU) > 0 || config.Domain != "" {
		simConfig.ISIM = &sim.ISIMConfig{
			IMPI:   config.IMPI,
			IMPU:   config.IMPU,
			Domain: config.Domain,
		}
	}

	// Convert applet config
	if config.AppletCAP != "" && config.AppletConfig != nil {
		simConfig.GlobalPlatform = &sim.GlobalPlatformConfig{
			Applets: &sim.GPAppletsConfig{
				Loads: []sim.GPAppletLoadConfig{
					{
						CAPPath:     config.AppletCAP,
						PackageAID:  config.AppletConfig.PackageAID,
						AppletAID:   config.AppletConfig.ClassAID,
						InstanceAID: config.AppletConfig.InstanceAID,
						SDAID:       config.AppletConfig.SecurityDomainAID,
						UseForESIM:  true,
						Personalization: &sim.AppletPersonalizationConfig{
							APDUs: config.AppletConfig.APDUs,
						},
					},
				},
			},
		}

		// Convert Milenage config if present
		if config.AppletConfig.MilenageUSIM != nil {
			simConfig.GlobalPlatform.Applets.Loads[0].Personalization.MilenageUSIM = &sim.MilenageUSIMPersonalization{
				Ki:  config.AppletConfig.MilenageUSIM.Ki,
				OPc: config.AppletConfig.MilenageUSIM.OPc,
				OP:  config.AppletConfig.MilenageUSIM.OP,
				AMF: config.AppletConfig.MilenageUSIM.AMF,
				SQN: config.AppletConfig.MilenageUSIM.SQN,
			}
		}
	}

	return BuildProfileFromSIMConfig(template, simConfig)
}
