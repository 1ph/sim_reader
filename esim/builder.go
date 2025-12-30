package esim

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// BuildConfig represents configuration for building an eSIM profile
type BuildConfig struct {
	// Basic identifiers
	ICCID string `json:"iccid"`
	IMSI  string `json:"imsi"`
	
	// Authentication
	Ki  string `json:"ki"`       // 32 hex chars (16 bytes) or 64 hex chars (32 bytes)
	OPc string `json:"opc"`      // Optional: 32 or 64 hex chars
	OP  string `json:"op"`       // Optional: used to compute OPc if OPc not provided
	
	// ISIM parameters (optional)
	IMPI   string   `json:"impi,omitempty"`
	IMPU   []string `json:"impu,omitempty"`
	Domain string   `json:"domain,omitempty"`
	
	// Security codes (optional, default from template)
	PIN1 string `json:"pin1,omitempty"`
	PIN2 string `json:"pin2,omitempty"`
	PUK1 string `json:"puk1,omitempty"`
	PUK2 string `json:"puk2,omitempty"`
	ADM1 string `json:"adm1,omitempty"`
	
	// Applet configuration (optional)
	AppletCAP    string                       `json:"applet_cap,omitempty"`
	AppletConfig *AppletPersonalizationConfig `json:"applet_config,omitempty"`
	UseAppletAuth bool                        `json:"use_applet_auth,omitempty"`
	
	// Algorithm override (default: keep from template)
	AlgorithmID int `json:"algorithm_id,omitempty"` // 1=Milenage, 2=TUAK, 3=USIM Test
	
	// Profile type override
	ProfileType string `json:"profile_type,omitempty"`
}

// AppletPersonalizationConfig represents applet-specific configuration
type AppletPersonalizationConfig struct {
	// Package and applet AIDs
	PackageAID  string `json:"package_aid"`
	ClassAID    string `json:"class_aid"`
	InstanceAID string `json:"instance_aid"`
	
	// Target Security Domain AID (optional, default ISD)
	SecurityDomainAID string `json:"sd_aid,omitempty"`
	
	// Personalization APDUs in hex format
	APDUs []string `json:"apdus,omitempty"`
	
	// Or use structured config for known applet types
	MilenageUSIM *MilenageUSIMAppletConfig `json:"milenage_usim,omitempty"`
}

// MilenageUSIMAppletConfig represents Milenage USIM applet configuration
type MilenageUSIMAppletConfig struct {
	Ki  string `json:"ki"`
	OPc string `json:"opc,omitempty"`
	OP  string `json:"op,omitempty"`
	AMF string `json:"amf,omitempty"` // Default: "8000"
	SQN string `json:"sqn,omitempty"` // Initial SQN (optional)
}

// BuildProfile builds a new profile from template and configuration
func BuildProfile(template *Profile, config *BuildConfig) (*Profile, error) {
	// Clone template
	profile, err := template.Clone()
	if err != nil {
		return nil, fmt.Errorf("clone template: %w", err)
	}

	// Set ICCID
	if config.ICCID != "" {
		if err := profile.SetICCID(config.ICCID); err != nil {
			return nil, fmt.Errorf("set ICCID: %w", err)
		}
	}

	// Set IMSI
	if config.IMSI != "" {
		if err := profile.SetIMSI(config.IMSI); err != nil {
			return nil, fmt.Errorf("set IMSI: %w", err)
		}
	}

	// Set Ki
	if config.Ki != "" {
		ki, err := hex.DecodeString(config.Ki)
		if err != nil {
			return nil, fmt.Errorf("parse Ki: %w", err)
		}
		if err := profile.SetKi(ki); err != nil {
			return nil, fmt.Errorf("set Ki: %w", err)
		}
	}

	// Set OPc
	if config.OPc != "" {
		opc, err := hex.DecodeString(config.OPc)
		if err != nil {
			return nil, fmt.Errorf("parse OPc: %w", err)
		}
		if err := profile.SetOPC(opc); err != nil {
			return nil, fmt.Errorf("set OPc: %w", err)
		}
	}

	// Set ISIM parameters
	if config.IMPI != "" || len(config.IMPU) > 0 || config.Domain != "" {
		if err := setISIMParams(profile, config); err != nil {
			return nil, fmt.Errorf("set ISIM params: %w", err)
		}
	}

	// Set security codes
	if err := setSecurityCodes(profile, config); err != nil {
		return nil, fmt.Errorf("set security codes: %w", err)
	}

	// Set profile type
	if config.ProfileType != "" && profile.Header != nil {
		profile.Header.ProfileType = config.ProfileType
	}

	// Set algorithm ID
	if config.AlgorithmID > 0 {
		if len(profile.AKAParams) > 0 && profile.AKAParams[0].AlgoConfig != nil {
			profile.AKAParams[0].AlgoConfig.AlgorithmID = AlgorithmID(config.AlgorithmID)
		}
	}

	// Handle applet authentication delegation
	if config.UseAppletAuth {
		if len(profile.AKAParams) > 0 && profile.AKAParams[0].AlgoConfig != nil {
			profile.AKAParams[0].AlgoConfig.AlgorithmID = AlgoUSIMTestAlgorithm
		}
	}

	// Add applet if CAP file specified
	if config.AppletCAP != "" {
		if err := addAppletToProfile(profile, config); err != nil {
			return nil, fmt.Errorf("add applet: %w", err)
		}
	}

	return profile, nil
}

func setISIMParams(profile *Profile, config *BuildConfig) error {
	if profile.ISIM == nil {
		return fmt.Errorf("ISIM application not found in template")
	}

	// Set IMPI
	if config.IMPI != "" && profile.ISIM.EF_IMPI != nil {
		impiBytes := encodeIMPI(config.IMPI)
		if len(profile.ISIM.EF_IMPI.FillContents) > 0 {
			profile.ISIM.EF_IMPI.FillContents[0].Content = impiBytes
		} else {
			profile.ISIM.EF_IMPI.FillContents = append(profile.ISIM.EF_IMPI.FillContents, FillContent{
				Content: impiBytes,
			})
		}
	}

	// Set IMPU
	if len(config.IMPU) > 0 && profile.ISIM.EF_IMPU != nil {
		impuBytes := encodeIMPUList(config.IMPU)
		if len(profile.ISIM.EF_IMPU.FillContents) > 0 {
			profile.ISIM.EF_IMPU.FillContents[0].Content = impuBytes
		} else {
			profile.ISIM.EF_IMPU.FillContents = append(profile.ISIM.EF_IMPU.FillContents, FillContent{
				Content: impuBytes,
			})
		}
	}

	// Set Domain
	if config.Domain != "" && profile.ISIM.EF_DOMAIN != nil {
		domainBytes := encodeDomain(config.Domain)
		if len(profile.ISIM.EF_DOMAIN.FillContents) > 0 {
			profile.ISIM.EF_DOMAIN.FillContents[0].Content = domainBytes
		} else {
			profile.ISIM.EF_DOMAIN.FillContents = append(profile.ISIM.EF_DOMAIN.FillContents, FillContent{
				Content: domainBytes,
			})
		}
	}

	return nil
}

func setSecurityCodes(profile *Profile, config *BuildConfig) error {
	// Set PIN1
	if config.PIN1 != "" {
		if err := setPIN(profile, 0x01, config.PIN1); err != nil {
			return fmt.Errorf("set PIN1: %w", err)
		}
	}

	// Set PIN2
	if config.PIN2 != "" {
		if err := setPIN(profile, 0x81, config.PIN2); err != nil {
			return fmt.Errorf("set PIN2: %w", err)
		}
	}

	// Set PUK1
	if config.PUK1 != "" {
		if err := setPUK(profile, 0x01, config.PUK1); err != nil {
			return fmt.Errorf("set PUK1: %w", err)
		}
	}

	// Set PUK2
	if config.PUK2 != "" {
		if err := setPUK(profile, 0x81, config.PUK2); err != nil {
			return fmt.Errorf("set PUK2: %w", err)
		}
	}

	// Set ADM1
	if config.ADM1 != "" {
		if err := setPIN(profile, 0x0A, config.ADM1); err != nil {
			return fmt.Errorf("set ADM1: %w", err)
		}
	}

	return nil
}

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

func addAppletToProfile(profile *Profile, config *BuildConfig) error {
	// Read CAP file
	capData, err := os.ReadFile(config.AppletCAP)
	if err != nil {
		return fmt.Errorf("read CAP file: %w", err)
	}

	appConfig := config.AppletConfig
	if appConfig == nil {
		return fmt.Errorf("applet_config is required when applet_cap is specified")
	}

	// Parse AIDs
	packageAID, err := hex.DecodeString(strings.ReplaceAll(appConfig.PackageAID, ":", ""))
	if err != nil {
		return fmt.Errorf("parse package AID: %w", err)
	}

	classAID, err := hex.DecodeString(strings.ReplaceAll(appConfig.ClassAID, ":", ""))
	if err != nil {
		return fmt.Errorf("parse class AID: %w", err)
	}

	instanceAID, err := hex.DecodeString(strings.ReplaceAll(appConfig.InstanceAID, ":", ""))
	if err != nil {
		return fmt.Errorf("parse instance AID: %w", err)
	}

	var sdAID []byte
	if appConfig.SecurityDomainAID != "" {
		sdAID, err = hex.DecodeString(strings.ReplaceAll(appConfig.SecurityDomainAID, ":", ""))
		if err != nil {
			return fmt.Errorf("parse SD AID: %w", err)
		}
	}

	// Build ProcessData APDUs
	var processData [][]byte
	
	// Use explicit APDUs if provided
	if len(appConfig.APDUs) > 0 {
		for _, apduHex := range appConfig.APDUs {
			apdu, err := hex.DecodeString(strings.ReplaceAll(apduHex, " ", ""))
			if err != nil {
				return fmt.Errorf("parse APDU: %w", err)
			}
			processData = append(processData, apdu)
		}
	}

	// Or build from structured config
	if appConfig.MilenageUSIM != nil {
		apdus, err := buildMilenageUSIMAPDUs(appConfig.MilenageUSIM)
		if err != nil {
			return fmt.Errorf("build Milenage APDUs: %w", err)
		}
		processData = append(processData, apdus...)
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
				LifeCycleState:              0x07,                      // Selectable
				ApplicationSpecificParamsC9: []byte{0x81, 0x00},       // Default C9
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

func buildMilenageUSIMAPDUs(cfg *MilenageUSIMAppletConfig) ([][]byte, error) {
	var apdus [][]byte

	// Parse Ki
	ki, err := hex.DecodeString(cfg.Ki)
	if err != nil {
		return nil, fmt.Errorf("parse Ki: %w", err)
	}
	if len(ki) != 16 {
		return nil, fmt.Errorf("Ki must be 16 bytes, got %d", len(ki))
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

	// APDU 1: Store Ki
	// Tag 01 = Ki
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

	// APDU 3: Store AMF
	amfAPDU := []byte{0x80, 0xE2, 0x00, 0x00}
	amfData := append([]byte{0x04, byte(len(amf))}, amf...)
	amfAPDU = append(amfAPDU, byte(len(amfData)))
	amfAPDU = append(amfAPDU, amfData...)
	apdus = append(apdus, amfAPDU)

	// APDU 4: Store SQN if provided
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

