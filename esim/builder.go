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
		var err error
		if config.ICCIDPreserveChecksum {
			// Use raw ICCID without Luhn recalculation
			err = profile.SetICCIDRaw(config.ICCID)
		} else {
			// Automatically fix Luhn checksum
			err = profile.SetICCID(config.ICCID)
		}
		if err != nil {
			return fmt.Errorf("set ICCID: %w", err)
		}
	}

	// Set IMSI
	if config.IMSI != "" {
		if err := profile.SetIMSI(config.IMSI); err != nil {
			return fmt.Errorf("set IMSI: %w", err)
		}
	}

	// Set Ki and OPc - check applet keys first, then fallback to root config
	var kiSource, opcSource string

	if config.UseAppletAuth {
		// Try to get keys from applet personalization config
		appletKeys := findAppletMilenageKeys(config)
		if appletKeys != nil {
			kiSource = appletKeys.Ki
			opcSource = appletKeys.OPc
		}
	}

	// Fallback to root config keys if applet keys not found
	if kiSource == "" && config.Ki != "" {
		kiSource = config.Ki
	}
	if opcSource == "" && config.OPc != "" {
		opcSource = config.OPc
	}

	// Apply Ki
	if kiSource != "" {
		ki, err := hex.DecodeString(kiSource)
		if err != nil {
			return fmt.Errorf("parse Ki: %w", err)
		}
		if err := profile.SetKi(ki); err != nil {
			return fmt.Errorf("set Ki: %w", err)
		}
	}

	// Apply OPc
	if opcSource != "" {
		opc, err := hex.DecodeString(opcSource)
		if err != nil {
			return fmt.Errorf("parse OPc: %w", err)
		}
		if err := profile.SetOPC(opc); err != nil {
			return fmt.Errorf("set OPc: %w", err)
		}
	}

	// Set algorithm ID and update MandatoryServices accordingly
	if config.AlgorithmID > 0 || config.UseAppletAuth {
		algoID := AlgorithmID(config.AlgorithmID)
		if algoID == 0 {
			algoID = AlgoMilenage // Default to Milenage
		}

		for _, aka := range profile.AKAParams {
			if aka.AlgoConfig != nil {
				aka.AlgoConfig.AlgorithmID = algoID
				// Match reference profile usim-applet.txt options ('00'H)
				aka.AlgoConfig.AlgorithmOptions = 0x00

				// If switching to pure Milenage, clear TUAK-specific parameters
				if algoID == AlgoMilenage {
					// For Milenage, use standard rotation constants (r1-r5)
					// Default: r1=64, r2=0, r3=32, r4=64, r5=96 bits
					aka.AlgoConfig.RotationConstants = []byte{0x40, 0x00, 0x20, 0x40, 0x60}
					// Clear TUAK-specific xoring constants - use Milenage c1-c5 defaults
					aka.AlgoConfig.XoringConstants = nil
					// Clear numberOfKeccak (TUAK only)
					aka.AlgoConfig.NumberOfKeccak = nil
				}
			}
		}
		profile.invalidate(TagAKAParameter)

		// Update MandatoryServices to match algorithm
		if profile.Header != nil && profile.Header.MandatoryServices != nil {
			ms := profile.Header.MandatoryServices
			// Clear all algorithm flags first
			ms.Milenage = false
			ms.TUAK128 = false
			ms.TUAK256 = false
			ms.USIMTestAlgorithm = false

			if config.UseAppletAuth {
				// If applet auth is used, GSMA recommends setting USIMTestAlgorithm=true
				// while actual algorithm in akaParameter can still be milenage
				ms.USIMTestAlgorithm = true
			} else {
				// Set the appropriate flag for native algorithm
				switch algoID {
				case AlgoMilenage:
					ms.Milenage = true
				case AlgoTUAK:
					ms.TUAK128 = true // TUAK with 128-bit key
				case AlgoUSIMTestAlgorithm:
					ms.USIMTestAlgorithm = true
				}
			}
			profile.invalidate(TagProfileHeader)
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

	// Handle SkipUSIM - remove PE-USIM and related elements for applet-only profile
	if config.SkipUSIM {
		if err := removeUSIMElements(profile); err != nil {
			return fmt.Errorf("remove USIM elements: %w", err)
		}
	} else {
		// Count akaParameter elements first
		akaTotal := 0
		for _, elem := range profile.Elements {
			if elem.Tag == TagAKAParameter {
				akaTotal++
			}
		}

		// Cleanup for Variant 2 (USIM + Applet):
		// Some templates (like TS48v5) have TWO akaParameter elements.
		// Reference profile usim-applet.txt has only ONE.
		// Remove the first akaParameter only if there are multiple.
		if akaTotal > 1 {
			newElements := make([]ProfileElement, 0, len(profile.Elements))
			akaCount := 0
			for _, elem := range profile.Elements {
				if elem.Tag == TagAKAParameter {
					akaCount++
					if akaCount == 1 {
						// Skip the first akaParameter
						continue
					}
				}
				newElements = append(newElements, elem)
			}
			profile.Elements = newElements
			profile.UpdateReferences()
		}
	}

	// Add applets from GlobalPlatform config
	if config.GlobalPlatform != nil && config.GlobalPlatform.Applets != nil {
		for _, appletCfg := range config.GlobalPlatform.Applets.Loads {
			if appletCfg.UseForESIM {
				if err := addAppletFromGPConfig(profile, &appletCfg); err != nil {
					return fmt.Errorf("add applet %s: %w", appletCfg.PackageAID, err)
				}

				// Override USIM dfName with applet's instance AID if requested
				if appletCfg.OverrideUSIMDfName && !config.SkipUSIM {
					instanceAID, err := hex.DecodeString(appletCfg.InstanceAID)
					if err != nil {
						return fmt.Errorf("parse instance AID for dfName override: %w", err)
					}
					if err := overrideUSIMDfName(profile, instanceAID); err != nil {
						return fmt.Errorf("override USIM dfName: %w", err)
					}
				}
			}
		}
	}

	// Renumbering removed to preserve template IDs for tests
	for i := range profile.Elements {
		// CRITICAL: Invalidate template cache for THIS element to force re-encoding
		profile.Elements[i].RawBytes = nil
	}

	return nil
}

// removeUSIMElements removes PE-USIM, PE-OptUSIM, PE-AKAParameter from profile
// for Variant 1 (applet-only) profiles
func removeUSIMElements(profile *Profile) error {
	// Tags to remove
	tagsToRemove := map[int]bool{
		TagUSIM:         true,
		TagOptUSIM:      true,
		TagAKAParameter: true,
	}

	// Filter out USIM-related elements
	newElements := make([]ProfileElement, 0, len(profile.Elements))
	for _, elem := range profile.Elements {
		if !tagsToRemove[elem.Tag] {
			newElements = append(newElements, elem)
		}
	}
	profile.Elements = newElements

	// Clear typed slices
	profile.USIM = nil
	profile.AKAParams = nil

	// Update header mandatory services - no USIM-related flags
	if profile.Header != nil && profile.Header.MandatoryServices != nil {
		profile.Header.MandatoryServices.Milenage = false
		profile.Header.MandatoryServices.TUAK128 = false
		profile.Header.MandatoryServices.TUAK256 = false
		profile.Header.MandatoryServices.USIMTestAlgorithm = false
		profile.invalidate(TagProfileHeader)
	}

	return nil
}

// overrideUSIMDfName sets PE-USIM.adf-usim.dfName to the applet's instance AID
// This makes SELECT(USIM AID) route to the applet instead of native USIM
func overrideUSIMDfName(profile *Profile, instanceAID []byte) error {
	if profile.USIM == nil {
		return nil // No USIM to override
	}

	// Find and update DFName in USIM ADF descriptor
	if profile.USIM.ADFUSIM != nil {
		profile.USIM.ADFUSIM.DFName = instanceAID
		profile.invalidate(TagUSIM)
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
		updateEFContent(profile.ISIM.EF_IMPI, impiBytes)
	}

	// Set IMPU
	if len(isim.IMPU) > 0 && profile.ISIM.EF_IMPU != nil {
		impuBytes := encodeIMPUList(isim.IMPU)
		updateEFContent(profile.ISIM.EF_IMPU, impuBytes)
	}

	// Set Domain
	if isim.Domain != "" && profile.ISIM.EF_DOMAIN != nil {
		domainBytes := encodeDomain(isim.Domain)
		updateEFContent(profile.ISIM.EF_DOMAIN, domainBytes)
	}

	profile.invalidate(TagISIM)
	return nil
}

// updateEFContent updates EF content and adjusts file size if needed
func updateEFContent(ef *ElementaryFile, content []byte) {
	// Update content
	if len(ef.FillContents) > 0 {
		ef.FillContents[0].Content = content
	} else {
		ef.FillContents = append(ef.FillContents, FillContent{
			Content: content,
		})
	}
	ef.Raw = nil

	// Update file size in descriptor if content is larger than current size
	if ef.Descriptor != nil {
		currentSize := decodeEFFileSize(ef.Descriptor.EFFileSize)
		newSize := len(content)

		if newSize > currentSize {
			// Encode new size (round up to next 16-byte boundary for alignment)
			alignedSize := ((newSize + 15) / 16) * 16
			ef.Descriptor.EFFileSize = encodeEFFileSize(alignedSize)
		}
	}
}

// decodeEFFileSize decodes file size from bytes
func decodeEFFileSize(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	size := 0
	for _, b := range data {
		size = size*256 + int(b)
	}
	return size
}

// encodeEFFileSize encodes file size to minimal bytes
func encodeEFFileSize(size int) []byte {
	if size == 0 {
		return nil
	}
	if size <= 0xFF {
		return []byte{byte(size)}
	}
	if size <= 0xFFFF {
		return []byte{byte(size >> 8), byte(size)}
	}
	return []byte{byte(size >> 16), byte(size >> 8), byte(size)}
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

	// Set ADM2
	if config.ADM2 != "" {
		if err := setPIN(profile, 0x0B, config.ADM2); err != nil {
			return fmt.Errorf("set ADM2: %w", err)
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

	// Convert CAP to IJC format if needed
	// Working eSIM profiles require IJC format (starts with DECAFFED), not ZIP/CAP
	ijcData, err := ConvertCAPToIJC(capData)
	if err != nil {
		return fmt.Errorf("convert CAP to IJC: %w", err)
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

	// Note: SecurityDomainAID is intentionally not used in loadBlock
	// Working eSIM profiles don't include it in PE-Application

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

	// Find insertion point for Application (specifically after SecurityDomain to match usim-applet.txt ID 24)
	insertIdx := -1
	for i, el := range profile.Elements {
		if el.Tag == TagSecurityDomain {
			insertIdx = i + 1
			break
		}
	}

	if insertIdx == -1 {
		// Fallback to before End
		for i, el := range profile.Elements {
			if el.Tag == TagEnd {
				insertIdx = i
				break
			}
		}
	}

	// Create Application element
	app := &Application{
		Header: &ElementHeader{
			Mandated: true,
		},
		LoadBlock: &ApplicationLoadPackage{
			LoadPackageAID: packageAID,
			// SecurityDomainAID is intentionally omitted - working profiles don't have it
			LoadBlockObject:        ijcData,                        // IJC format, not raw CAP
			NonVolatileCodeLimitC6: []byte{0x00, 0x01, 0x00, 0x00}, // 64KB NV code limit
			VolatileDataLimitC7:    []byte{0x10, 0x00},             // 4KB volatile data
			NonVolatileDataLimitC8: []byte{0x20, 0x00},             // 8KB NV data
		},
		InstanceList: []*ApplicationInstance{
			{
				ApplicationLoadPackageAID:   packageAID,
				ClassAID:                    classAID,
				InstanceAID:                 instanceAID,
				ApplicationPrivileges:       []byte{0x00},       // 1 byte, no privileges
				LifeCycleState:              0x07,               // Selectable
				ApplicationSpecificParamsC9: []byte{0xC9, 0x00}, // Matches working profile 'C900'H
				ProcessData:                 processData,
			},
		},
	}

	appElem := ProfileElement{
		Tag:   TagApplication,
		Value: app,
	}

	// Insert at calculated position
	if insertIdx >= 0 {
		profile.Elements = append(profile.Elements[:insertIdx],
			append([]ProfileElement{appElem}, profile.Elements[insertIdx:]...)...)
	} else {
		profile.Elements = append(profile.Elements, appElem)
	}

	// Add to profile.Applications list as well
	profile.Applications = append(profile.Applications, app)

	return nil
}

// buildMilenageAPDUs builds personalization APDUs for Milenage USIM applet.
// Uses INS_LOAD_KEYS (0x10) and INS_SET_SQN (0x11) commands compatible with
// MilenageUSIMApplet and USIMApplet from com.operator.milenage/usim packages.
//
// Command format:
//   - 80 10 00 Lc: K(16) + OPc(16) = 32 bytes (P1=00)
//   - 80 10 01 Lc: K(16) + OP(16) + AMF(2) = 34 bytes (P1=01)
//   - 80 10 02 09: IMSI(9) (P1=02)
//   - 80 11 00 06: SQN(6) (INS=11, SET_SQN)
func buildMilenageAPDUs(cfg *sim.MilenageUSIMPersonalization) ([][]byte, error) {
	var apdus [][]byte

	// Parse Ki (required)
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

	// AMF default: 0x8000
	amf := []byte{0x80, 0x00}
	if cfg.AMF != "" {
		amf, err = hex.DecodeString(cfg.AMF)
		if err != nil {
			return nil, fmt.Errorf("parse AMF: %w", err)
		}
	}

	// Build APDUs using INS_LOAD_KEYS (0x10) format expected by MilenageUSIMApplet
	// CLA=80, INS=10, P1=command type, P2=00, Lc=data length, Data

	if useOP && len(opcOrOP) > 0 {
		// P1=01: K(16) + OP(16) + AMF(2) = 34 bytes
		data := make([]byte, 0, 34)
		data = append(data, ki...)
		data = append(data, opcOrOP...)
		data = append(data, amf...)
		apdu := []byte{0x80, 0x10, 0x01, 0x00, byte(len(data))}
		apdu = append(apdu, data...)
		apdus = append(apdus, apdu)
	} else if len(opcOrOP) > 0 {
		// P1=00: K(16) + OPc(16) = 32 bytes
		data := make([]byte, 0, 32)
		data = append(data, ki...)
		data = append(data, opcOrOP...)
		apdu := []byte{0x80, 0x10, 0x00, 0x00, byte(len(data))}
		apdu = append(apdu, data...)
		apdus = append(apdus, apdu)
	}

	// P1=02: IMSI(9) if provided
	if cfg.IMSI != "" {
		imsiBytes := encodeIMSIForApplet(cfg.IMSI)
		if len(imsiBytes) > 0 {
			apdu := []byte{0x80, 0x10, 0x02, 0x00, byte(len(imsiBytes))}
			apdu = append(apdu, imsiBytes...)
			apdus = append(apdus, apdu)
		}
	}

	// INS_SET_SQN (0x11): SQN(6) if provided
	if cfg.SQN != "" {
		sqn, err := hex.DecodeString(cfg.SQN)
		if err != nil {
			return nil, fmt.Errorf("parse SQN: %w", err)
		}
		if len(sqn) != 6 {
			return nil, fmt.Errorf("SQN must be 6 bytes, got %d", len(sqn))
		}
		apdu := []byte{0x80, 0x11, 0x00, 0x00, 0x06}
		apdu = append(apdu, sqn...)
		apdus = append(apdus, apdu)
	}

	return apdus, nil
}

// encodeIMSIForApplet encodes IMSI string to 9-byte format for applet personalization.
// Format: length byte + BCD-encoded IMSI (same as EF.IMSI content)
func encodeIMSIForApplet(imsi string) []byte {
	// Remove non-digits
	var digits []byte
	for _, c := range imsi {
		if c >= '0' && c <= '9' {
			digits = append(digits, byte(c-'0'))
		}
	}
	if len(digits) == 0 || len(digits) > 15 {
		return nil
	}

	// IMSI encoding: first byte is length, then BCD with first nibble = parity
	result := make([]byte, 9)
	result[0] = byte(len(digits))

	// First nibble: 9 (odd parity) or 1 (even parity) based on digit count
	if len(digits)%2 == 1 {
		result[1] = 0x09 | (digits[0] << 4)
	} else {
		result[1] = 0x01 | (digits[0] << 4)
	}

	// Pack remaining digits in BCD, two per byte, swapped nibbles
	idx := 1
	for i := 1; i < len(digits); i += 2 {
		idx++
		if idx >= 9 {
			break
		}
		if i+1 < len(digits) {
			result[idx] = digits[i] | (digits[i+1] << 4)
		} else {
			result[idx] = digits[i] | 0xF0
		}
	}

	return result
}

// ============================================================================
// Helper functions for encoding profile data
// ============================================================================

func setPIN(profile *Profile, keyRef byte, value string) error {
	encoded := encodePINValue(value)
	found := false

	// Update PIN value in ALL PinCodes elements (there may be multiple: MF, USIM, ISIM, etc.)
	for _, pc := range profile.PinCodes {
		for i := range pc.Configs {
			if pc.Configs[i].KeyReference == keyRef {
				pc.Configs[i].PINValue = encoded
				found = true
			}
		}
	}

	if !found {
		return fmt.Errorf("PIN with KeyReference 0x%02X not found", keyRef)
	}
	return nil
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

// getElementHeader extracts ElementHeader from different profile element types
func getElementHeader(elem ProfileElement) *ElementHeader {
	if elem.Value == nil {
		return nil
	}

	switch v := elem.Value.(type) {
	case *MasterFile:
		return v.MFHeader
	case MasterFile:
		return v.MFHeader
	case *PUKCodes:
		return v.Header
	case PUKCodes:
		return v.Header
	case *PINCodes:
		return v.Header
	case PINCodes:
		return v.Header
	case *TelecomDF:
		return v.Header
	case TelecomDF:
		return v.Header
	case *USIMApplication:
		return v.Header
	case USIMApplication:
		return v.Header
	case *OptionalUSIM:
		return v.Header
	case OptionalUSIM:
		return v.Header
	case *ISIMApplication:
		return v.Header
	case ISIMApplication:
		return v.Header
	case *OptionalISIM:
		return v.Header
	case OptionalISIM:
		return v.Header
	case *CSIMApplication:
		return v.Header
	case CSIMApplication:
		return v.Header
	case *OptionalCSIM:
		return v.Header
	case OptionalCSIM:
		return v.Header
	case *GSMAccessDF:
		return v.Header
	case GSMAccessDF:
		return v.Header
	case *DF5GS:
		return v.Header
	case DF5GS:
		return v.Header
	case *DFSAIP:
		return v.Header
	case DFSAIP:
		return v.Header
	case *AKAParameter:
		return v.Header
	case AKAParameter:
		return v.Header
	case *CDMAParameter:
		return v.Header
	case CDMAParameter:
		return v.Header
	case *SecurityDomain:
		return v.Header
	case SecurityDomain:
		return v.Header
	case *RFMConfig:
		return v.Header
	case RFMConfig:
		return v.Header
	case *Application:
		return v.Header
	case Application:
		return v.Header
	case *GenericFileManagement:
		return v.Header
	case GenericFileManagement:
		return v.Header
	case *EndElement:
		return v.Header
	case EndElement:
		return v.Header
	default:
		return nil
	}
}
