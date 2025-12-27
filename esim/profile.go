package esim

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// LoadProfile loads profile from DER file
func LoadProfile(filename string) (*Profile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return DecodeProfile(data)
}

// SaveProfile saves profile to DER file
func SaveProfile(p *Profile, filename string) error {
	data, err := EncodeProfile(p)
	if err != nil {
		return fmt.Errorf("encode profile: %w", err)
	}
	return os.WriteFile(filename, data, 0644)
}

// GetICCID returns ICCID in readable format
func (p *Profile) GetICCID() string {
	if p.Header != nil && len(p.Header.ICCID) > 0 {
		return decodeSwappedBCD(p.Header.ICCID)
	}
	return ""
}

// GetIMSI returns IMSI from USIM
func (p *Profile) GetIMSI() string {
	if p.USIM != nil && p.USIM.EF_IMSI != nil && len(p.USIM.EF_IMSI.FillContents) > 0 {
		return decodeIMSI(p.USIM.EF_IMSI.FillContents[0].Content)
	}
	return ""
}

// GetProfileType returns profile type
func (p *Profile) GetProfileType() string {
	if p.Header != nil {
		return p.Header.ProfileType
	}
	return ""
}

// GetVersion returns profile version
func (p *Profile) GetVersion() (major, minor int) {
	if p.Header != nil {
		return p.Header.MajorVersion, p.Header.MinorVersion
	}
	return 0, 0
}

// GetKi returns Ki key from first AKA parameter
func (p *Profile) GetKi() []byte {
	if len(p.AKAParams) > 0 && p.AKAParams[0].AlgoConfig != nil {
		return copyBytes(p.AKAParams[0].AlgoConfig.Key)
	}
	return nil
}

// GetOPC returns OPc from first AKA parameter
func (p *Profile) GetOPC() []byte {
	if len(p.AKAParams) > 0 && p.AKAParams[0].AlgoConfig != nil {
		return copyBytes(p.AKAParams[0].AlgoConfig.OPC)
	}
	return nil
}

// GetAlgorithmID returns authentication algorithm ID
func (p *Profile) GetAlgorithmID() AlgorithmID {
	if len(p.AKAParams) > 0 && p.AKAParams[0].AlgoConfig != nil {
		return p.AKAParams[0].AlgoConfig.AlgorithmID
	}
	return 0
}

// GetAlgorithmName returns authentication algorithm name
func (p *Profile) GetAlgorithmName() string {
	switch p.GetAlgorithmID() {
	case AlgoMilenage:
		return "Milenage"
	case AlgoTUAK:
		return "TUAK"
	case AlgoUSIMTestAlgorithm:
		return "USIM Test Algorithm"
	default:
		return "Unknown"
	}
}

// GetUSIMAID returns USIM application AID
func (p *Profile) GetUSIMAID() []byte {
	if p.USIM != nil && p.USIM.ADFUSIM != nil {
		return copyBytes(p.USIM.ADFUSIM.DFName)
	}
	return nil
}

// GetISIMAID returns ISIM application AID
func (p *Profile) GetISIMAID() []byte {
	if p.ISIM != nil && p.ISIM.ADFISIM != nil {
		return copyBytes(p.ISIM.ADFISIM.DFName)
	}
	return nil
}

// HasUSIM checks if USIM application is present
func (p *Profile) HasUSIM() bool {
	return p.USIM != nil
}

// HasISIM checks if ISIM application is present
func (p *Profile) HasISIM() bool {
	return p.ISIM != nil
}

// HasCSIM checks if CSIM application is present
func (p *Profile) HasCSIM() bool {
	return p.CSIM != nil
}

// GetPIN1 returns PIN1 value
func (p *Profile) GetPIN1() string {
	for _, pc := range p.PinCodes {
		for _, config := range pc.Configs {
			if config.KeyReference == 0x01 { // PIN1
				return decodePINValue(config.PINValue)
			}
		}
	}
	return ""
}

// GetPIN2 returns PIN2 value
func (p *Profile) GetPIN2() string {
	for _, pc := range p.PinCodes {
		for _, config := range pc.Configs {
			if config.KeyReference == 0x81 { // PIN2
				return decodePINValue(config.PINValue)
			}
		}
	}
	return ""
}

// GetPUK1 returns PUK1 value
func (p *Profile) GetPUK1() string {
	if p.PukCodes != nil {
		for _, code := range p.PukCodes.Codes {
			if code.KeyReference == 0x01 { // PUK1
				return decodePINValue(code.PUKValue)
			}
		}
	}
	return ""
}

// GetPUK2 returns PUK2 value
func (p *Profile) GetPUK2() string {
	if p.PukCodes != nil {
		for _, code := range p.PukCodes.Codes {
			if code.KeyReference == 0x81 { // PUK2
				return decodePINValue(code.PUKValue)
			}
		}
	}
	return ""
}

// GetADM1 returns ADM1 value
func (p *Profile) GetADM1() string {
	for _, pc := range p.PinCodes {
		for _, config := range pc.Configs {
			if config.KeyReference == 0x0A { // ADM1
				return decodePINValue(config.PINValue)
			}
		}
	}
	return ""
}

// decodePINValue decodes PIN/PUK value from bytes
func decodePINValue(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= '0' && b <= '9' {
			result.WriteByte(b)
		} else if b == 0xFF {
			break
		}
	}
	return result.String()
}

// String returns brief profile description
func (p *Profile) String() string {
	major, minor := p.GetVersion()
	return fmt.Sprintf("Profile{ICCID: %s, IMSI: %s, Type: %s, Version: %d.%d, Algo: %s}",
		p.GetICCID(),
		p.GetIMSI(),
		p.GetProfileType(),
		major,
		minor,
		p.GetAlgorithmName(),
	)
}

// Summary returns detailed profile information
func (p *Profile) Summary() string {
	var sb strings.Builder

	sb.WriteString("=== eSIM Profile Summary ===\n\n")

	// Header info
	if p.Header != nil {
		major, minor := p.GetVersion()
		sb.WriteString(fmt.Sprintf("Version:      %d.%d\n", major, minor))
		sb.WriteString(fmt.Sprintf("Profile Type: %s\n", p.GetProfileType()))
		sb.WriteString(fmt.Sprintf("ICCID:        %s\n", p.GetICCID()))
	}

	sb.WriteString("\n--- Applications ---\n")
	sb.WriteString(fmt.Sprintf("USIM: %v\n", p.HasUSIM()))
	sb.WriteString(fmt.Sprintf("ISIM: %v\n", p.HasISIM()))
	sb.WriteString(fmt.Sprintf("CSIM: %v\n", p.HasCSIM()))

	// USIM info
	if p.HasUSIM() {
		sb.WriteString("\n--- USIM ---\n")
		sb.WriteString(fmt.Sprintf("IMSI: %s\n", p.GetIMSI()))
		if aid := p.GetUSIMAID(); len(aid) > 0 {
			sb.WriteString(fmt.Sprintf("AID:  %s\n", hex.EncodeToString(aid)))
		}
	}

	// ISIM info
	if p.HasISIM() {
		sb.WriteString("\n--- ISIM ---\n")
		if aid := p.GetISIMAID(); len(aid) > 0 {
			sb.WriteString(fmt.Sprintf("AID:  %s\n", hex.EncodeToString(aid)))
		}
	}

	// Authentication
	if len(p.AKAParams) > 0 {
		sb.WriteString("\n--- Authentication ---\n")
		sb.WriteString(fmt.Sprintf("Algorithm: %s\n", p.GetAlgorithmName()))
		if ki := p.GetKi(); len(ki) > 0 {
			sb.WriteString(fmt.Sprintf("Ki:        %s\n", hex.EncodeToString(ki)))
		}
		if opc := p.GetOPC(); len(opc) > 0 {
			sb.WriteString(fmt.Sprintf("OPc:       %s\n", hex.EncodeToString(opc)))
		}
	}

	// PIN/PUK
	sb.WriteString("\n--- PIN/PUK ---\n")
	if pin1 := p.GetPIN1(); pin1 != "" {
		sb.WriteString(fmt.Sprintf("PIN1: %s\n", pin1))
	}
	if puk1 := p.GetPUK1(); puk1 != "" {
		sb.WriteString(fmt.Sprintf("PUK1: %s\n", puk1))
	}
	if adm1 := p.GetADM1(); adm1 != "" {
		sb.WriteString(fmt.Sprintf("ADM1: %s\n", adm1))
	}

	// Security Domains
	if len(p.SecurityDomains) > 0 {
		sb.WriteString("\n--- Security Domains ---\n")
		for i, sd := range p.SecurityDomains {
			if sd.Instance != nil {
				sb.WriteString(fmt.Sprintf("SD[%d] AID: %s\n", i, hex.EncodeToString(sd.Instance.InstanceAID)))
			}
		}
	}

	// RFM
	if len(p.RFM) > 0 {
		sb.WriteString("\n--- RFM Configurations ---\n")
		for i, rfm := range p.RFM {
			sb.WriteString(fmt.Sprintf("RFM[%d] AID: %s\n", i, hex.EncodeToString(rfm.InstanceAID)))
			for j, tar := range rfm.TARList {
				sb.WriteString(fmt.Sprintf("  TAR[%d]: %s\n", j, hex.EncodeToString(tar)))
			}
		}
	}

	// Elements count
	sb.WriteString(fmt.Sprintf("\n--- Profile Elements: %d ---\n", len(p.Elements)))
	for _, elem := range p.Elements {
		sb.WriteString(fmt.Sprintf("  [%2d] %s\n", elem.Tag, GetProfileElementName(elem.Tag)))
	}

	return sb.String()
}

// SetIMSI sets new IMSI in profile
func (p *Profile) SetIMSI(imsi string) error {
	if p.USIM == nil {
		return fmt.Errorf("USIM application not found")
	}
	if p.USIM.EF_IMSI == nil {
		p.USIM.EF_IMSI = &ElementaryFile{
			FillContents: make([]FillContent, 0),
		}
	}

	encoded := encodeIMSI(imsi)
	if len(p.USIM.EF_IMSI.FillContents) == 0 {
		p.USIM.EF_IMSI.FillContents = append(p.USIM.EF_IMSI.FillContents, FillContent{
			Offset:  0,
			Content: encoded,
		})
	} else {
		p.USIM.EF_IMSI.FillContents[0].Content = encoded
	}

	return nil
}

// SetKi sets new Ki in first AKA parameter
func (p *Profile) SetKi(ki []byte) error {
	if len(p.AKAParams) == 0 {
		return fmt.Errorf("AKA parameters not found")
	}
	if p.AKAParams[0].AlgoConfig == nil {
		p.AKAParams[0].AlgoConfig = &AlgoConfiguration{}
	}
	p.AKAParams[0].AlgoConfig.Key = copyBytes(ki)
	return nil
}

// SetOPC sets new OPc in first AKA parameter
func (p *Profile) SetOPC(opc []byte) error {
	if len(p.AKAParams) == 0 {
		return fmt.Errorf("AKA parameters not found")
	}
	if p.AKAParams[0].AlgoConfig == nil {
		p.AKAParams[0].AlgoConfig = &AlgoConfiguration{}
	}
	p.AKAParams[0].AlgoConfig.OPC = copyBytes(opc)
	return nil
}

// SetICCID sets new ICCID
func (p *Profile) SetICCID(iccid string) error {
	if p.Header == nil {
		return fmt.Errorf("profile header not found")
	}

	// Remove non-digits
	var digits strings.Builder
	for _, r := range iccid {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}

	p.Header.ICCID = encodeSwappedBCD(digits.String())

	// Also update EF.ICCID if present
	if p.MF != nil && p.MF.EF_ICCID != nil {
		if len(p.MF.EF_ICCID.FillContents) > 0 {
			p.MF.EF_ICCID.FillContents[0].Content = p.Header.ICCID
		}
	}

	return nil
}

// Clone creates a deep copy of profile
func (p *Profile) Clone() (*Profile, error) {
	// Serialize and deserialize for deep copy
	data, err := EncodeProfile(p)
	if err != nil {
		return nil, err
	}
	return DecodeProfile(data)
}
