package esim

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
)

// GenerateValueNotation generates ASN.1 Value Notation text from Profile
func GenerateValueNotation(p *Profile) string {
	g := &Generator{
		sb:     &strings.Builder{},
		indent: 0,
	}
	g.generateProfile(p)
	return g.sb.String()
}

// GenerateValueNotationFile generates ASN.1 Value Notation and writes to file
func GenerateValueNotationFile(p *Profile, filename string) error {
	content := GenerateValueNotation(p)
	return os.WriteFile(filename, []byte(content), 0644)
}

// Generator generates ASN.1 Value Notation text
type Generator struct {
	sb       *strings.Builder
	indent   int
	valueNum int
}

func (g *Generator) write(s string) {
	g.sb.WriteString(s)
}

func (g *Generator) writeLine(s string) {
	g.writeIndent()
	g.sb.WriteString(s)
	g.sb.WriteString("\r\n")
}

func (g *Generator) writeIndent() {
	for i := 0; i < g.indent; i++ {
		g.sb.WriteString("  ")
	}
}

func (g *Generator) writeFields(fields []string) {
	for i, f := range fields {
		suffix := ""
		if i < len(fields)-1 {
			suffix = ","
		}
		g.writeLine(f + suffix)
	}
}

func (g *Generator) formatHex(b []byte) string {
	if b == nil {
		return "''H"
	}
	return fmt.Sprintf("'%s'H", strings.ToUpper(hex.EncodeToString(b)))
}

func (g *Generator) generateProfile(p *Profile) {
	for _, elem := range p.Elements {
		g.valueNum++
		g.generateProfileElement(&elem, g.valueNum)
	}
}

func (g *Generator) generateProfileElement(elem *ProfileElement, num int) {
	choiceName := getChoiceFromTag(elem.Tag)
	g.write(fmt.Sprintf("value%d ProfileElement ::= %s : ", num, choiceName))

	switch elem.Tag {
	case TagProfileHeader:
		g.generateProfileHeader(elem.Value.(*ProfileHeader))
	case TagMF:
		g.generateMasterFile(elem.Value.(*MasterFile))
	case TagPukCodes:
		g.generatePUKCodes(elem.Value.(*PUKCodes))
	case TagPinCodes:
		g.generatePINCodes(elem.Value.(*PINCodes))
	case TagTelecom:
		g.generateTelecom(elem.Value.(*TelecomDF))
	case TagUSIM:
		g.generateUSIM(elem.Value.(*USIMApplication))
	case TagOptUSIM:
		g.generateOptUSIM(elem.Value.(*OptionalUSIM))
	case TagISIM:
		g.generateISIM(elem.Value.(*ISIMApplication))
	case TagOptISIM:
		g.generateOptISIM(elem.Value.(*OptionalISIM))
	case TagCSIM:
		g.generateCSIM(elem.Value.(*CSIMApplication))
	case TagOptCSIM:
		g.generateOptCSIM(elem.Value.(*OptionalCSIM))
	case TagGSMAccess:
		g.generateGSMAccess(elem.Value.(*GSMAccessDF))
	case TagAKAParameter:
		g.generateAKAParameter(elem.Value.(*AKAParameter))
	case TagCDMAParameter:
		g.generateCDMAParameter(elem.Value.(*CDMAParameter))
	case TagDF5GS:
		g.generateDF5GS(elem.Value.(*DF5GS))
	case TagDFSAIP:
		g.generateDFSAIP(elem.Value.(*DFSAIP))
	case TagGenericFileManagement:
		g.generateGenericFileManagement(elem.Value.(*GenericFileManagement))
	case TagSecurityDomain:
		g.generateSecurityDomain(elem.Value.(*SecurityDomain))
	case TagRFM:
		g.generateRFM(elem.Value.(*RFMConfig))
	case TagApplication:
		g.generateApplication(elem.Value.(*Application))
	case TagEnd:
		g.generateEnd(elem.Value.(*EndElement))
	default:
		g.write("{\r\n}\r\n")
	}
}

func getChoiceFromTag(tag int) string {
	switch tag {
	case TagProfileHeader:
		return "header"
	case TagMF:
		return "mf"
	case TagPukCodes:
		return "pukCodes"
	case TagPinCodes:
		return "pinCodes"
	case TagTelecom:
		return "telecom"
	case TagUSIM:
		return "usim"
	case TagOptUSIM:
		return "opt-usim"
	case TagISIM:
		return "isim"
	case TagOptISIM:
		return "opt-isim"
	case TagCSIM:
		return "csim"
	case TagOptCSIM:
		return "opt-csim"
	case TagGSMAccess:
		return "gsm-access"
	case TagAKAParameter:
		return "akaParameter"
	case TagCDMAParameter:
		return "cdmaParameter"
	case TagDF5GS:
		return "df-5gs"
	case TagDFSAIP:
		return "df-saip"
	case TagGenericFileManagement:
		return "genericFileManagement"
	case TagSecurityDomain:
		return "securityDomain"
	case TagRFM:
		return "rfm"
	case TagApplication:
		return "application"
	case TagEnd:
		return "end"
	default:
		return fmt.Sprintf("unknown-%d", tag)
	}
}

// ============================================================================
// ProfileHeader generator
// ============================================================================

func (g *Generator) generateProfileHeader(h *ProfileHeader) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	fields = append(fields, fmt.Sprintf("major-version %d", h.MajorVersion))
	fields = append(fields, fmt.Sprintf("minor-version %d", h.MinorVersion))

	if h.ProfileType != "" {
		fields = append(fields, fmt.Sprintf("profileType \"%s\"", h.ProfileType))
	}

	if len(h.ICCID) > 0 {
		fields = append(fields, fmt.Sprintf("iccid %s", g.formatHex(h.ICCID)))
	}

	if len(h.POL) > 0 {
		fields = append(fields, fmt.Sprintf("pol %s", g.formatHex(h.POL)))
	}

	if h.MandatoryServices != nil {
		fields = append(fields, g.sgenerateMandatoryServices(h.MandatoryServices))
	}

	if len(h.MandatoryGFSTEList) > 0 {
		fields = append(fields, g.sgenerateOIDList("eUICC-Mandatory-GFSTEList", h.MandatoryGFSTEList))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateMandatoryServices(ms *MandatoryServices) string {
	var sb strings.Builder
	sb.WriteString("eUICC-Mandatory-services {\r\n")
	g.indent++

	fields := make([]string, 0)
	if ms.USIM {
		fields = append(fields, "usim NULL")
	}
	if ms.ISIM {
		fields = append(fields, "isim NULL")
	}
	if ms.CSIM {
		fields = append(fields, "csim NULL")
	}
	if ms.USIMTestAlgorithm {
		fields = append(fields, "usim-test-algorithm NULL")
	}
	if ms.BERTLV {
		fields = append(fields, "ber-tlv NULL")
	}
	if ms.GetIdentity {
		fields = append(fields, "get-identity NULL")
	}
	if ms.ProfileAX25519 {
		fields = append(fields, "profile-a-x25519 NULL")
	}
	if ms.ProfileBP256 {
		fields = append(fields, "profile-b-p256 NULL")
	}

	for i, f := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(f)
		if i < len(fields)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) sgenerateOIDList(name string, oids []OID) string {
	var sb strings.Builder
	sb.WriteString(name + " {\r\n")
	g.indent++

	for i, oid := range oids {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		parts := make([]string, len(oid))
		for j, n := range oid {
			parts[j] = fmt.Sprintf("%d", n)
		}
		sb.WriteString("{ " + strings.Join(parts, " ") + " }")
		if i < len(oids)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) generateOID(oid OID) string {
	parts := make([]string, len(oid))
	for i, n := range oid {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return "{ " + strings.Join(parts, " ") + " }"
}

// ============================================================================
// MasterFile generator
// ============================================================================

func (g *Generator) generateMasterFile(mf *MasterFile) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if mf.MFHeader != nil {
		fields = append(fields, g.sgenerateElementHeader("mf-header", mf.MFHeader))
	}

	if len(mf.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(mf.TemplateID)))
	}

	if mf.MF != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("mf", mf.MF))
	}

	if mf.EF_PL != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-pl", mf.EF_PL))
	}
	if mf.EF_ICCID != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-iccid", mf.EF_ICCID))
	}
	if mf.EF_DIR != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-dir", mf.EF_DIR))
	}
	if mf.EF_ARR != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-arr", mf.EF_ARR))
	}
	if mf.EF_UMPC != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-umpc", mf.EF_UMPC))
	}

	for _, ef := range mf.EFList {
		fields = append(fields, g.sgenerateElementaryFile("efList", ef))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateElementHeader(name string, eh *ElementHeader) string {
	var sb strings.Builder
	sb.WriteString(name + " {\r\n")
	g.indent++

	fields := make([]string, 0)
	if eh.Mandated {
		fields = append(fields, "mandated NULL")
	}
	fields = append(fields, fmt.Sprintf("identification %d", eh.Identification))

	for i, f := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(f)
		if i < len(fields)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) generateElementHeader(name string, eh *ElementHeader) {
	g.writeLine(g.sgenerateElementHeader(name, eh))
}

func (g *Generator) generateFileDescriptorWrapper(name string, fd *FileDescriptor) {
	g.writeLine(name + " {")
	g.indent++
	g.writeLine(g.sgenerateFileDescriptorInner("fileDescriptor", fd))
	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateFileDescriptorInner(name string, fd *FileDescriptor) string {
	var sb strings.Builder
	sb.WriteString(name + " : {\r\n")
	g.indent++

	fields := make([]string, 0)
	if len(fd.FileDescriptor) > 0 {
		fields = append(fields, fmt.Sprintf("fileDescriptor %s", g.formatHex(fd.FileDescriptor)))
	}
	if len(fd.FileID) > 0 {
		fields = append(fields, fmt.Sprintf("fileID %s", g.formatHex(fd.FileID)))
	}
	if len(fd.DFName) > 0 {
		fields = append(fields, fmt.Sprintf("dfName %s", g.formatHex(fd.DFName)))
	}
	if len(fd.LCSI) > 0 {
		fields = append(fields, fmt.Sprintf("lcsi %s", g.formatHex(fd.LCSI)))
	}
	if len(fd.SecurityAttributesReferenced) > 0 {
		fields = append(fields, fmt.Sprintf("securityAttributesReferenced %s", g.formatHex(fd.SecurityAttributesReferenced)))
	}
	if len(fd.EFFileSize) > 0 {
		fields = append(fields, fmt.Sprintf("efFileSize %s", g.formatHex(fd.EFFileSize)))
	}
	if fd.ShortEFID != nil {
		fields = append(fields, fmt.Sprintf("shortEFID %s", g.formatHex(fd.ShortEFID)))
	}
	if len(fd.PinStatusTemplateDO) > 0 {
		fields = append(fields, fmt.Sprintf("pinStatusTemplateDO %s", g.formatHex(fd.PinStatusTemplateDO)))
	}
	if len(fd.LinkPath) > 0 {
		fields = append(fields, fmt.Sprintf("linkPath %s", g.formatHex(fd.LinkPath)))
	}
	if fd.ProprietaryEFInfo != nil {
		fields = append(fields, g.sgenerateProprietaryEFInfo(fd.ProprietaryEFInfo))
	}

	for i, f := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(f)
		if i < len(fields)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) sgenerateProprietaryEFInfo(pei *ProprietaryEFInfo) string {
	var sb strings.Builder
	sb.WriteString("proprietaryEFInfo {\r\n")
	g.indent++

	fields := make([]string, 0)
	// Always print specialFileInformation if we have it
	if len(pei.SpecialFileInformation) > 0 {
		fields = append(fields, fmt.Sprintf("specialFileInformation %s", g.formatHex(pei.SpecialFileInformation)))
	}
	if len(pei.FillPattern) > 0 {
		fields = append(fields, fmt.Sprintf("fillPattern %s", g.formatHex(pei.FillPattern)))
	}
	if len(pei.RepeatPattern) > 0 {
		fields = append(fields, fmt.Sprintf("repeatPattern %s", g.formatHex(pei.RepeatPattern)))
	}
	if len(pei.MaximumFileSize) > 0 {
		fields = append(fields, fmt.Sprintf("maximumFileSize %s", g.formatHex(pei.MaximumFileSize)))
	}
	if len(pei.FileDetails) > 0 {
		fields = append(fields, fmt.Sprintf("fileDetails %s", g.formatHex(pei.FileDetails)))
	}

	for i, f := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(f)
		if i < len(fields)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) generateElementaryFile(name string, ef *ElementaryFile) {
	g.writeLine(name + " {")
	g.indent++

	fields := make([]string, 0)

	// Use Raw elements if available for exact round-trip
	if len(ef.Raw) > 0 {
		for _, elem := range ef.Raw {
			switch elem.Type {
			case FileElementDoNotCreate:
				fields = append(fields, "doNotCreate NULL")
			case FileElementDescriptor:
				if elem.Descriptor != nil {
					fields = append(fields, g.sgenerateFileDescriptorInner("fileDescriptor", elem.Descriptor))
				}
			case FileElementOffset:
				fields = append(fields, fmt.Sprintf("fillFileOffset : %d", elem.Offset))
			case FileElementContent:
				fields = append(fields, fmt.Sprintf("fillFileContent : %s", g.formatHex(elem.Content)))
			}
		}
	} else {
		// Fallback to simplified structure
		if ef.Descriptor != nil {
			fields = append(fields, g.sgenerateFileDescriptorInner("fileDescriptor", ef.Descriptor))
		}

		for _, fc := range ef.FillContents {
			if fc.Offset > 0 {
				fields = append(fields, fmt.Sprintf("fillFileOffset : %d", fc.Offset))
			}
			fields = append(fields, fmt.Sprintf("fillFileContent : %s", g.formatHex(fc.Content)))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// PUK/PIN Codes generator
// ============================================================================

func (g *Generator) generatePUKCodes(puk *PUKCodes) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if puk.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("puk-Header", puk.Header))
	}

	if len(puk.Codes) > 0 {
		var sb strings.Builder
		sb.WriteString("pukCodes {\r\n")
		g.indent++

		for i, code := range puk.Codes {
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString("{\r\n")
			g.indent++

			cfields := make([]string, 0)
			cfields = append(cfields, fmt.Sprintf("keyReference %s", g.getKeyRefName(code.KeyReference, true)))
			cfields = append(cfields, fmt.Sprintf("pukValue %s", g.formatHex(code.PUKValue)))
			cfields = append(cfields, fmt.Sprintf("maxNumOfAttemps-retryNumLeft %d", code.MaxNumOfAttempsRetryNumLeft))

			for j, f := range cfields {
				for k := 0; k < g.indent; k++ {
					sb.WriteString("  ")
				}
				sb.WriteString(f)
				if j < len(cfields)-1 {
					sb.WriteString(",")
				}
				sb.WriteString("\r\n")
			}

			g.indent--
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString("}")
			if i < len(puk.Codes)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\r\n")
		}

		g.indent--
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("}")
		fields = append(fields, sb.String())
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generatePINCodes(pin *PINCodes) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if pin.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("pin-Header", pin.Header))
	}

	if len(pin.Configs) > 0 {
		var sb strings.Builder
		sb.WriteString("pinCodes pinconfig : {\r\n")
		g.indent++

		for i, config := range pin.Configs {
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString("{\r\n")
			g.indent++

			cfields := make([]string, 0)
			cfields = append(cfields, fmt.Sprintf("keyReference %s", g.getKeyRefName(config.KeyReference, false)))
			cfields = append(cfields, fmt.Sprintf("pinValue %s", g.formatHex(config.PINValue)))
			if config.UnblockingPINReference != 0 {
				cfields = append(cfields, fmt.Sprintf("unblockingPINReference %s", g.getKeyRefName(config.UnblockingPINReference, true)))
			}
			cfields = append(cfields, fmt.Sprintf("pinAttributes %d", config.PINAttributes))
			cfields = append(cfields, fmt.Sprintf("maxNumOfAttemps-retryNumLeft %d", config.MaxNumOfAttempsRetryNumLeft))

			for j, f := range cfields {
				for k := 0; k < g.indent; k++ {
					sb.WriteString("  ")
				}
				sb.WriteString(f)
				if j < len(cfields)-1 {
					sb.WriteString(",")
				}
				sb.WriteString("\r\n")
			}

			g.indent--
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString("}")
			if i < len(pin.Configs)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\r\n")
		}

		g.indent--
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("}")
		fields = append(fields, sb.String())
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) getKeyRefName(ref byte, isPUK bool) string {
	if isPUK {
		switch ref {
		case 0x01:
			return "pukAppl1"
		case 0x81:
			return "secondPUKAppl1"
		}
	} else {
		switch ref {
		case 0x01:
			return "pinAppl1"
		case 0x81:
			return "secondPINAppl1"
		case 0x0A:
			return "adm1"
		case 0x0B:
			return "adm2"
		}
	}
	return fmt.Sprintf("0x%02X", ref)
}

// ============================================================================
// Telecom generator
// ============================================================================

func (g *Generator) generateTelecom(t *TelecomDF) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if t.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("telecom-header", t.Header))
	}

	if len(t.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(t.TemplateID)))
	}

	if t.DFTelecom != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-telecom", t.DFTelecom))
	}

	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-arr", t.EF_ARR},
		{"ef-sume", t.EF_SUME},
		{"ef-psismsc", t.EF_PSISMSC},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	if t.DFGraphics != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-graphics", t.DFGraphics))
	}
	if t.EF_IMG != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-img", t.EF_IMG))
	}
	if t.EF_LaunchSCWS != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-launch-scws", t.EF_LaunchSCWS))
	}
	if t.DFPhonebook != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-phonebook", t.DFPhonebook))
	}
	if t.EF_PBR != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-pbr", t.EF_PBR))
	}
	if t.EF_PSC != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-psc", t.EF_PSC))
	}
	if t.EF_CC != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-cc", t.EF_CC))
	}
	if t.EF_PUID != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-puid", t.EF_PUID))
	}
	if t.DFMMSS != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-mmss", t.DFMMSS))
	}
	if t.EF_MLPL != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-mlpl", t.EF_MLPL))
	}
	if t.EF_MSPL != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-mspl", t.EF_MSPL))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// USIM generator
// ============================================================================

func (g *Generator) generateUSIM(u *USIMApplication) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if u.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("usim-header", u.Header))
	}

	if len(u.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(u.TemplateID)))
	}

	if u.ADFUSIM != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("adf-usim", u.ADFUSIM))
	}

	// Generate all EF files
	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-imsi", u.EF_IMSI},
		{"ef-arr", u.EF_ARR},
		{"ef-keys", u.EF_Keys},
		{"ef-keysPS", u.EF_KeysPS},
		{"ef-hpplmn", u.EF_HPPLMN},
		{"ef-ust", u.EF_UST},
		{"ef-fdn", u.EF_FDN},
		{"ef-sms", u.EF_SMS},
		{"ef-smsp", u.EF_SMSP},
		{"ef-smss", u.EF_SMSS},
		{"ef-spn", u.EF_SPN},
		{"ef-est", u.EF_EST},
		{"ef-start-hfn", u.EF_StartHFN},
		{"ef-threshold", u.EF_Threshold},
		{"ef-psloci", u.EF_PSLOCI},
		{"ef-acc", u.EF_ACC},
		{"ef-fplmn", u.EF_FPLMN},
		{"ef-loci", u.EF_LOCI},
		{"ef-ad", u.EF_AD},
		{"ef-ecc", u.EF_ECC},
		{"ef-netpar", u.EF_NETPAR},
		{"ef-epsloci", u.EF_EPSLOCI},
		{"ef-epsnsc", u.EF_EPSNSC},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateFileDescriptorWrapper(name string, fd *FileDescriptor) string {
	var sb strings.Builder
	sb.WriteString(name + " {\r\n")
	g.indent++
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString(g.sgenerateFileDescriptorInner("fileDescriptor", fd))
	sb.WriteString("\r\n")
	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) sgenerateElementaryFile(name string, ef *ElementaryFile) string {
	var sb strings.Builder
	sb.WriteString(name + " {\r\n")
	g.indent++

	fields := make([]string, 0)

	// Use Raw elements if available for exact round-trip
	if len(ef.Raw) > 0 {
		for _, elem := range ef.Raw {
			switch elem.Type {
			case FileElementDoNotCreate:
				fields = append(fields, "doNotCreate NULL")
			case FileElementDescriptor:
				if elem.Descriptor != nil {
					fields = append(fields, g.sgenerateFileDescriptorInner("fileDescriptor", elem.Descriptor))
				}
			case FileElementOffset:
				fields = append(fields, fmt.Sprintf("fillFileOffset : %d", elem.Offset))
			case FileElementContent:
				fields = append(fields, fmt.Sprintf("fillFileContent : %s", g.formatHex(elem.Content)))
			}
		}
	} else {
		// Fallback to simplified structure
		if ef.Descriptor != nil {
			fields = append(fields, g.sgenerateFileDescriptorInner("fileDescriptor", ef.Descriptor))
		}

		for _, fc := range ef.FillContents {
			if fc.Offset > 0 {
				fields = append(fields, fmt.Sprintf("fillFileOffset : %d", fc.Offset))
			}
			fields = append(fields, fmt.Sprintf("fillFileContent : %s", g.formatHex(fc.Content)))
		}
	}

	for i, f := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(f)
		if i < len(fields)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) generateOptUSIM(u *OptionalUSIM) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if u.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("optusim-header", u.Header))
	}
	if len(u.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(u.TemplateID)))
	}

	// Generate all optional EF files
	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-li", u.EF_LI},
		{"ef-acmax", u.EF_ACMAX},
		{"ef-acm", u.EF_ACM},
		{"ef-gid1", u.EF_GID1},
		{"ef-gid2", u.EF_GID2},
		{"ef-msisdn", u.EF_MSISDN},
		{"ef-puct", u.EF_PUCT},
		{"ef-cbmi", u.EF_CBMI},
		{"ef-cbmid", u.EF_CBMID},
		{"ef-sdn", u.EF_SDN},
		{"ef-ext2", u.EF_EXT2},
		{"ef-ext3", u.EF_EXT3},
		{"ef-cbmir", u.EF_CBMIR},
		{"ef-plmnwact", u.EF_PLMNWACT},
		{"ef-oplmnwact", u.EF_OPLMNWACT},
		{"ef-hplmnwact", u.EF_HPLMNWACT},
		{"ef-dck", u.EF_DCK},
		{"ef-cnl", u.EF_CNL},
		{"ef-smsr", u.EF_SMSR},
		{"ef-bdn", u.EF_BDN},
		{"ef-ext5", u.EF_EXT5},
		{"ef-ccp2", u.EF_CCP2},
		{"ef-ext4", u.EF_EXT4},
		{"ef-acl", u.EF_ACL},
		{"ef-cmi", u.EF_CMI},
		{"ef-ici", u.EF_ICI},
		{"ef-oci", u.EF_OCI},
		{"ef-ict", u.EF_ICT},
		{"ef-oct", u.EF_OCT},
		{"ef-vgcs", u.EF_VGCS},
		{"ef-vgcss", u.EF_VGCSS},
		{"ef-vbs", u.EF_VBS},
		{"ef-vbss", u.EF_VBSS},
		{"ef-emlpp", u.EF_EMLPP},
		{"ef-aaem", u.EF_AAEM},
		{"ef-hiddenkey", u.EF_HIDDENKEY},
		{"ef-pnn", u.EF_PNN},
		{"ef-opl", u.EF_OPL},
		{"ef-mbdn", u.EF_MBDN},
		{"ef-ext6", u.EF_EXT6},
		{"ef-mbi", u.EF_MBI},
		{"ef-mwis", u.EF_MWIS},
		{"ef-cfis", u.EF_CFIS},
		{"ef-ext7", u.EF_EXT7},
		{"ef-spdi", u.EF_SPDI},
		{"ef-mmsn", u.EF_MMSN},
		{"ef-ext8", u.EF_EXT8},
		{"ef-mmsicp", u.EF_MMSICP},
		{"ef-mmsup", u.EF_MMSUP},
		{"ef-mmsucp", u.EF_MMSUCP},
		{"ef-nia", u.EF_NIA},
		{"ef-vgcsca", u.EF_VGCSCA},
		{"ef-vbsca", u.EF_VBSCA},
		{"ef-gbabp", u.EF_GBABP},
		{"ef-msk", u.EF_MSK},
		{"ef-muk", u.EF_MUK},
		{"ef-ehplmn", u.EF_EHPLMN},
		{"ef-gbanl", u.EF_GBANL},
		{"ef-ehplmnpi", u.EF_EHPLMNPI},
		{"ef-lrplmnsi", u.EF_LRPLMNSI},
		{"ef-nafkca", u.EF_NAFKCA},
		{"ef-spni", u.EF_SPNI},
		{"ef-pnni", u.EF_PNNI},
		{"ef-ncp-ip", u.EF_NCP_IP},
		{"ef-ufc", u.EF_UFC},
		{"ef-nasconfig", u.EF_NASCONFIG},
		{"ef-uicciari", u.EF_UICCIARI},
		{"ef-pws", u.EF_PWS},
		{"ef-fdnuri", u.EF_FDNURI},
		{"ef-bdnuri", u.EF_BDNURI},
		{"ef-sdnuri", u.EF_SDNURI},
		{"ef-ial", u.EF_IAL},
		{"ef-ips", u.EF_IPS},
		{"ef-ipd", u.EF_IPD},
		{"ef-epdgid", u.EF_EPDGID},
		{"ef-epdgselection", u.EF_EPDGSELECTION},
		{"ef-epdgidem", u.EF_EPDGIDEM},
		{"ef-epdgselectionem", u.EF_EPDGSELECTIONEM},
		{"ef-frompreferred", u.EF_FROMPREFERRED},
		{"ef-imsconfigdata", u.EF_IMSCONFIGDATA},
		{"ef-3gpppsdataoff", u.EF_3GPPPSDATAOFF},
		{"ef-3gpppsdataoffservicelist", u.EF_3GPPPSDATAOFFSERVICELIST},
		{"ef-xcapconfigdata", u.EF_XCAPCONFIGDATA},
		{"ef-earfcnlist", u.EF_EARFCNLIST},
		{"ef-mudmidconfigdata", u.EF_MUDMIDCONFIGDATA},
		{"ef-eaka", u.EF_EAKA},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// ISIM generator
// ============================================================================

func (g *Generator) generateISIM(i *ISIMApplication) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if i.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("isim-header", i.Header))
	}
	if len(i.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(i.TemplateID)))
	}

	if i.ADFISIM != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("adf-isim", i.ADFISIM))
	}

	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-impi", i.EF_IMPI},
		{"ef-impu", i.EF_IMPU},
		{"ef-domain", i.EF_DOMAIN},
		{"ef-ist", i.EF_IST},
		{"ef-ad", i.EF_AD},
		{"ef-arr", i.EF_ARR},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateOptISIM(i *OptionalISIM) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if i.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("optisim-header", i.Header))
	}
	if len(i.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(i.TemplateID)))
	}

	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-pcscf", i.EF_PCSCF},
		{"ef-gbabp", i.EF_GBABP},
		{"ef-gbanl", i.EF_GBANL},
		{"ef-nasconfig", i.EF_NASCONFIG},
		{"ef-uicciari", i.EF_UICCIARI},
		{"ef-3gpppsdataoff", i.EF_3GPPPSDATAOFF},
		{"ef-3gpppsdataoffservicelist", i.EF_3GPPPSDATAOFFSERVICELIST},
		{"ef-xcapconfigdata", i.EF_XCAPCONFIGDATA},
		{"ef-eaka", i.EF_EAKA},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	// Add any additional EFs
	if len(i.AdditionalEFs) > 0 {
		// Sort keys for deterministic output
		keys := make([]string, 0, len(i.AdditionalEFs))
		for k := range i.AdditionalEFs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fields = append(fields, g.sgenerateElementaryFile(k, i.AdditionalEFs[k]))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// CSIM generator
// ============================================================================

func (g *Generator) generateCSIM(c *CSIMApplication) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if c.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("csim-header", c.Header))
	}
	if len(c.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(c.TemplateID)))
	}

	if c.ADFCSIM != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("adf-csim", c.ADFCSIM))
	}

	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-arr", c.EF_ARR},
		{"ef-call-count", c.EF_CallCount},
		{"ef-imsi-m", c.EF_IMSI_M},
		{"ef-imsi-t", c.EF_IMSI_T},
		{"ef-tmsi", c.EF_TMSI},
		{"ef-ah", c.EF_AH},
		{"ef-aop", c.EF_AOP},
		{"ef-aloc", c.EF_ALOC},
		{"ef-cdmahome", c.EF_CDMAHOME},
		{"ef-znregi", c.EF_ZNREGI},
		{"ef-snregi", c.EF_SNREGI},
		{"ef-distregi", c.EF_DISTREGI},
		{"ef-accolc", c.EF_ACCOLC},
		{"ef-term", c.EF_TERM},
		{"ef-acp", c.EF_ACP},
		{"ef-prl", c.EF_PRL},
		{"ef-ruimid", c.EF_RUIMID},
		{"ef-csim-st", c.EF_CSIM_ST},
		{"ef-spc", c.EF_SPC},
		{"ef-otapaspc", c.EF_OTAPASPC},
		{"ef-namlock", c.EF_NAMLOCK},
		{"ef-ota", c.EF_OTA},
		{"ef-sp", c.EF_SP},
		{"ef-esn-meid-me", c.EF_ESN_MEID_ME},
		{"ef-li", c.EF_LI},
		{"ef-usgind", c.EF_USGIND},
		{"ef-ad", c.EF_AD},
		{"ef-max-prl", c.EF_MAX_PRL},
		{"ef-spcs", c.EF_SPCS},
		{"ef-mecrp", c.EF_MECRP},
		{"ef-home-tag", c.EF_HOME_TAG},
		{"ef-group-tag", c.EF_GROUP_TAG},
		{"ef-specific-tag", c.EF_SPECIFIC_TAG},
		{"ef-call-prompt", c.EF_CALL_PROMPT},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateOptCSIM(c *OptionalCSIM) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if c.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("optcsim-header", c.Header))
	}
	if len(c.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(c.TemplateID)))
	}

	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-ssci", c.EF_SSCI},
		{"ef-fdn", c.EF_FDN},
		{"ef-sms", c.EF_SMS},
		{"ef-smsp", c.EF_SMSP},
		{"ef-smss", c.EF_SMSS},
		{"ef-ssfc", c.EF_SSFC},
		{"ef-spn", c.EF_SPN},
		{"ef-mdn", c.EF_MDN},
		{"ef-ecc", c.EF_ECC},
		{"ef-me3gpdopc", c.EF_ME3GPDOPC},
		{"ef-3gpdopm", c.EF_3GPDOPM},
		{"ef-sipcap", c.EF_SIPCAP},
		{"ef-mipcap", c.EF_MIPCAP},
		{"ef-sipupp", c.EF_SIPUPP},
		{"ef-mipupp", c.EF_MIPUPP},
		{"ef-sipsp", c.EF_SIPSP},
		{"ef-mipsp", c.EF_MIPSP},
		{"ef-sippapss", c.EF_SIPPAPSS},
		{"ef-hrpdcap", c.EF_HRPDCAP},
		{"ef-hrpdupp", c.EF_HRPDUPP},
		{"ef-csspr", c.EF_CSSPR},
		{"ef-atc", c.EF_ATC},
		{"ef-eprl", c.EF_EPRL},
		{"ef-bcsmsp", c.EF_BCSMSP},
		{"ef-mmsn", c.EF_MMSN},
		{"ef-ext8", c.EF_EXT8},
		{"ef-mmsicp", c.EF_MMSICP},
		{"ef-mmsup", c.EF_MMSUP},
		{"ef-mmsucp", c.EF_MMSUCP},
		{"ef-3gcik", c.EF_3GCIK},
		{"ef-gid1", c.EF_GID1},
		{"ef-gid2", c.EF_GID2},
		{"ef-sf-euimid", c.EF_SF_EUIMID},
		{"ef-est", c.EF_EST},
		{"ef-hidden-key", c.EF_HIDDEN_KEY},
		{"ef-sdn", c.EF_SDN},
		{"ef-ext2", c.EF_EXT2},
		{"ef-ext3", c.EF_EXT3},
		{"ef-ici", c.EF_ICI},
		{"ef-oci", c.EF_OCI},
		{"ef-ext5", c.EF_EXT5},
		{"ef-ccp2", c.EF_CCP2},
		{"ef-model", c.EF_MODEL},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// GSM Access generator
// ============================================================================

func (g *Generator) generateGSMAccess(gsm *GSMAccessDF) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if gsm.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("gsm-access-header", gsm.Header))
	}
	if len(gsm.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(gsm.TemplateID)))
	}

	if gsm.DFGSMAccess != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-gsm-access", gsm.DFGSMAccess))
	}

	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-kc", gsm.EF_Kc},
		{"ef-kcgprs", gsm.EF_KcGPRS},
		{"ef-cpbcch", gsm.EF_CPBCCH},
		{"ef-invscan", gsm.EF_INVSCAN},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// DF-5GS generator
// ============================================================================

func (g *Generator) generateDF5GS(d *DF5GS) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if d.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("df-5gs-header", d.Header))
	}
	if len(d.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(d.TemplateID)))
	}

	if d.DFDF5GS != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-df-5gs", d.DFDF5GS))
	}

	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-5gs3gpploci", d.EF_5GS3GPPLOCI},
		{"ef-5gsn3gpploci", d.EF_5GSN3GPPLOCI},
		{"ef-5gs3gppnsc", d.EF_5GS3GPPNSC},
		{"ef-5gsn3gppnsc", d.EF_5GSN3GPPNSC},
		{"ef-5gauthkeys", d.EF_5GAUTHKEYS},
		{"ef-uac-aic", d.EF_UAC_AIC},
		{"ef-suci-calc-info", d.EF_SUCI_CALC_INFO},
		{"ef-opl5g", d.EF_OPL5G},
		{"ef-routing-indicator", d.EF_ROUTING_INDICATOR},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// DF-SAIP generator
// ============================================================================

func (g *Generator) generateDFSAIP(d *DFSAIP) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if d.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("df-saip-header", d.Header))
	}
	if len(d.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(d.TemplateID)))
	}

	if d.DFDFSAIP != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-df-saip", d.DFDFSAIP))
	}

	if d.EF_SUCI_CALC_INFO_USIM != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-suci-calc-info-usim", d.EF_SUCI_CALC_INFO_USIM))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// AKA Parameter generator
// ============================================================================

func (g *Generator) generateAKAParameter(aka *AKAParameter) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if aka.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("aka-header", aka.Header))
	}
	if aka.AlgoConfig != nil {
		fields = append(fields, g.sgenerateAlgoConfiguration(aka.AlgoConfig))
	}

	fields = append(fields, fmt.Sprintf("sqnOptions '%02X'H", aka.SQNOptions))

	if len(aka.SQNDelta) > 0 {
		fields = append(fields, fmt.Sprintf("sqnDelta %s", g.formatHex(aka.SQNDelta)))
	}
	if len(aka.SQNAgeLimit) > 0 {
		fields = append(fields, fmt.Sprintf("sqnAgeLimit %s", g.formatHex(aka.SQNAgeLimit)))
	}

	if len(aka.SQNInit) > 0 {
		fields = append(fields, g.sgenerateSQNInit(aka.SQNInit))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateAlgoConfiguration(ac *AlgoConfiguration) string {
	var sb strings.Builder
	sb.WriteString("algoConfiguration algoParameter : {\r\n")
	g.indent++

	fields := make([]string, 0)
	fields = append(fields, fmt.Sprintf("algorithmID %s", g.getAlgorithmIDName(ac.AlgorithmID)))
	fields = append(fields, fmt.Sprintf("algorithmOptions '%02X'H", ac.AlgorithmOptions))

	if len(ac.Key) > 0 {
		fields = append(fields, fmt.Sprintf("key %s", g.formatHex(ac.Key)))
	}
	if len(ac.OPC) > 0 {
		fields = append(fields, fmt.Sprintf("opc %s", g.formatHex(ac.OPC)))
	}
	if len(ac.RotationConstants) > 0 {
		fields = append(fields, fmt.Sprintf("rotationConstants %s", g.formatHex(ac.RotationConstants)))
	}
	if len(ac.XoringConstants) > 0 {
		fields = append(fields, fmt.Sprintf("xoringConstants %s", g.formatHex(ac.XoringConstants)))
	}
	if ac.NumberOfKeccak > 0 {
		fields = append(fields, fmt.Sprintf("numberOfKeccak %d", ac.NumberOfKeccak))
	}

	for i, f := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(f)
		if i < len(fields)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) sgenerateSQNInit(sqns [][]byte) string {
	var sb strings.Builder
	sb.WriteString("sqnInit {\r\n")
	g.indent++
	for i, sqn := range sqns {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(fmt.Sprintf("%s", g.formatHex(sqn)))
		if i < len(sqns)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}
	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) getAlgorithmIDName(id AlgorithmID) string {
	switch id {
	case AlgoMilenage:
		return "milenage"
	case AlgoTUAK:
		return "tuak"
	case AlgoUSIMTestAlgorithm:
		return "usim-test-algorithm"
	default:
		return fmt.Sprintf("%d", id)
	}
}

// ============================================================================
// CDMA Parameter generator
// ============================================================================

func (g *Generator) generateCDMAParameter(cdma *CDMAParameter) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if cdma.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("cdma-header", cdma.Header))
	}
	if len(cdma.AuthenticationKey) > 0 {
		fields = append(fields, fmt.Sprintf("authenticationKey %s", g.formatHex(cdma.AuthenticationKey)))
	}
	if len(cdma.SSD) > 0 {
		fields = append(fields, fmt.Sprintf("ssd %s", g.formatHex(cdma.SSD)))
	}
	if len(cdma.HRPDAccessAuthenticationData) > 0 {
		fields = append(fields, fmt.Sprintf("hrpdAccessAuthenticationData %s", g.formatHex(cdma.HRPDAccessAuthenticationData)))
	}
	if len(cdma.SimpleIPAuthenticationData) > 0 {
		fields = append(fields, fmt.Sprintf("simpleIPAuthenticationData %s", g.formatHex(cdma.SimpleIPAuthenticationData)))
	}
	if len(cdma.MobileIPAuthenticationData) > 0 {
		fields = append(fields, fmt.Sprintf("mobileIPAuthenticationData %s", g.formatHex(cdma.MobileIPAuthenticationData)))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// Security Domain generator
// ============================================================================

func (g *Generator) generateGenericFileManagement(gfm *GenericFileManagement) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if gfm.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("gfm-header", gfm.Header))
	}

	if len(gfm.FileManagementCMDs) > 0 {
		var sb strings.Builder
		sb.WriteString("fileManagementCMD {\r\n")
		g.indent++

		for i, cmd := range gfm.FileManagementCMDs {
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString("{\r\n")
			g.indent++

			cfields := make([]string, 0)
			for _, item := range cmd {
				switch item.ItemType {
				case 0: // filePath
					cfields = append(cfields, fmt.Sprintf("filePath : %s", g.formatHex(item.FilePath)))
				case 1: // createFCP
					if item.CreateFCP != nil {
						cfields = append(cfields, g.sgenerateFileDescriptorContent(item.CreateFCP))
					}
				case 2: // fillFileContent
					cfields = append(cfields, fmt.Sprintf("fillFileContent : %s", g.formatHex(item.FillFileContent)))
				case 3: // fillFileOffset
					cfields = append(cfields, fmt.Sprintf("fillFileOffset : %d", item.FillFileOffset))
				}
			}

			for j, f := range cfields {
				for k := 0; k < g.indent; k++ {
					sb.WriteString("  ")
				}
				sb.WriteString(f)
				if j < len(cfields)-1 {
					sb.WriteString(",")
				}
				sb.WriteString("\r\n")
			}

			g.indent--
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString("}")
			if i < len(gfm.FileManagementCMDs)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\r\n")
		}

		g.indent--
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("}")
		fields = append(fields, sb.String())
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateFileDescriptorContent(fd *FileDescriptor) string {
	var sb strings.Builder
	sb.WriteString("createFCP : {\r\n")
	g.indent++

	fields := make([]string, 0)
	if len(fd.FileDescriptor) > 0 {
		fields = append(fields, fmt.Sprintf("fileDescriptor %s", g.formatHex(fd.FileDescriptor)))
	}
	if len(fd.FileID) > 0 {
		fields = append(fields, fmt.Sprintf("fileID %s", g.formatHex(fd.FileID)))
	}
	if len(fd.DFName) > 0 {
		fields = append(fields, fmt.Sprintf("dfName %s", g.formatHex(fd.DFName)))
	}
	if len(fd.LCSI) > 0 {
		fields = append(fields, fmt.Sprintf("lcsi %s", g.formatHex(fd.LCSI)))
	}
	if len(fd.SecurityAttributesReferenced) > 0 {
		fields = append(fields, fmt.Sprintf("securityAttributesReferenced %s", g.formatHex(fd.SecurityAttributesReferenced)))
	}
	if len(fd.EFFileSize) > 0 {
		fields = append(fields, fmt.Sprintf("efFileSize %s", g.formatHex(fd.EFFileSize)))
	}
	if fd.ShortEFID != nil {
		fields = append(fields, fmt.Sprintf("shortEFID %s", g.formatHex(fd.ShortEFID)))
	}
	if len(fd.PinStatusTemplateDO) > 0 {
		fields = append(fields, fmt.Sprintf("pinStatusTemplateDO %s", g.formatHex(fd.PinStatusTemplateDO)))
	}
	if len(fd.LinkPath) > 0 {
		fields = append(fields, fmt.Sprintf("linkPath %s", g.formatHex(fd.LinkPath)))
	}
	if fd.ProprietaryEFInfo != nil {
		fields = append(fields, g.sgenerateProprietaryEFInfo(fd.ProprietaryEFInfo))
	}

	for i, f := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(f)
		if i < len(fields)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) generateSecurityDomain(sd *SecurityDomain) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if sd.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("sd-Header", sd.Header))
	}
	if sd.Instance != nil {
		var sb strings.Builder
		sb.WriteString("instance {\r\n")
		g.indent++

		ifields := make([]string, 0)
		if len(sd.Instance.ApplicationLoadPackageAID) > 0 {
			ifields = append(ifields, fmt.Sprintf("applicationLoadPackageAID %s", g.formatHex(sd.Instance.ApplicationLoadPackageAID)))
		}
		if len(sd.Instance.ClassAID) > 0 {
			ifields = append(ifields, fmt.Sprintf("classAID %s", g.formatHex(sd.Instance.ClassAID)))
		}
		if len(sd.Instance.InstanceAID) > 0 {
			ifields = append(ifields, fmt.Sprintf("instanceAID %s", g.formatHex(sd.Instance.InstanceAID)))
		}
		if len(sd.Instance.ApplicationPrivileges) > 0 {
			ifields = append(ifields, fmt.Sprintf("applicationPrivileges %s", g.formatHex(sd.Instance.ApplicationPrivileges)))
		}
		ifields = append(ifields, fmt.Sprintf("lifeCycleState '%02X'H", sd.Instance.LifeCycleState))
		if len(sd.Instance.ApplicationSpecificParamsC9) > 0 {
			ifields = append(ifields, fmt.Sprintf("applicationSpecificParametersC9 %s", g.formatHex(sd.Instance.ApplicationSpecificParamsC9)))
		}
		if sd.Instance.ApplicationParameters != nil && len(sd.Instance.ApplicationParameters.UIICToolkitApplicationSpecificParametersField) > 0 {
			ifields = append(ifields, g.sgenerateApplicationParameters(sd.Instance.ApplicationParameters))
		}

		for i, f := range ifields {
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString(f)
			if i < len(ifields)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\r\n")
		}

		g.indent--
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("}")
		fields = append(fields, sb.String())
	}

	if len(sd.KeyList) > 0 {
		var sb strings.Builder
		sb.WriteString("keyList {\r\n")
		g.indent++

		for i, key := range sd.KeyList {
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString("{\r\n")
			g.indent++

			kfields := make([]string, 0)
			kfields = append(kfields, fmt.Sprintf("keyUsageQualifier '%02X'H", key.KeyUsageQualifier))
			kfields = append(kfields, fmt.Sprintf("keyAccess '%02X'H", key.KeyAccess))
			kfields = append(kfields, fmt.Sprintf("keyIdentifier '%02X'H", key.KeyIdentifier))
			kfields = append(kfields, fmt.Sprintf("keyVersionNumber '%02X'H", key.KeyVersionNumber))

			if len(key.KeyCompontents) > 0 {
				kfields = append(kfields, g.sgenerateKeyCompontents(key.KeyCompontents))
			}

			for j, f := range kfields {
				for k := 0; k < g.indent; k++ {
					sb.WriteString("  ")
				}
				sb.WriteString(f)
				if j < len(kfields)-1 {
					sb.WriteString(",")
				}
				sb.WriteString("\r\n")
			}

			g.indent--
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString("}")
			if i < len(sd.KeyList)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\r\n")
		}

		g.indent--
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("}")
		fields = append(fields, sb.String())
	}

	if len(sd.SDPersoData) > 0 {
		var sb strings.Builder
		sb.WriteString("sdPersoData {\r\n")
		g.indent++
		for i, data := range sd.SDPersoData {
			for j := 0; j < g.indent; j++ {
				sb.WriteString("  ")
			}
			sb.WriteString(g.formatHex(data))
			if i < len(sd.SDPersoData)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\r\n")
		}
		g.indent--
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("}")
		fields = append(fields, sb.String())
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateApplicationParameters(ap *ApplicationParameters) string {
	var sb strings.Builder
	sb.WriteString("applicationParameters {\r\n")
	g.indent++
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString(fmt.Sprintf("uiccToolkitApplicationSpecificParametersField %s\r\n", g.formatHex(ap.UIICToolkitApplicationSpecificParametersField)))
	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) sgenerateKeyCompontents(comps []KeyComponent) string {
	var sb strings.Builder
	sb.WriteString("keyCompontents {\r\n")
	g.indent++
	for i, comp := range comps {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("{\r\n")
		g.indent++

		fields := make([]string, 0)
		fields = append(fields, fmt.Sprintf("keyType '%02X'H", comp.KeyType))
		fields = append(fields, fmt.Sprintf("keyData %s", g.formatHex(comp.KeyData)))
		fields = append(fields, fmt.Sprintf("macLength %d", comp.MACLength))

		for j, f := range fields {
			for k := 0; k < g.indent; k++ {
				sb.WriteString("  ")
			}
			sb.WriteString(f)
			if j < len(fields)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\r\n")
		}

		g.indent--
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("}")
		if i < len(comps)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}
	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

// ============================================================================
// RFM generator
// ============================================================================

func (g *Generator) generateRFM(rfm *RFMConfig) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if rfm.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("rfm-header", rfm.Header))
	}
	if len(rfm.InstanceAID) > 0 {
		fields = append(fields, fmt.Sprintf("instanceAID %s", g.formatHex(rfm.InstanceAID)))
	}

	if len(rfm.TARList) > 0 {
		fields = append(fields, g.sgenerateTARList(rfm.TARList))
	}

	fields = append(fields, fmt.Sprintf("minimumSecurityLevel '%02X'H", rfm.MinimumSecurityLevel))
	fields = append(fields, fmt.Sprintf("uiccAccessDomain '%02X'H", rfm.UICCAccessDomain))
	fields = append(fields, fmt.Sprintf("uiccAdminAccessDomain '%02X'H", rfm.UICCAdminAccessDomain))

	if rfm.ADFRFMAccess != nil {
		fields = append(fields, g.sgenerateADFRFMAccess(rfm.ADFRFMAccess))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateTARList(tars [][]byte) string {
	var sb strings.Builder
	sb.WriteString("tarList {\r\n")
	g.indent++
	for i, tar := range tars {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(fmt.Sprintf("%s", g.formatHex(tar)))
		if i < len(tars)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}
	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) sgenerateADFRFMAccess(acc *ADFRFMAccess) string {
	var sb strings.Builder
	sb.WriteString("adfRFMAccess {\r\n")
	g.indent++

	fields := make([]string, 0)
	fields = append(fields, fmt.Sprintf("adfAID %s", g.formatHex(acc.ADFAID)))
	fields = append(fields, fmt.Sprintf("adfAccessDomain '%02X'H", acc.ADFAccessDomain))
	fields = append(fields, fmt.Sprintf("adfAdminAccessDomain '%02X'H", acc.ADFAdminAccessDomain))

	for i, f := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(f)
		if i < len(fields)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

// ============================================================================
// Application generator
// ============================================================================

func (g *Generator) generateApplication(app *Application) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if app.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("app-Header", app.Header))
	}
	if app.LoadBlock != nil {
		fields = append(fields, g.sgenerateApplicationLoadPackage(app.LoadBlock))
	}

	if len(app.InstanceList) > 0 {
		fields = append(fields, g.sgenerateApplicationInstanceList(app.InstanceList))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateApplicationLoadPackage(pkg *ApplicationLoadPackage) string {
	var sb strings.Builder
	sb.WriteString("loadBlock {\r\n")
	g.indent++

	fields := make([]string, 0)
	if len(pkg.LoadPackageAID) > 0 {
		fields = append(fields, fmt.Sprintf("loadPackageAID %s", g.formatHex(pkg.LoadPackageAID)))
	}
	if len(pkg.SecurityDomainAID) > 0 {
		fields = append(fields, fmt.Sprintf("securityDomainAID %s", g.formatHex(pkg.SecurityDomainAID)))
	}
	if len(pkg.HashValue) > 0 {
		fields = append(fields, fmt.Sprintf("hashValue %s", g.formatHex(pkg.HashValue)))
	}
	if len(pkg.LoadBlockObject) > 0 {
		fields = append(fields, fmt.Sprintf("loadBlockObject %s", g.formatHex(pkg.LoadBlockObject)))
	}
	if len(pkg.NonVolatileCodeLimitC6) > 0 {
		fields = append(fields, fmt.Sprintf("nonVolatileCodeLimitC6 %s", g.formatHex(pkg.NonVolatileCodeLimitC6)))
	}
	if len(pkg.VolatileDataLimitC7) > 0 {
		fields = append(fields, fmt.Sprintf("volatileDataLimitC7 %s", g.formatHex(pkg.VolatileDataLimitC7)))
	}
	if len(pkg.NonVolatileDataLimitC8) > 0 {
		fields = append(fields, fmt.Sprintf("nonVolatileDataLimitC8 %s", g.formatHex(pkg.NonVolatileDataLimitC8)))
	}

	for i, f := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(f)
		if i < len(fields)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) sgenerateApplicationInstanceList(instances []*ApplicationInstance) string {
	var sb strings.Builder
	sb.WriteString("instanceList {\r\n")
	g.indent++

	for i, inst := range instances {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("{\r\n")
		g.indent++

		fields := make([]string, 0)
		if len(inst.ApplicationLoadPackageAID) > 0 {
			fields = append(fields, fmt.Sprintf("applicationLoadPackageAID %s", g.formatHex(inst.ApplicationLoadPackageAID)))
		}
		if len(inst.ClassAID) > 0 {
			fields = append(fields, fmt.Sprintf("classAID %s", g.formatHex(inst.ClassAID)))
		}
		if len(inst.InstanceAID) > 0 {
			fields = append(fields, fmt.Sprintf("instanceAID %s", g.formatHex(inst.InstanceAID)))
		}
		if len(inst.ExtraditeSecurityDomainAID) > 0 {
			fields = append(fields, fmt.Sprintf("extraditeSecurityDomainAID %s", g.formatHex(inst.ExtraditeSecurityDomainAID)))
		}
		if len(inst.ApplicationPrivileges) > 0 {
			fields = append(fields, fmt.Sprintf("applicationPrivileges %s", g.formatHex(inst.ApplicationPrivileges)))
		}
		fields = append(fields, fmt.Sprintf("lifeCycleState '%02X'H", inst.LifeCycleState))
		if len(inst.ApplicationSpecificParamsC9) > 0 {
			fields = append(fields, fmt.Sprintf("applicationSpecificParametersC9 %s", g.formatHex(inst.ApplicationSpecificParamsC9)))
		}
		if len(inst.SystemSpecificParams) > 0 {
			fields = append(fields, fmt.Sprintf("systemSpecificParameters %s", g.formatHex(inst.SystemSpecificParams)))
		}
		if len(inst.ControlReferenceTemplate) > 0 {
			fields = append(fields, fmt.Sprintf("controlReferenceTemplate %s", g.formatHex(inst.ControlReferenceTemplate)))
		}
		if len(inst.ProcessData) > 0 {
			fields = append(fields, g.sgenerateProcessData(inst.ProcessData))
		}

		for j, f := range fields {
			for k := 0; k < g.indent; k++ {
				sb.WriteString("  ")
			}
			sb.WriteString(f)
			if j < len(fields)-1 {
				sb.WriteString(",")
			}
			sb.WriteString("\r\n")
		}

		g.indent--
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("}")
		if i < len(instances)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}

	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) sgenerateProcessData(data [][]byte) string {
	var sb strings.Builder
	sb.WriteString("processData {\r\n")
	g.indent++
	for i, d := range data {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(fmt.Sprintf("%s", g.formatHex(d)))
		if i < len(data)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\r\n")
	}
	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

// ============================================================================
// End generator
// ============================================================================

func (g *Generator) generateEnd(end *EndElement) {
	g.write("{\r\n")
	g.indent++

	fields := make([]string, 0)
	if end.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("end-header", end.Header))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}
