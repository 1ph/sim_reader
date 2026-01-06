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
	case TagCD:
		g.generateCD(elem.Value.(*CDDF))
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
	case TagPhonebook:
		g.generatePhonebook(elem.Value.(*PhonebookDF))
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
	case TagEAP:
		g.generateEAP(elem.Value.(*EAPDF))
	case TagDF5GS:
		g.generateDF5GS(elem.Value.(*DF5GS))
	case TagDFSAIP:
		g.generateDFSAIP(elem.Value.(*DFSAIP))
	case TagDFSNPN:
		g.generateDFSNPN(elem.Value.(*DFSNPN))
	case TagDF5GPROSE:
		g.generateDF5GPROSE(elem.Value.(*DF5GPROSE))
	case TagIoT:
		g.generateIoT(elem.Value.(*IoTPE))
	case TagOptIoT:
		g.generateOptIoT(elem.Value.(*OptionalIoT))
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
	case TagCD:
		return "cd"
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
	case TagPhonebook:
		return "phonebook"
	case TagGSMAccess:
		return "gsm-access"
	case TagCSIM:
		return "csim"
	case TagOptCSIM:
		return "opt-csim"
	case TagEAP:
		return "eap"
	case TagAKAParameter:
		return "akaParameter"
	case TagCDMAParameter:
		return "cdmaParameter"
	case TagDF5GS:
		return "df-5gs"
	case TagDFSAIP:
		return "df-saip"
	case TagDFSNPN:
		return "df-snpn"
	case TagDF5GPROSE:
		return "df-5gprose"
	case TagIoT:
		return "iot"
	case TagOptIoT:
		return "opt-iot"
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

	if len(h.ConnectivityParameters) > 0 {
		fields = append(fields, fmt.Sprintf("connectivityParameters %s", g.formatHex(h.ConnectivityParameters)))
	}

	if len(h.MandatoryAIDs) > 0 {
		fields = append(fields, g.sgenerateMandatoryAIDList(h.MandatoryAIDs))
	}

	if h.IOTOptions != nil {
		fields = append(fields, g.sgenerateIOTOptions(h.IOTOptions))
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
	if ms.Contactless {
		fields = append(fields, "contactless NULL")
	}
	if ms.USIM {
		fields = append(fields, "usim NULL")
	}
	if ms.ISIM {
		fields = append(fields, "isim NULL")
	}
	if ms.CSIM {
		fields = append(fields, "csim NULL")
	}
	if ms.Milenage {
		fields = append(fields, "milenage NULL")
	}
	if ms.TUAK128 {
		fields = append(fields, "tuak128 NULL")
	}
	if ms.CAVE {
		fields = append(fields, "cave NULL")
	}
	if ms.GBAUSIM {
		fields = append(fields, "gba-usim NULL")
	}
	if ms.GBAISIM {
		fields = append(fields, "gba-isim NULL")
	}
	if ms.MBMS {
		fields = append(fields, "mbms NULL")
	}
	if ms.EAP {
		fields = append(fields, "eap NULL")
	}
	if ms.JavaCard {
		fields = append(fields, "javacard NULL")
	}
	if ms.Multos {
		fields = append(fields, "multos NULL")
	}
	if ms.MultipleUSIM {
		fields = append(fields, "multiple-usim NULL")
	}
	if ms.MultipleISIM {
		fields = append(fields, "multiple-isim NULL")
	}
	if ms.MultipleCSIM {
		fields = append(fields, "multiple-csim NULL")
	}
	if ms.TUAK256 {
		fields = append(fields, "tuak256 NULL")
	}
	if ms.USIMTestAlgorithm {
		fields = append(fields, "usim-test-algorithm NULL")
	}
	if ms.BERTLV {
		fields = append(fields, "ber-tlv NULL")
	}
	if ms.DFLink {
		fields = append(fields, "dfLink NULL")
	}
	if ms.CatTP {
		fields = append(fields, "cat-tp NULL")
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
	if ms.SuciCalculatorApi {
		fields = append(fields, "suciCalculatorApi NULL")
	}
	if ms.DNSResolution {
		fields = append(fields, "dns-resolution NULL")
	}
	if ms.SCP11ac {
		fields = append(fields, "scp11ac NULL")
	}
	if ms.SCP11cAuth {
		fields = append(fields, "scp11c-authorization-mechanism NULL")
	}
	if ms.S16Mode {
		fields = append(fields, "s16mode NULL")
	}
	if ms.EAKA {
		fields = append(fields, "eaka NULL")
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

// ============================================================================
// CD generator
// ============================================================================

func (g *Generator) generateCD(cd *CDDF) {
	g.write("{\r\n")
	g.indent++
	fields := make([]string, 0)
	if cd.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("cd-header", cd.Header))
	}
	if len(cd.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(cd.TemplateID)))
	}
	if cd.DFCD != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-cd", cd.DFCD))
	}
	if cd.EF_LaunchPad != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-launchpad", cd.EF_LaunchPad))
	}
	if cd.EF_Icon != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-icon", cd.EF_Icon))
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
	if len(fd.UnknownTag) > 0 {
		fields = append(fields, fmt.Sprintf("unknownTag %s", g.formatHex(fd.UnknownTag)))
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

	if len(pin.FilePath) > 0 {
		fields = append(fields, fmt.Sprintf("pinCodes filePath : %s", g.formatHex(pin.FilePath)))
	} else if len(pin.Configs) > 0 {
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
		{"ef-rma", t.EF_RMA},
		{"ef-sume", t.EF_SUME},
		{"ef-ice-dn", t.EF_ICE_DN},
		{"ef-ice-ff", t.EF_ICE_FF},
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
	if t.EF_IIDF != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-iidf", t.EF_IIDF))
	}
	if t.EF_ICE_Graphics != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-ice-graphics", t.EF_ICE_Graphics))
	}
	if t.EF_LaunchSCWS != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-launch-scws", t.EF_LaunchSCWS))
	}
	if t.EF_ICON != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-icon", t.EF_ICON))
	}
	if t.DFPhonebook != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-phonebook", t.DFPhonebook))
	}
	if t.EF_PBR != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-pbr", t.EF_PBR))
	}
	if t.EF_EXT1 != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-ext1", t.EF_EXT1))
	}
	if t.EF_AAS != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-aas", t.EF_AAS))
	}
	if t.EF_GAS != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-gas", t.EF_GAS))
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
	if t.EF_IAP != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-iap", t.EF_IAP))
	}
	if t.EF_ADN != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-adn", t.EF_ADN))
	}
	if t.EF_PBC != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-pbc", t.EF_PBC))
	}
	if t.EF_ANR != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-anr", t.EF_ANR))
	}
	if t.EF_PURI != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-puri", t.EF_PURI))
	}
	if t.EF_EMAIL != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-email", t.EF_EMAIL))
	}
	if t.EF_SNE != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-sne", t.EF_SNE))
	}
	if t.EF_UID != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-uid", t.EF_UID))
	}
	if t.EF_GRP != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-grp", t.EF_GRP))
	}
	if t.EF_CCP1 != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-ccp1", t.EF_CCP1))
	}
	if t.DFMultimedia != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-multimedia", t.DFMultimedia))
	}
	if t.EF_MML != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-mml", t.EF_MML))
	}
	if t.EF_MMDF != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-mmdf", t.EF_MMDF))
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
	if t.EF_MMSSMODE != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-mmssmode", t.EF_MMSSMODE))
	}
	if t.DFMCS != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-mcs", t.DFMCS))
	}
	if t.EF_MST != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-mst", t.EF_MST))
	}
	if t.EF_MCSConfig != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-mcs-config", t.EF_MCSConfig))
	}
	if t.DFV2X != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-v2x", t.DFV2X))
	}
	if t.EF_VST != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-vst", t.EF_VST))
	}
	if t.EF_V2XConfig != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-v2x-config", t.EF_V2XConfig))
	}
	if t.EF_V2XPPC5 != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-v2xp-pc5", t.EF_V2XPPC5))
	}
	if t.EF_V2XPUu != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-v2xp-Uu", t.EF_V2XPUu))
	}

	// Add any additional EFs
	if len(t.AdditionalEFs) > 0 {
		keys := make([]string, 0, len(t.AdditionalEFs))
		for k := range t.AdditionalEFs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fields = append(fields, g.sgenerateElementaryFile(k, t.AdditionalEFs[k]))
		}
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
		{"ef-wlan", u.EF_WLAN},
		{"ef-deb-pk", u.EF_DEB_PK},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	if len(u.AdditionalEFs) > 0 {
		keys := make([]string, 0, len(u.AdditionalEFs))
		for k := range u.AdditionalEFs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fields = append(fields, g.sgenerateElementaryFile(k, u.AdditionalEFs[k]))
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

	if len(u.AdditionalEFs) > 0 {
		keys := make([]string, 0, len(u.AdditionalEFs))
		for k := range u.AdditionalEFs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fields = append(fields, g.sgenerateElementaryFile(k, u.AdditionalEFs[k]))
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

	if len(i.AdditionalEFs) > 0 {
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
		{"ef-sms", i.EF_SMS},
		{"ef-smsp", i.EF_SMSP},
		{"ef-smss", i.EF_SMSS},
		{"ef-smsr", i.EF_SMSR},
		{"ef-gbabp", i.EF_GBABP},
		{"ef-gbanl", i.EF_GBANL},
		{"ef-nafkca", i.EF_NAFKCA},
		{"ef-uicciari", i.EF_UICCIARI},
		{"ef-frompreferred", i.EF_FROMPREFERRED},
		{"ef-imsconfigdata", i.EF_IMSCONFIGDATA},
		{"ef-xcapconfigdata", i.EF_XCAPCONFIGDATA},
		{"ef-webrtcuri", i.EF_WEBRTCURI},
		{"ef-mudmidconfigdata", i.EF_MUDMIDCONFIGDATA},
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
// Phonebook generator
// ============================================================================

func (g *Generator) generatePhonebook(pb *PhonebookDF) {
	g.write("{\r\n")
	g.indent++
	fields := make([]string, 0)
	if pb.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("phonebook-header", pb.Header))
	}
	if len(pb.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(pb.TemplateID)))
	}
	if pb.DFPhonebook != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-phonebook", pb.DFPhonebook))
	}
	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-pbr", pb.EF_PBR},
		{"ef-ext1", pb.EF_EXT1},
		{"ef-aas", pb.EF_AAS},
		{"ef-gas", pb.EF_GAS},
		{"ef-psc", pb.EF_PSC},
		{"ef-cc", pb.EF_CC},
		{"ef-puid", pb.EF_PUID},
		{"ef-iap", pb.EF_IAP},
		{"ef-adn", pb.EF_ADN},
		{"ef-pbc", pb.EF_PBC},
		{"ef-anr", pb.EF_ANR},
		{"ef-puri", pb.EF_PURI},
		{"ef-email", pb.EF_EMAIL},
		{"ef-sne", pb.EF_SNE},
		{"ef-uid", pb.EF_UID},
		{"ef-grp", pb.EF_GRP},
		{"ef-ccp1", pb.EF_CCP1},
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

	if len(gsm.AdditionalEFs) > 0 {
		keys := make([]string, 0, len(gsm.AdditionalEFs))
		for k := range gsm.AdditionalEFs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fields = append(fields, g.sgenerateElementaryFile(k, gsm.AdditionalEFs[k]))
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

	if len(c.AdditionalEFs) > 0 {
		keys := make([]string, 0, len(c.AdditionalEFs))
		for k := range c.AdditionalEFs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fields = append(fields, g.sgenerateElementaryFile(k, c.AdditionalEFs[k]))
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
		{"ef-puzl", c.EF_PUZL},
		{"ef-max-puzl", c.EF_MAX_PUZL},
		{"ef-hrpdcap", c.EF_HRPDCAP},
		{"ef-hrpdupp", c.EF_HRPDUPP},
		{"ef-csspr", c.EF_CSSPR},
		{"ef-atc", c.EF_ATC},
		{"ef-eprl", c.EF_EPRL},
		{"ef-bcsmscfg", c.EF_BCSMSConfig},
		{"ef-bcsmspref", c.EF_BCSMSPref},
		{"ef-bcsmstable", c.EF_BCSMSTable},
		{"ef-bcsmsp", c.EF_BCSMSP},
		{"ef-bakpara", c.EF_BAKPara},
		{"ef-upbakpara", c.EF_UPBAKPara},
		{"ef-mmsn", c.EF_MMSN},
		{"ef-ext8", c.EF_EXT8},
		{"ef-mmsicp", c.EF_MMSICP},
		{"ef-mmsup", c.EF_MMSUP},
		{"ef-mmsucp", c.EF_MMSUCP},
		{"ef-auth-capability", c.EF_AuthCapability},
		{"ef-3gcik", c.EF_3GCIK},
		{"ef-dck", c.EF_DCK},
		{"ef-gid1", c.EF_GID1},
		{"ef-gid2", c.EF_GID2},
		{"ef-cdmacnl", c.EF_CDMACNL},
		{"ef-sf-euimid", c.EF_SF_EUIMID},
		{"ef-est", c.EF_EST},
		{"ef-hidden-key", c.EF_HIDDEN_KEY},
		{"ef-lcsver", c.EF_LCSVer},
		{"ef-lcscp", c.EF_LCSCP},
		{"ef-sdn", c.EF_SDN},
		{"ef-ext2", c.EF_EXT2},
		{"ef-ext3", c.EF_EXT3},
		{"ef-ici", c.EF_ICI},
		{"ef-oci", c.EF_OCI},
		{"ef-ext5", c.EF_EXT5},
		{"ef-ccp2", c.EF_CCP2},
		{"ef-applabels", c.EF_AppLabels},
		{"ef-model", c.EF_MODEL},
		{"ef-rc", c.EF_RC},
		{"ef-smscap", c.EF_SMSCap},
		{"ef-mipflags", c.EF_MIPFlags},
		{"ef-3gpduppext", c.EF_3GPDUppeExt},
		{"ef-ipv6cap", c.EF_IPv6Cap},
		{"ef-tcpconfig", c.EF_TCPConfig},
		{"ef-dgc", c.EF_DGC},
		{"ef-wapbrowsercp", c.EF_WAPBrowserCP},
		{"ef-wapbrowserbm", c.EF_WAPBrowserBM},
		{"ef-mmsconfig", c.EF_MMSConfig},
		{"ef-jdl", c.EF_JDL},
		{"ef-meidme", c.EF_MEIDME},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	if len(c.AdditionalEFs) > 0 {
		keys := make([]string, 0, len(c.AdditionalEFs))
		for k := range c.AdditionalEFs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fields = append(fields, g.sgenerateElementaryFile(k, c.AdditionalEFs[k]))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// EAP generator
// ============================================================================

func (g *Generator) generateEAP(eap *EAPDF) {
	g.write("{\r\n")
	g.indent++
	fields := make([]string, 0)
	if eap.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("eap-header", eap.Header))
	}
	if len(eap.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(eap.TemplateID)))
	}
	if eap.DFEAP != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-eap", eap.DFEAP))
	}
	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-eapkeys", eap.EF_EAPKeys},
		{"ef-eapstatus", eap.EF_EAPStatus},
		{"ef-puid", eap.EF_PUID},
		{"ef-ps", eap.EF_PS},
		{"ef-curid", eap.EF_CURID},
		{"ef-reid", eap.EF_REID},
		{"ef-realm", eap.EF_Realm},
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
		{"ef-supi-nai", d.EF_SUPI_NAI},
		{"ef-routing-indicator", d.EF_ROUTING_INDICATOR},
		{"ef-ursp", d.EF_URSP},
		{"ef-tn3gppsnn", d.EF_TN3GPPSNN},
		{"ef-cag", d.EF_CAG},
		{"ef-sor-cmci", d.EF_SOR_CMCI},
		{"ef-dri", d.EF_DRI},
		{"ef-5gsedrx", d.EF_5GSEDRX},
		{"ef-5gnswo-conf", d.EF_5GNSWO_CONF},
		{"ef-mchpplmn", d.EF_MCHPPLMN},
		{"ef-kausf-derivation", d.EF_KAUSF_DERIVATION},
	}

	for _, f := range efFields {
		if f.ef != nil {
			fields = append(fields, g.sgenerateElementaryFile(f.name, f.ef))
		}
	}

	if len(d.AdditionalEFs) > 0 {
		keys := make([]string, 0, len(d.AdditionalEFs))
		for k := range d.AdditionalEFs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fields = append(fields, g.sgenerateElementaryFile(k, d.AdditionalEFs[k]))
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

	if len(d.AdditionalEFs) > 0 {
		keys := make([]string, 0, len(d.AdditionalEFs))
		for k := range d.AdditionalEFs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fields = append(fields, g.sgenerateElementaryFile(k, d.AdditionalEFs[k]))
		}
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// DFSNPN generator
// ============================================================================

func (g *Generator) generateDFSNPN(snpn *DFSNPN) {
	g.write("{\r\n")
	g.indent++
	fields := make([]string, 0)
	if snpn.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("df-snpn-header", snpn.Header))
	}
	if len(snpn.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(snpn.TemplateID)))
	}
	if snpn.DFDFSNPN != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-df-snpn", snpn.DFDFSNPN))
	}
	if snpn.EF_PWS_SNPN != nil {
		fields = append(fields, g.sgenerateElementaryFile("ef-pws-snpn", snpn.EF_PWS_SNPN))
	}
	g.writeFields(fields)
	g.indent--
	g.writeLine("}")
}

// ============================================================================
// DF5GPROSE generator
// ============================================================================

func (g *Generator) generateDF5GPROSE(prose *DF5GPROSE) {
	g.write("{\r\n")
	g.indent++
	fields := make([]string, 0)
	if prose.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("df-5g-prose-header", prose.Header))
	}
	if len(prose.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(prose.TemplateID)))
	}
	if prose.DFDF5GProSe != nil {
		fields = append(fields, g.sgenerateFileDescriptorWrapper("df-df-5g-prose", prose.DFDF5GProSe))
	}
	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-5g-prose-st", prose.EF_5G_ProSe_ST},
		{"ef-5g-prose-dd", prose.EF_5G_ProSe_DD},
		{"ef-5g-prose-dc", prose.EF_5G_ProSe_DC},
		{"ef-5g-prose-u2nru", prose.EF_5G_ProSe_U2NRU},
		{"ef-5g-prose-ru", prose.EF_5G_ProSe_RU},
		{"ef-5g-prose-uir", prose.EF_5G_ProSe_UIR},
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
// IoT generator
// ============================================================================

func (g *Generator) generateIoT(iot *IoTPE) {
	g.write("{\r\n")
	g.indent++
	fields := make([]string, 0)
	if iot.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("iot-header", iot.Header))
	}
	if len(iot.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(iot.TemplateID)))
	}
	efFields := []struct {
		name string
		f    *File
	}{
		{"mf", iot.MF},
		{"ef-pl", iot.EF_PL},
		{"ef-iccid", iot.EF_ICCID},
		{"ef-dir", iot.EF_DIR},
		{"ef-arr", iot.EF_ARR},
		{"ef-umpc", iot.EF_UMPC},
		{"adf-usim", iot.ADF_USIM},
		{"ef-imsi", iot.EF_IMSI},
		{"ef-arr-usim", iot.EF_ARR_USIM},
		{"ef-keys", iot.EF_Keys},
		{"ef-keysPS", iot.EF_KeysPS},
		{"ef-hpplmn", iot.EF_HPPLMN},
		{"ef-ust", iot.EF_UST},
		{"ef-start-hfn", iot.EF_StartHFN},
		{"ef-threshold", iot.EF_Threshold},
		{"ef-psloci", iot.EF_PSLOCI},
		{"ef-acc", iot.EF_ACC},
		{"ef-fplmn", iot.EF_FPLMN},
		{"ef-loci", iot.EF_LOCI},
		{"ef-ad", iot.EF_AD},
		{"ef-ecc", iot.EF_ECC},
		{"ef-netpar", iot.EF_NETPAR},
	}
	for _, f := range efFields {
		if f.f != nil {
			fields = append(fields, g.sgenerateIoTFile(f.name, f.f))
		}
	}
	g.writeFields(fields)
	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateOptIoT(iot *OptionalIoT) {
	g.write("{\r\n")
	g.indent++
	fields := make([]string, 0)
	if iot.Header != nil {
		fields = append(fields, g.sgenerateElementHeader("optiot-header", iot.Header))
	}
	if len(iot.TemplateID) > 0 {
		fields = append(fields, fmt.Sprintf("templateID %s", g.generateOID(iot.TemplateID)))
	}
	efFields := []struct {
		name string
		f    *File
	}{
		{"ef-fdn", iot.EF_FDN},
		{"ef-sms", iot.EF_SMS},
		{"ef-smsp", iot.EF_SMSP},
		{"ef-smss", iot.EF_SMSS},
		{"ef-spn", iot.EF_SPN},
		{"ef-est", iot.EF_EST},
		{"ef-oplmnwact", iot.EF_OPLMNWACT},
		{"ef-hplmnwact", iot.EF_HPLMNWACT},
		{"ef-ehplmn", iot.EF_EHPLMN},
		{"ef-epsloci", iot.EF_EPSLOCI},
		{"ef-epsnsc", iot.EF_EPSNSC},
		{"df-df-5gs", iot.DF_DF_5GS},
		{"ef-5gs3gpploci", iot.EF_5GS3GPPLOCI},
		{"ef-5gsn3gpploci", iot.EF_5GSN3GPPLOCI},
		{"ef-5gs3gppnsc", iot.EF_5GS3GPPNSC},
		{"ef-5gsn3gppnsc", iot.EF_5GSN3GPPNSC},
		{"ef-5gauthkeys", iot.EF_5GAUTHKEYS},
		{"ef-uac-aic", iot.EF_UAC_AIC},
		{"ef-suci-calc-info", iot.EF_SUCI_CALC_INFO},
		{"ef-opl5g", iot.EF_OPL5G},
		{"ef-supi-nai", iot.EF_SUPI_NAI},
		{"ef-routing-indicator", iot.EF_ROUTING_INDICATOR},
		{"ef-ursp", iot.EF_URSP},
		{"ef-tn3gppsnn", iot.EF_TN3GPPSNN},
		{"df-df-saip", iot.DF_DF_SAIP},
		{"ef-suci-calc-info-usim", iot.EF_SUCI_CALC_INFO_USIM},
	}
	for _, f := range efFields {
		if f.f != nil {
			fields = append(fields, g.sgenerateIoTFile(f.name, f.f))
		}
	}
	g.writeFields(fields)
	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateIoTFile(name string, f *File) string {
	var sb strings.Builder
	sb.WriteString(name + " {\r\n")
	g.indent++
	fields := make([]string, 0)
	for _, elem := range *f {
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
	for i, field := range fields {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString(field)
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
	if ac.MappingParameter != nil {
		sb.WriteString("algoConfiguration mappingParameter : {\r\n")
		g.indent++
		fields := make([]string, 0)
		fields = append(fields, fmt.Sprintf("mappingOptions '%02X'H", ac.MappingParameter.MappingOptions))
		fields = append(fields, fmt.Sprintf("mappingSource %s", g.formatHex(ac.MappingParameter.MappingSource)))
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
	} else {
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
		if len(ac.AuthCounterMax) > 0 {
			fields = append(fields, fmt.Sprintf("authCounterMax %s", g.formatHex(ac.AuthCounterMax)))
		}
		if ac.NumberOfKeccak != nil {
			fields = append(fields, fmt.Sprintf("numberOfKeccak %d", *ac.NumberOfKeccak))
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
	}
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
	if len(fd.UnknownTag) > 0 {
		fields = append(fields, fmt.Sprintf("unknownTag %s", g.formatHex(fd.UnknownTag)))
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
		fields = append(fields, g.sgenerateApplicationInstance("instance", sd.Instance))
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

			if len(key.KeyComponents) > 0 {
				kfields = append(kfields, g.sgenerateKeyCompontents(key.KeyComponents))
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

	if sd.OpenPersoData != nil {
		fields = append(fields, g.sgenerateOpenPersoData(sd.OpenPersoData))
	}

	if sd.CatTpParameters != nil {
		fields = append(fields, g.sgenerateCatTpParameters(sd.CatTpParameters))
	}

	g.writeFields(fields)

	g.indent--
	g.writeLine("}")
}

func (g *Generator) sgenerateApplicationInstance(name string, inst *ApplicationInstance) string {
	var sb strings.Builder
	sb.WriteString(name + " {\r\n")
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
	if inst.SystemSpecificParams != nil {
		fields = append(fields, g.sgenerateApplicationSystemParameters(inst.SystemSpecificParams))
	}
	if inst.ApplicationParameters != nil {
		fields = append(fields, g.sgenerateUICCApplicationParameters(inst.ApplicationParameters))
	}
	if len(inst.ProcessData) > 0 {
		fields = append(fields, g.sgenerateProcessData(inst.ProcessData))
	}
	if inst.ControlReferenceTemplate != nil {
		fields = append(fields, g.sgenerateControlReferenceTemplate(inst.ControlReferenceTemplate))
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

func (g *Generator) sgenerateApplicationSystemParameters(asp *ApplicationSystemParameters) string {
	var sb strings.Builder
	sb.WriteString("systemSpecificParameters {\r\n")
	g.indent++
	fields := make([]string, 0)
	if len(asp.VolatileMemoryQuotaC7) > 0 {
		fields = append(fields, fmt.Sprintf("volatileMemoryQuotaC7 %s", g.formatHex(asp.VolatileMemoryQuotaC7)))
	}
	if len(asp.NonVolatileMemoryQuotaC8) > 0 {
		fields = append(fields, fmt.Sprintf("nonVolatileMemoryQuotaC8 %s", g.formatHex(asp.NonVolatileMemoryQuotaC8)))
	}
	if len(asp.GlobalServiceParameters) > 0 {
		fields = append(fields, fmt.Sprintf("globalServiceParameters %s", g.formatHex(asp.GlobalServiceParameters)))
	}
	if len(asp.ImplicitSelectionParameter) > 0 {
		fields = append(fields, fmt.Sprintf("implicitSelectionParameter %s", g.formatHex(asp.ImplicitSelectionParameter)))
	}
	if len(asp.VolatileReservedMemory) > 0 {
		fields = append(fields, fmt.Sprintf("volatileReservedMemory %s", g.formatHex(asp.VolatileReservedMemory)))
	}
	if len(asp.NonVolatileReservedMemory) > 0 {
		fields = append(fields, fmt.Sprintf("nonVolatileReservedMemory %s", g.formatHex(asp.NonVolatileReservedMemory)))
	}
	if len(asp.TS102226SIMFileAccessToolkitParameter) > 0 {
		fields = append(fields, fmt.Sprintf("ts102226SIMFileAccessToolkitParameter %s", g.formatHex(asp.TS102226SIMFileAccessToolkitParameter)))
	}
	if len(asp.TS102226AdditionalContactlessParameters) > 0 {
		var isb strings.Builder
		isb.WriteString("ts102226AdditionalContactlessParameters {\r\n")
		g.indent++
		for j := 0; j < g.indent; j++ {
			isb.WriteString("  ")
		}
		isb.WriteString(fmt.Sprintf("protocolParameterData %s\r\n", g.formatHex(asp.TS102226AdditionalContactlessParameters)))
		g.indent--
		for j := 0; j < g.indent; j++ {
			isb.WriteString("  ")
		}
		isb.WriteString("}")
		fields = append(fields, isb.String())
	}
	if len(asp.ContactlessProtocolParameters) > 0 {
		fields = append(fields, fmt.Sprintf("contactlessProtocolParameters %s", g.formatHex(asp.ContactlessProtocolParameters)))
	}
	if len(asp.UserInteractionContactlessParameters) > 0 {
		fields = append(fields, fmt.Sprintf("userInteractionContactlessParameters %s", g.formatHex(asp.UserInteractionContactlessParameters)))
	}
	if len(asp.CumulativeGrantedVolatileMemory) > 0 {
		fields = append(fields, fmt.Sprintf("cumulativeGrantedVolatileMemory %s", g.formatHex(asp.CumulativeGrantedVolatileMemory)))
	}
	if len(asp.CumulativeGrantedNonVolatileMemory) > 0 {
		fields = append(fields, fmt.Sprintf("cumulativeGrantedNonVolatileMemory %s", g.formatHex(asp.CumulativeGrantedNonVolatileMemory)))
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

func (g *Generator) sgenerateUICCApplicationParameters(uap *UICCApplicationParameters) string {
	var sb strings.Builder
	sb.WriteString("applicationParameters {\r\n")
	g.indent++
	fields := make([]string, 0)
	if len(uap.UiccToolkitApplicationSpecificParametersField) > 0 {
		fields = append(fields, fmt.Sprintf("uiccToolkitApplicationSpecificParametersField %s", g.formatHex(uap.UiccToolkitApplicationSpecificParametersField)))
	}
	if len(uap.UiccAccessApplicationSpecificParametersField) > 0 {
		fields = append(fields, fmt.Sprintf("uiccAccessApplicationSpecificParametersField %s", g.formatHex(uap.UiccAccessApplicationSpecificParametersField)))
	}
	if len(uap.UiccAdministrativeAccessApplicationSpecificParametersField) > 0 {
		fields = append(fields, fmt.Sprintf("uiccAdministrativeAccessApplicationSpecificParametersField %s", g.formatHex(uap.UiccAdministrativeAccessApplicationSpecificParametersField)))
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

func (g *Generator) sgenerateKeyCompontents(comps []KeyComponent) string {
	var sb strings.Builder
	sb.WriteString("keyCompontents {\r\n") // Use typo variant to match test data
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

func (g *Generator) sgenerateOpenPersoData(opd *OpenPersoData) string {
	var sb strings.Builder
	sb.WriteString("openPersoData {\r\n")
	g.indent++
	fields := make([]string, 0)
	if len(opd.RestrictParameter) > 0 {
		fields = append(fields, fmt.Sprintf("restrictParameter %s", g.formatHex(opd.RestrictParameter)))
	}
	if len(opd.ContactlessProtocolParameters) > 0 {
		fields = append(fields, fmt.Sprintf("contactlessProtocolParameters %s", g.formatHex(opd.ContactlessProtocolParameters)))
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

func (g *Generator) sgenerateCatTpParameters(ctp *CatTpParameters) string {
	var sb strings.Builder
	sb.WriteString("catTpParameters {\r\n")
	g.indent++
	fields := make([]string, 0)
	fields = append(fields, fmt.Sprintf("catTpMaxSduSize %d", ctp.CatTpMaxSduSize))
	fields = append(fields, fmt.Sprintf("catTpMaxPduSize %d", ctp.CatTpMaxPduSize))
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

func (g *Generator) sgenerateControlReferenceTemplate(crt *ControlReferenceTemplate) string {
	var sb strings.Builder
	sb.WriteString("controlReferenceTemplate {\r\n")
	g.indent++
	fields := make([]string, 0)
	if len(crt.ApplicationProviderIdentifier) > 0 {
		fields = append(fields, fmt.Sprintf("applicationProviderIdentifier %s", g.formatHex(crt.ApplicationProviderIdentifier)))
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

func (g *Generator) sgenerateIOTOptions(opts *IOTOptions) string {
	var sb strings.Builder
	sb.WriteString("iotOptions {\r\n")
	g.indent++
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString(fmt.Sprintf("pix %s\r\n", g.formatHex(opts.PIX)))
	g.indent--
	for j := 0; j < g.indent; j++ {
		sb.WriteString("  ")
	}
	sb.WriteString("}")
	return sb.String()
}

func (g *Generator) sgenerateMandatoryAIDList(aids []MandatoryAID) string {
	var sb strings.Builder
	sb.WriteString("eUICC-Mandatory-AIDs {\r\n")
	g.indent++
	for i, aid := range aids {
		for j := 0; j < g.indent; j++ {
			sb.WriteString("  ")
		}
		sb.WriteString("{\r\n")
		g.indent++
		fields := make([]string, 0)
		fields = append(fields, fmt.Sprintf("aid %s", g.formatHex(aid.AID)))
		fields = append(fields, fmt.Sprintf("version %s", g.formatHex(aid.Version)))
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
		if i < len(aids)-1 {
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
		fields = append(fields, g.sgenerateElementHeader("app-header", app.Header))
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
	if len(pkg.NonVolatileCodeLimitC6) > 0 {
		fields = append(fields, fmt.Sprintf("nonVolatileCodeLimitC6 %s", g.formatHex(pkg.NonVolatileCodeLimitC6)))
	}
	if len(pkg.VolatileDataLimitC7) > 0 {
		fields = append(fields, fmt.Sprintf("volatileDataLimitC7 %s", g.formatHex(pkg.VolatileDataLimitC7)))
	}
	if len(pkg.NonVolatileDataLimitC8) > 0 {
		fields = append(fields, fmt.Sprintf("nonVolatileDataLimitC8 %s", g.formatHex(pkg.NonVolatileDataLimitC8)))
	}
	if len(pkg.HashValue) > 0 {
		fields = append(fields, fmt.Sprintf("hashValue %s", g.formatHex(pkg.HashValue)))
	}
	if len(pkg.LoadBlockObject) > 0 {
		fields = append(fields, fmt.Sprintf("loadBlockObject %s", g.formatHex(pkg.LoadBlockObject)))
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
		sb.WriteString(g.sgenerateApplicationInstance("", inst))
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
