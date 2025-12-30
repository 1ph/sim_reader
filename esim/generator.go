package esim

import (
	"encoding/hex"
	"fmt"
	"os"
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
	sb        *strings.Builder
	indent    int
	valueNum  int
}

func (g *Generator) write(s string) {
	g.sb.WriteString(s)
}

func (g *Generator) writeLine(s string) {
	g.writeIndent()
	g.sb.WriteString(s)
	g.sb.WriteString("\n")
}

func (g *Generator) writeIndent() {
	for i := 0; i < g.indent; i++ {
		g.sb.WriteString("  ")
	}
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
	case TagEnd:
		g.generateEnd(elem.Value.(*EndElement))
	default:
		g.write("{\n}\n")
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
	g.write("{\n")
	g.indent++

	g.writeLine(fmt.Sprintf("major-version %d,", h.MajorVersion))
	g.writeLine(fmt.Sprintf("minor-version %d,", h.MinorVersion))

	if h.ProfileType != "" {
		g.writeLine(fmt.Sprintf("profileType \"%s\",", h.ProfileType))
	}

	if len(h.ICCID) > 0 {
		g.writeLine(fmt.Sprintf("iccid '%s'H,", strings.ToUpper(hex.EncodeToString(h.ICCID))))
	}

	if h.MandatoryServices != nil {
		g.generateMandatoryServices(h.MandatoryServices)
	}

	if len(h.MandatoryGFSTEList) > 0 {
		g.generateOIDList("eUICC-Mandatory-GFSTEList", h.MandatoryGFSTEList)
	}

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateMandatoryServices(ms *MandatoryServices) {
	g.writeLine("eUICC-Mandatory-services {")
	g.indent++

	if ms.USIM {
		g.writeLine("usim NULL,")
	}
	if ms.ISIM {
		g.writeLine("isim NULL,")
	}
	if ms.CSIM {
		g.writeLine("csim NULL,")
	}
	if ms.USIMTestAlgorithm {
		g.writeLine("usim-test-algorithm NULL,")
	}
	if ms.BERTLV {
		g.writeLine("ber-tlv NULL,")
	}
	if ms.GetIdentity {
		g.writeLine("get-identity NULL,")
	}
	if ms.ProfileAX25519 {
		g.writeLine("profile-a-x25519 NULL,")
	}
	if ms.ProfileBP256 {
		g.writeLine("profile-b-p256 NULL")
	}

	g.indent--
	g.writeLine("},")
}

func (g *Generator) generateOIDList(name string, oids []OID) {
	g.writeLine(name + " {")
	g.indent++

	for i, oid := range oids {
		parts := make([]string, len(oid))
		for j, n := range oid {
			parts[j] = fmt.Sprintf("%d", n)
		}
		suffix := ","
		if i == len(oids)-1 {
			suffix = ""
		}
		g.writeLine("{ " + strings.Join(parts, " ") + " }" + suffix)
	}

	g.indent--
	g.writeLine("}")
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
	g.write("{\n")
	g.indent++

	if mf.MFHeader != nil {
		g.generateElementHeader("mf-header", mf.MFHeader)
	}

	if len(mf.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(mf.TemplateID)))
	}

	if mf.MF != nil {
		g.writeLine("mf {")
		g.indent++
		g.generateFileDescriptorInner("fileDescriptor", mf.MF)
		g.indent--
		g.writeLine("},")
	}

	if mf.EF_PL != nil {
		g.generateElementaryFile("ef-pl", mf.EF_PL)
	}
	if mf.EF_ICCID != nil {
		g.generateElementaryFile("ef-iccid", mf.EF_ICCID)
	}
	if mf.EF_DIR != nil {
		g.generateElementaryFile("ef-dir", mf.EF_DIR)
	}
	if mf.EF_ARR != nil {
		g.generateElementaryFile("ef-arr", mf.EF_ARR)
	}
	if mf.EF_UMPC != nil {
		g.generateElementaryFile("ef-umpc", mf.EF_UMPC)
	}

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateElementHeader(name string, eh *ElementHeader) {
	g.writeLine(name + " {")
	g.indent++

	if eh.Mandated {
		g.writeLine("mandated NULL,")
	}
	g.writeLine(fmt.Sprintf("identification %d", eh.Identification))

	g.indent--
	g.writeLine("},")
}

func (g *Generator) generateFileDescriptorWrapper(name string, fd *FileDescriptor) {
	g.writeLine(name + " {")
	g.indent++
	g.generateFileDescriptorInner("fileDescriptor", fd)
	g.indent--
	g.writeLine("},")
}

func (g *Generator) generateFileDescriptorInner(name string, fd *FileDescriptor) {
	g.writeLine(name + " : {")
	g.indent++

	if len(fd.FileDescriptor) > 0 {
		g.writeLine(fmt.Sprintf("fileDescriptor '%s'H,", strings.ToUpper(hex.EncodeToString(fd.FileDescriptor))))
	}
	if fd.FileID != 0 {
		g.writeLine(fmt.Sprintf("fileID '%04X'H,", fd.FileID))
	}
	if fd.LCSI != 0 {
		g.writeLine(fmt.Sprintf("lcsi '%02X'H,", fd.LCSI))
	}
	if len(fd.SecurityAttributesReferenced) > 0 {
		g.writeLine(fmt.Sprintf("securityAttributesReferenced '%s'H,", strings.ToUpper(hex.EncodeToString(fd.SecurityAttributesReferenced))))
	}
	if fd.EFFileSize > 0 {
		hexStr := fmt.Sprintf("%X", fd.EFFileSize)
		if len(hexStr)%2 != 0 {
			hexStr = "0" + hexStr
		}
		g.writeLine(fmt.Sprintf("efFileSize '%s'H,", hexStr))
	}
	if fd.ShortEFID != 0 {
		g.writeLine(fmt.Sprintf("shortEFID '%02X'H,", fd.ShortEFID))
	}
	if len(fd.DFName) > 0 {
		g.writeLine(fmt.Sprintf("dfName '%s'H,", strings.ToUpper(hex.EncodeToString(fd.DFName))))
	}
	if len(fd.PinStatusTemplateDO) > 0 {
		g.writeLine(fmt.Sprintf("pinStatusTemplateDO '%s'H,", strings.ToUpper(hex.EncodeToString(fd.PinStatusTemplateDO))))
	}
	if len(fd.LinkPath) > 0 {
		g.writeLine(fmt.Sprintf("linkPath '%s'H,", strings.ToUpper(hex.EncodeToString(fd.LinkPath))))
	}
	if fd.ProprietaryEFInfo != nil {
		g.generateProprietaryEFInfo(fd.ProprietaryEFInfo)
	}

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateProprietaryEFInfo(pei *ProprietaryEFInfo) {
	g.writeLine("proprietaryEFInfo {")
	g.indent++

	g.writeLine(fmt.Sprintf("specialFileInformation '%02X'H,", pei.SpecialFileInformation))

	if len(pei.FillPattern) > 0 {
		g.writeLine(fmt.Sprintf("fillPattern '%s'H,", strings.ToUpper(hex.EncodeToString(pei.FillPattern))))
	}
	if len(pei.RepeatPattern) > 0 {
		g.writeLine(fmt.Sprintf("repeatPattern '%s'H", strings.ToUpper(hex.EncodeToString(pei.RepeatPattern))))
	}

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateElementaryFile(name string, ef *ElementaryFile) {
	g.writeLine(name + " {")
	g.indent++

	// Use Raw elements if available for exact round-trip
	if len(ef.Raw) > 0 {
		for _, elem := range ef.Raw {
			switch elem.Type {
			case FileElementDoNotCreate:
				g.writeLine("doNotCreate NULL,")
			case FileElementDescriptor:
				if elem.Descriptor != nil {
					g.generateFileDescriptorInner("fileDescriptor", elem.Descriptor)
					g.write(",\n")
				}
			case FileElementOffset:
				g.writeLine(fmt.Sprintf("fillFileOffset : %d,", elem.Offset))
			case FileElementContent:
				g.writeLine(fmt.Sprintf("fillFileContent : '%s'H,", strings.ToUpper(hex.EncodeToString(elem.Content))))
			}
		}
	} else {
		// Fallback to simplified structure
		if ef.Descriptor != nil {
			g.generateFileDescriptorInner("fileDescriptor", ef.Descriptor)
			g.write(",\n")
		}

		for _, fc := range ef.FillContents {
			if fc.Offset > 0 {
				g.writeLine(fmt.Sprintf("fillFileOffset : %d,", fc.Offset))
			}
			g.writeLine(fmt.Sprintf("fillFileContent : '%s'H,", strings.ToUpper(hex.EncodeToString(fc.Content))))
		}
	}

	g.indent--
	g.writeLine("},")
}

// ============================================================================
// PUK/PIN Codes generator
// ============================================================================

func (g *Generator) generatePUKCodes(puk *PUKCodes) {
	g.write("{\n")
	g.indent++

	if puk.Header != nil {
		g.generateElementHeader("puk-Header", puk.Header)
	}

	if len(puk.Codes) > 0 {
		g.writeLine("pukCodes {")
		g.indent++

		for i, code := range puk.Codes {
			g.writeLine("{")
			g.indent++

			g.writeLine(fmt.Sprintf("keyReference %s,", g.getKeyRefName(code.KeyReference, true)))
			g.writeLine(fmt.Sprintf("pukValue '%s'H,", strings.ToUpper(hex.EncodeToString(code.PUKValue))))
			g.writeLine(fmt.Sprintf("maxNumOfAttemps-retryNumLeft %d", code.MaxNumOfAttempsRetryNumLeft))

			g.indent--
			suffix := ","
			if i == len(puk.Codes)-1 {
				suffix = ""
			}
			g.writeLine("}" + suffix)
		}

		g.indent--
		g.writeLine("}")
	}

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generatePINCodes(pin *PINCodes) {
	g.write("{\n")
	g.indent++

	if pin.Header != nil {
		g.generateElementHeader("pin-Header", pin.Header)
	}

	if len(pin.Configs) > 0 {
		g.writeLine("pinCodes pinconfig : {")
		g.indent++

		for i, config := range pin.Configs {
			g.writeLine("{")
			g.indent++

			g.writeLine(fmt.Sprintf("keyReference %s,", g.getKeyRefName(config.KeyReference, false)))
			g.writeLine(fmt.Sprintf("pinValue '%s'H,", strings.ToUpper(hex.EncodeToString(config.PINValue))))
			if config.UnblockingPINReference != 0 {
				g.writeLine(fmt.Sprintf("unblockingPINReference %s,", g.getKeyRefName(config.UnblockingPINReference, true)))
			}
			g.writeLine(fmt.Sprintf("pinAttributes %d,", config.PINAttributes))
			g.writeLine(fmt.Sprintf("maxNumOfAttemps-retryNumLeft %d", config.MaxNumOfAttempsRetryNumLeft))

			g.indent--
			suffix := ","
			if i == len(pin.Configs)-1 {
				suffix = ""
			}
			g.writeLine("}" + suffix)
		}

		g.indent--
		g.writeLine("}")
	}

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
	g.write("{\n")
	g.indent++

	if t.Header != nil {
		g.generateElementHeader("telecom-header", t.Header)
	}

	if len(t.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(t.TemplateID)))
	}

	if t.DFTelecom != nil {
		g.generateFileDescriptorWrapper("df-telecom", t.DFTelecom)
	}

	if t.EF_ARR != nil {
		g.generateElementaryFile("ef-arr", t.EF_ARR)
	}
	if t.EF_SUME != nil {
		g.generateElementaryFile("ef-sume", t.EF_SUME)
	}
	if t.EF_PSISMSC != nil {
		g.generateElementaryFile("ef-psismsc", t.EF_PSISMSC)
	}
	if t.DFGraphics != nil {
		g.generateFileDescriptorWrapper("df-graphics", t.DFGraphics)
	}
	if t.EF_IMG != nil {
		g.generateElementaryFile("ef-img", t.EF_IMG)
	}
	if t.EF_LaunchSCWS != nil {
		g.generateElementaryFile("ef-launch-scws", t.EF_LaunchSCWS)
	}
	if t.DFPhonebook != nil {
		g.generateFileDescriptorWrapper("df-phonebook", t.DFPhonebook)
	}
	if t.EF_PBR != nil {
		g.generateElementaryFile("ef-pbr", t.EF_PBR)
	}
	if t.EF_PSC != nil {
		g.generateElementaryFile("ef-psc", t.EF_PSC)
	}
	if t.EF_CC != nil {
		g.generateElementaryFile("ef-cc", t.EF_CC)
	}
	if t.EF_PUID != nil {
		g.generateElementaryFile("ef-puid", t.EF_PUID)
	}
	if t.DFMMSS != nil {
		g.generateFileDescriptorWrapper("df-mmss", t.DFMMSS)
	}
	if t.EF_MLPL != nil {
		g.generateElementaryFile("ef-mlpl", t.EF_MLPL)
	}
	if t.EF_MSPL != nil {
		g.generateElementaryFile("ef-mspl", t.EF_MSPL)
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// USIM generator
// ============================================================================

func (g *Generator) generateUSIM(u *USIMApplication) {
	g.write("{\n")
	g.indent++

	if u.Header != nil {
		g.generateElementHeader("usim-header", u.Header)
	}

	if len(u.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(u.TemplateID)))
	}

	if u.ADFUSIM != nil {
		g.generateFileDescriptorWrapper("adf-usim", u.ADFUSIM)
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
			g.generateElementaryFile(f.name, f.ef)
		}
	}

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateOptUSIM(u *OptionalUSIM) {
	g.write("{\n")
	g.indent++

	if u.Header != nil {
		g.generateElementHeader("optusim-header", u.Header)
	}

	if len(u.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(u.TemplateID)))
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
		{"ef-mmsn", u.EF_MMSN},
		{"ef-ext8", u.EF_EXT8},
		{"ef-mmsicp", u.EF_MMSICP},
		{"ef-mmsup", u.EF_MMSUP},
		{"ef-mmsucp", u.EF_MMSUCP},
		{"ef-nia", u.EF_NIA},
		{"ef-vgcsca", u.EF_VGCSCA},
		{"ef-vbsca", u.EF_VBSCA},
		{"ef-ehplmn", u.EF_EHPLMN},
		{"ef-ehplmnpi", u.EF_EHPLMNPI},
		{"ef-lrplmnsi", u.EF_LRPLMNSI},
		{"ef-nasconfig", u.EF_NASCONFIG},
		{"ef-fdnuri", u.EF_FDNURI},
		{"ef-sdnuri", u.EF_SDNURI},
	}

	for _, f := range efFields {
		if f.ef != nil {
			g.generateElementaryFile(f.name, f.ef)
		}
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// ISIM generator
// ============================================================================

func (g *Generator) generateISIM(i *ISIMApplication) {
	g.write("{\n")
	g.indent++

	if i.Header != nil {
		g.generateElementHeader("isim-header", i.Header)
	}

	if len(i.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(i.TemplateID)))
	}

	if i.ADFISIM != nil {
		g.generateFileDescriptorWrapper("adf-isim", i.ADFISIM)
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
			g.generateElementaryFile(f.name, f.ef)
		}
	}

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateOptISIM(i *OptionalISIM) {
	g.write("{\n")
	g.indent++

	if i.Header != nil {
		g.generateElementHeader("optisim-header", i.Header)
	}

	if len(i.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(i.TemplateID)))
	}

	efFields := []struct {
		name string
		ef   *ElementaryFile
	}{
		{"ef-pcscf", i.EF_PCSCF},
		{"ef-gbabp", i.EF_GBABP},
		{"ef-gbanl", i.EF_GBANL},
	}

	for _, f := range efFields {
		if f.ef != nil {
			g.generateElementaryFile(f.name, f.ef)
		}
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// CSIM generator
// ============================================================================

func (g *Generator) generateCSIM(c *CSIMApplication) {
	g.write("{\n")
	g.indent++

	if c.Header != nil {
		g.generateElementHeader("csim-header", c.Header)
	}

	if len(c.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(c.TemplateID)))
	}

	if c.ADFCSIM != nil {
		g.generateFileDescriptorWrapper("adf-csim", c.ADFCSIM)
	}

	if c.EF_ARR != nil {
		g.generateElementaryFile("ef-arr", c.EF_ARR)
	}

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateOptCSIM(c *OptionalCSIM) {
	g.write("{\n")
	g.indent++

	if c.Header != nil {
		g.generateElementHeader("optcsim-header", c.Header)
	}

	if len(c.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(c.TemplateID)))
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// GSM Access generator
// ============================================================================

func (g *Generator) generateGSMAccess(gsm *GSMAccessDF) {
	g.write("{\n")
	g.indent++

	if gsm.Header != nil {
		g.generateElementHeader("gsm-access-header", gsm.Header)
	}

	if len(gsm.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(gsm.TemplateID)))
	}

	if gsm.DFGSMAccess != nil {
		g.generateFileDescriptorWrapper("df-gsm-access", gsm.DFGSMAccess)
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
			g.generateElementaryFile(f.name, f.ef)
		}
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// DF-5GS generator
// ============================================================================

func (g *Generator) generateDF5GS(d *DF5GS) {
	g.write("{\n")
	g.indent++

	if d.Header != nil {
		g.generateElementHeader("df-5gs-header", d.Header)
	}

	if len(d.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(d.TemplateID)))
	}

	if d.DFDF5GS != nil {
		g.generateFileDescriptorWrapper("df-df-5gs", d.DFDF5GS)
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
			g.generateElementaryFile(f.name, f.ef)
		}
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// DF-SAIP generator
// ============================================================================

func (g *Generator) generateDFSAIP(d *DFSAIP) {
	g.write("{\n")
	g.indent++

	if d.Header != nil {
		g.generateElementHeader("df-saip-header", d.Header)
	}

	if len(d.TemplateID) > 0 {
		g.writeLine(fmt.Sprintf("templateID %s,", g.generateOID(d.TemplateID)))
	}

	if d.DFDFSAIP != nil {
		g.generateFileDescriptorWrapper("df-df-saip", d.DFDFSAIP)
	}

	if d.EF_SUCI_CALC_INFO_USIM != nil {
		g.generateElementaryFile("ef-suci-calc-info-usim", d.EF_SUCI_CALC_INFO_USIM)
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// AKA Parameter generator
// ============================================================================

func (g *Generator) generateAKAParameter(aka *AKAParameter) {
	g.write("{\n")
	g.indent++

	if aka.Header != nil {
		g.generateElementHeader("aka-header", aka.Header)
	}

	if aka.AlgoConfig != nil {
		g.writeLine("algoConfiguration algoParameter : {")
		g.indent++

		g.writeLine(fmt.Sprintf("algorithmID %s,", g.getAlgorithmIDName(aka.AlgoConfig.AlgorithmID)))
		g.writeLine(fmt.Sprintf("algorithmOptions '%02X'H,", aka.AlgoConfig.AlgorithmOptions))

		if len(aka.AlgoConfig.Key) > 0 {
			g.writeLine(fmt.Sprintf("key '%s'H,", strings.ToUpper(hex.EncodeToString(aka.AlgoConfig.Key))))
		}
		if len(aka.AlgoConfig.OPC) > 0 {
			g.writeLine(fmt.Sprintf("opc '%s'H,", strings.ToUpper(hex.EncodeToString(aka.AlgoConfig.OPC))))
		}
		if len(aka.AlgoConfig.RotationConstants) > 0 {
			g.writeLine(fmt.Sprintf("rotationConstants '%s'H,", strings.ToUpper(hex.EncodeToString(aka.AlgoConfig.RotationConstants))))
		}
		if len(aka.AlgoConfig.XoringConstants) > 0 {
			g.writeLine(fmt.Sprintf("xoringConstants '%s'H,", strings.ToUpper(hex.EncodeToString(aka.AlgoConfig.XoringConstants))))
		}
		if aka.AlgoConfig.NumberOfKeccak > 0 {
			g.writeLine(fmt.Sprintf("numberOfKeccak %d", aka.AlgoConfig.NumberOfKeccak))
		}

		g.indent--
		g.writeLine("},")
	}

	g.writeLine(fmt.Sprintf("sqnOptions '%02X'H,", aka.SQNOptions))

	if len(aka.SQNDelta) > 0 {
		g.writeLine(fmt.Sprintf("sqnDelta '%s'H,", strings.ToUpper(hex.EncodeToString(aka.SQNDelta))))
	}
	if len(aka.SQNAgeLimit) > 0 {
		g.writeLine(fmt.Sprintf("sqnAgeLimit '%s'H,", strings.ToUpper(hex.EncodeToString(aka.SQNAgeLimit))))
	}

	if len(aka.SQNInit) > 0 {
		g.writeLine("sqnInit {")
		g.indent++
		for i, sqn := range aka.SQNInit {
			suffix := ","
			if i == len(aka.SQNInit)-1 {
				suffix = ""
			}
			g.writeLine(fmt.Sprintf("'%s'H%s", strings.ToUpper(hex.EncodeToString(sqn)), suffix))
		}
		g.indent--
		g.writeLine("}")
	}

	g.indent--
	g.writeLine("}")
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
	g.write("{\n")
	g.indent++

	if cdma.Header != nil {
		g.generateElementHeader("cdma-header", cdma.Header)
	}

	if len(cdma.AuthenticationKey) > 0 {
		g.writeLine(fmt.Sprintf("authenticationKey '%s'H,", strings.ToUpper(hex.EncodeToString(cdma.AuthenticationKey))))
	}
	if len(cdma.SSD) > 0 {
		g.writeLine(fmt.Sprintf("ssd '%s'H,", strings.ToUpper(hex.EncodeToString(cdma.SSD))))
	}
	if len(cdma.HRPDAccessAuthenticationData) > 0 {
		g.writeLine(fmt.Sprintf("hrpdAccessAuthenticationData '%s'H,", strings.ToUpper(hex.EncodeToString(cdma.HRPDAccessAuthenticationData))))
	}
	if len(cdma.SimpleIPAuthenticationData) > 0 {
		g.writeLine(fmt.Sprintf("simpleIPAuthenticationData '%s'H,", strings.ToUpper(hex.EncodeToString(cdma.SimpleIPAuthenticationData))))
	}
	if len(cdma.MobileIPAuthenticationData) > 0 {
		g.writeLine(fmt.Sprintf("mobileIPAuthenticationData '%s'H", strings.ToUpper(hex.EncodeToString(cdma.MobileIPAuthenticationData))))
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// Generic File Management generator
// ============================================================================

func (g *Generator) generateGenericFileManagement(gfm *GenericFileManagement) {
	g.write("{\n")
	g.indent++

	if gfm.Header != nil {
		g.generateElementHeader("gfm-header", gfm.Header)
	}

	if len(gfm.FileManagementCMDs) > 0 {
		g.writeLine("fileManagementCMD {")
		g.indent++

		for _, cmd := range gfm.FileManagementCMDs {
			g.writeLine("{")
			g.indent++

			for _, item := range cmd {
				switch item.ItemType {
				case 0: // filePath
					g.writeLine(fmt.Sprintf("filePath : '%s'H,", strings.ToUpper(hex.EncodeToString(item.FilePath))))
				case 1: // createFCP
					if item.CreateFCP != nil {
						g.writeLine("createFCP : {")
						g.indent++
						g.generateFileDescriptorContent(item.CreateFCP)
						g.indent--
						g.writeLine("},")
					}
				case 2: // fillFileContent
					g.writeLine(fmt.Sprintf("fillFileContent : '%s'H,", strings.ToUpper(hex.EncodeToString(item.FillFileContent))))
				case 3: // fillFileOffset
					g.writeLine(fmt.Sprintf("fillFileOffset : %d,", item.FillFileOffset))
				}
			}

			g.indent--
			g.writeLine("}")
		}

		g.indent--
		g.writeLine("}")
	}

	g.indent--
	g.writeLine("}")
}

func (g *Generator) generateFileDescriptorContent(fd *FileDescriptor) {
	if len(fd.FileDescriptor) > 0 {
		g.writeLine(fmt.Sprintf("fileDescriptor '%s'H,", strings.ToUpper(hex.EncodeToString(fd.FileDescriptor))))
	}
	if fd.FileID != 0 {
		g.writeLine(fmt.Sprintf("fileID '%04X'H,", fd.FileID))
	}
	if fd.LCSI != 0 {
		g.writeLine(fmt.Sprintf("lcsi '%02X'H,", fd.LCSI))
	}
	if len(fd.SecurityAttributesReferenced) > 0 {
		g.writeLine(fmt.Sprintf("securityAttributesReferenced '%s'H,", strings.ToUpper(hex.EncodeToString(fd.SecurityAttributesReferenced))))
	}
	if fd.EFFileSize > 0 {
		hexStr := fmt.Sprintf("%X", fd.EFFileSize)
		if len(hexStr)%2 != 0 {
			hexStr = "0" + hexStr
		}
		g.writeLine(fmt.Sprintf("efFileSize '%s'H,", hexStr))
	}
	if fd.ShortEFID != 0 {
		g.writeLine(fmt.Sprintf("shortEFID '%02X'H,", fd.ShortEFID))
	}
	if len(fd.DFName) > 0 {
		g.writeLine(fmt.Sprintf("dfName '%s'H,", strings.ToUpper(hex.EncodeToString(fd.DFName))))
	}
	if len(fd.PinStatusTemplateDO) > 0 {
		g.writeLine(fmt.Sprintf("pinStatusTemplateDO '%s'H,", strings.ToUpper(hex.EncodeToString(fd.PinStatusTemplateDO))))
	}
	if len(fd.LinkPath) > 0 {
		g.writeLine(fmt.Sprintf("linkPath '%s'H,", strings.ToUpper(hex.EncodeToString(fd.LinkPath))))
	}
	if fd.ProprietaryEFInfo != nil {
		g.generateProprietaryEFInfo(fd.ProprietaryEFInfo)
	}
}

// ============================================================================
// Security Domain generator
// ============================================================================

func (g *Generator) generateSecurityDomain(sd *SecurityDomain) {
	g.write("{\n")
	g.indent++

	if sd.Header != nil {
		g.generateElementHeader("sd-Header", sd.Header)
	}

	if sd.Instance != nil {
		g.writeLine("instance {")
		g.indent++

		if len(sd.Instance.ApplicationLoadPackageAID) > 0 {
			g.writeLine(fmt.Sprintf("applicationLoadPackageAID '%s'H,", strings.ToUpper(hex.EncodeToString(sd.Instance.ApplicationLoadPackageAID))))
		}
		if len(sd.Instance.ClassAID) > 0 {
			g.writeLine(fmt.Sprintf("classAID '%s'H,", strings.ToUpper(hex.EncodeToString(sd.Instance.ClassAID))))
		}
		if len(sd.Instance.InstanceAID) > 0 {
			g.writeLine(fmt.Sprintf("instanceAID '%s'H,", strings.ToUpper(hex.EncodeToString(sd.Instance.InstanceAID))))
		}
		if len(sd.Instance.ApplicationPrivileges) > 0 {
			g.writeLine(fmt.Sprintf("applicationPrivileges '%s'H,", strings.ToUpper(hex.EncodeToString(sd.Instance.ApplicationPrivileges))))
		}
		g.writeLine(fmt.Sprintf("lifeCycleState '%02X'H,", sd.Instance.LifeCycleState))
		if len(sd.Instance.ApplicationSpecificParamsC9) > 0 {
			g.writeLine(fmt.Sprintf("applicationSpecificParametersC9 '%s'H,", strings.ToUpper(hex.EncodeToString(sd.Instance.ApplicationSpecificParamsC9))))
		}
		if sd.Instance.ApplicationParameters != nil && len(sd.Instance.ApplicationParameters.UIICToolkitApplicationSpecificParametersField) > 0 {
			g.writeLine("applicationParameters {")
			g.indent++
			g.writeLine(fmt.Sprintf("uiccToolkitApplicationSpecificParametersField '%s'H", strings.ToUpper(hex.EncodeToString(sd.Instance.ApplicationParameters.UIICToolkitApplicationSpecificParametersField))))
			g.indent--
			g.writeLine("}")
		}

		g.indent--
		g.writeLine("},")
	}

	if len(sd.KeyList) > 0 {
		g.writeLine("keyList {")
		g.indent++

		for i, key := range sd.KeyList {
			g.writeLine("{")
			g.indent++

			g.writeLine(fmt.Sprintf("keyUsageQualifier '%02X'H,", key.KeyUsageQualifier))
			g.writeLine(fmt.Sprintf("keyAccess '%02X'H,", key.KeyAccess))
			g.writeLine(fmt.Sprintf("keyIdentifier '%02X'H,", key.KeyIdentifier))
			g.writeLine(fmt.Sprintf("keyVersionNumber '%02X'H,", key.KeyVersionNumber))

			if len(key.KeyComponents) > 0 {
				g.writeLine("keyCompontents {")
				g.indent++
				for j, comp := range key.KeyComponents {
					g.writeLine("{")
					g.indent++
					g.writeLine(fmt.Sprintf("keyType '%02X'H,", comp.KeyType))
					g.writeLine(fmt.Sprintf("keyData '%s'H,", strings.ToUpper(hex.EncodeToString(comp.KeyData))))
					g.writeLine(fmt.Sprintf("macLength %d", comp.MACLength))
					g.indent--
					ksuffix := ","
					if j == len(key.KeyComponents)-1 {
						ksuffix = ""
					}
					g.writeLine("}" + ksuffix)
				}
				g.indent--
				g.writeLine("}")
			}

			g.indent--
			suffix := ","
			if i == len(sd.KeyList)-1 {
				suffix = ""
			}
			g.writeLine("}" + suffix)
		}

		g.indent--
		g.writeLine("},")
	}

	if len(sd.SDPersoData) > 0 {
		g.writeLine("sdPersoData {")
		g.indent++
		g.writeLine(fmt.Sprintf("'%s'H", strings.ToUpper(hex.EncodeToString(sd.SDPersoData))))
		g.indent--
		g.writeLine("}")
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// RFM generator
// ============================================================================

func (g *Generator) generateRFM(rfm *RFMConfig) {
	g.write("{\n")
	g.indent++

	if rfm.Header != nil {
		g.generateElementHeader("rfm-header", rfm.Header)
	}

	if len(rfm.InstanceAID) > 0 {
		g.writeLine(fmt.Sprintf("instanceAID '%s'H,", strings.ToUpper(hex.EncodeToString(rfm.InstanceAID))))
	}

	if len(rfm.TARList) > 0 {
		g.writeLine("tarList {")
		g.indent++
		for i, tar := range rfm.TARList {
			suffix := ","
			if i == len(rfm.TARList)-1 {
				suffix = ""
			}
			g.writeLine(fmt.Sprintf("'%s'H%s", strings.ToUpper(hex.EncodeToString(tar)), suffix))
		}
		g.indent--
		g.writeLine("},")
	}

	g.writeLine(fmt.Sprintf("minimumSecurityLevel '%02X'H,", rfm.MinimumSecurityLevel))
	g.writeLine(fmt.Sprintf("uiccAccessDomain '%02X'H,", rfm.UICCAccessDomain))
	g.writeLine(fmt.Sprintf("uiccAdminAccessDomain '%02X'H,", rfm.UICCAdminAccessDomain))

	if rfm.ADFRFMAccess != nil {
		g.writeLine("adfRFMAccess {")
		g.indent++
		g.writeLine(fmt.Sprintf("adfAID '%s'H,", strings.ToUpper(hex.EncodeToString(rfm.ADFRFMAccess.ADFAID))))
		g.writeLine(fmt.Sprintf("adfAccessDomain '%02X'H,", rfm.ADFRFMAccess.ADFAccessDomain))
		g.writeLine(fmt.Sprintf("adfAdminAccessDomain '%02X'H", rfm.ADFRFMAccess.ADFAdminAccessDomain))
		g.indent--
		g.writeLine("}")
	}

	g.indent--
	g.writeLine("}")
}

// ============================================================================
// End generator
// ============================================================================

func (g *Generator) generateEnd(end *EndElement) {
	g.write("{\n")
	g.indent++

	if end.Header != nil {
		g.generateElementHeader("end-header", end.Header)
	}

	g.indent--
	g.writeLine("}")
}

