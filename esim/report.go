package esim

import (
	"encoding/hex"
	"fmt"
	"sim_reader/sim"
	"strings"
)

// ProfileReporter generates human-readable reports for eSIM profiles
type ProfileReporter struct {
	indent int
	sb     strings.Builder
}

// DetailedReport generates a comprehensive human-readable report of the profile
func DetailedReport(p *Profile) string {
	r := &ProfileReporter{}
	r.generate(p)
	return r.sb.String()
}

func (r *ProfileReporter) generate(p *Profile) {
	r.writeLine("=== Detailed eSIM Profile Report ===")
	r.writeLine("")

	for i, elem := range p.Elements {
		r.writeIndent()
		name := GetProfileElementName(elem.Tag)
		peName := "PE-" + strings.ToUpper(name)
		if name == "header" {
			peName = "PE-Header"
		}
		r.write(fmt.Sprintf("[%2d] value%d ProfileElement ::= %s : ", i, i+1, peName))
		r.generateElement(&elem)
		r.writeLine("")
	}
}

func (r *ProfileReporter) write(s string) {
	r.sb.WriteString(s)
}

func (r *ProfileReporter) writeLine(s string) {
	r.sb.WriteString(s)
	r.sb.WriteString("\n")
}

func (r *ProfileReporter) writeIndent() {
	for i := 0; i < r.indent; i++ {
		r.sb.WriteString("  ")
	}
}

func (r *ProfileReporter) formatHex(b []byte) string {
	if len(b) == 0 {
		return "''H"
	}
	return fmt.Sprintf("'%s'H", strings.ToUpper(hex.EncodeToString(b)))
}

func (r *ProfileReporter) generateElement(elem *ProfileElement) {
	switch elem.Tag {
	case TagProfileHeader:
		r.generateHeader(elem.Value.(*ProfileHeader))
	case TagMF:
		r.generateMF(elem.Value.(*MasterFile))
	case TagPukCodes:
		r.generatePUKCodes(elem.Value.(*PUKCodes))
	case TagPinCodes:
		r.generatePINCodes(elem.Value.(*PINCodes))
	case TagTelecom:
		r.generateTelecom(elem.Value.(*TelecomDF))
	case TagUSIM:
		r.generateUSIM(elem.Value.(*USIMApplication))
	case TagOptUSIM:
		r.generateOptUSIM(elem.Value.(*OptionalUSIM))
	case TagISIM:
		r.generateISIM(elem.Value.(*ISIMApplication))
	case TagOptISIM:
		r.generateOptISIM(elem.Value.(*OptionalISIM))
	case TagCSIM:
		r.generateCSIM(elem.Value.(*CSIMApplication))
	case TagOptCSIM:
		r.generateOptCSIM(elem.Value.(*OptionalCSIM))
	case TagAKAParameter:
		r.generateAKA(elem.Value.(*AKAParameter))
	case TagGenericFileManagement:
		r.generateGFM(elem.Value.(*GenericFileManagement))
	case TagSecurityDomain:
		r.generateSD(elem.Value.(*SecurityDomain))
	case TagRFM:
		r.generateRFM(elem.Value.(*RFMConfig))
	case TagApplication:
		r.generateApp(elem.Value.(*Application))
	case TagEnd:
		r.generateEnd(elem.Value.(*EndElement))
	case TagGSMAccess:
		r.generateGSMAccess(elem.Value.(*GSMAccessDF))
	case TagDF5GS:
		r.generateDF5GS(elem.Value.(*DF5GS))
	case TagDFSAIP:
		r.generateDFSAIP(elem.Value.(*DFSAIP))
	default:
		r.writeLine("{")
		r.indent++
		r.writeIndent()
		r.writeLine("-- [Decoded data not yet supported for this element]")
		r.indent--
		r.writeIndent()
		r.write("}")
	}
}

func (r *ProfileReporter) generateHeader(h *ProfileHeader) {
	r.writeLine("{")
	r.indent++
	r.writeLine(fmt.Sprintf("major-version %d,", h.MajorVersion))
	r.writeLine(fmt.Sprintf("minor-version %d,", h.MinorVersion))
	if h.ProfileType != "" {
		r.writeLine(fmt.Sprintf("profileType \"%s\",", h.ProfileType))
	}
	iccid := decodeBCD(h.ICCID)
	r.writeLine(fmt.Sprintf("iccid %s, -- %s", r.formatHex(h.ICCID), iccid))
	
	if h.MandatoryServices != nil {
		r.writeIndent()
		r.write("eUICC-Mandatory-services { ")
		var svcs []string
		ms := h.MandatoryServices
		if ms.USIM { svcs = append(svcs, "usim") }
		if ms.ISIM { svcs = append(svcs, "isim") }
		if ms.CSIM { svcs = append(svcs, "csim") }
		if ms.Milenage { svcs = append(svcs, "milenage") }
		if ms.TUAK128 { svcs = append(svcs, "tuak128") }
		if ms.JavaCard { svcs = append(svcs, "javacard") }
		if ms.USIMTestAlgorithm { svcs = append(svcs, "usim-test-algorithm") }
		if ms.GetIdentity { svcs = append(svcs, "get-identity") }
		if ms.ProfileAX25519 { svcs = append(svcs, "profile-a-x25519") }
		if ms.ProfileBP256 { svcs = append(svcs, "profile-b-p256") }
		r.write(strings.Join(svcs, ", "))
		r.writeLine(" },")
	}

	if len(h.MandatoryGFSTEList) > 0 {
		r.writeIndent()
		r.writeLine("eUICC-Mandatory-GFSTEList {")
		r.indent++
		for i, oid := range h.MandatoryGFSTEList {
			r.writeIndent()
			r.write(fmt.Sprintf("{ %s }", r.formatOID(oid)))
			if i < len(h.MandatoryGFSTEList)-1 {
				r.write(",")
			}
			r.writeLine("")
		}
		r.indent--
		r.writeIndent()
		r.writeLine("}")
	}

	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) formatOID(oid OID) string {
	parts := make([]string, len(oid))
	for i, n := range oid {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, " ")
}

func (r *ProfileReporter) generateMF(mf *MasterFile) {
	r.writeLine("{")
	r.indent++
	
	if mf.TemplateID != nil {
		r.writeLine(fmt.Sprintf("templateID { %s },", r.formatOID(mf.TemplateID)))
	}

	r.generateEF("ef-pl", mf.EF_PL, 0)
	r.generateEF("ef-iccid", mf.EF_ICCID, 0)
	r.generateEF("ef-dir", mf.EF_DIR, 0)
	r.generateEF("ef-arr", mf.EF_ARR, 0)
	r.generateEF("ef-umpc", mf.EF_UMPC, 0)

	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateEF(name string, ef *ElementaryFile, parentID uint16) {
	if ef == nil {
		return
	}
	r.writeIndent()
	r.write(name + " ")
	r.writeLine("{")
	r.indent++

	if ef.Descriptor != nil {
		r.writeIndent()
		r.writeLine("fileDescriptor : {")
		r.indent++
		if len(ef.Descriptor.FileID) > 0 {
			r.writeIndent()
			r.writeLine(fmt.Sprintf("fileID %s,", r.formatHex(ef.Descriptor.FileID)))
		}
		if len(ef.Descriptor.FileDescriptor) > 0 {
			r.writeIndent()
			r.writeLine(fmt.Sprintf("fileDescriptor %s, -- %s", r.formatHex(ef.Descriptor.FileDescriptor), sim.DecodeFCP(ef.Descriptor.FileDescriptor)))
		}
		if len(ef.Descriptor.ShortEFID) > 0 {
			r.writeIndent()
			r.writeLine(fmt.Sprintf("shortEFID %s,", r.formatHex(ef.Descriptor.ShortEFID)))
		}
		r.indent--
		r.writeIndent()
		r.writeLine("},")
	}

	for _, fc := range ef.FillContents {
		r.writeIndent()
		if fc.Offset > 0 {
			r.write(fmt.Sprintf("fillFileOffset : %d, ", fc.Offset))
		}
		r.write(fmt.Sprintf("fillFileContent : %s", r.formatHex(fc.Content)))
		
		// Detailed content decoding
		comment := r.decodeFileContent(ef.Descriptor, fc.Content)
		if comment != "" {
			r.write(" -- " + comment)
		}
		r.writeLine(",")
	}

	r.indent--
	r.writeIndent()
	r.writeLine("},")
}

func (r *ProfileReporter) decodeFileContent(fd *FileDescriptor, data []byte) string {
	if fd == nil || len(fd.FileID) < 2 {
		return ""
	}
	fileID := uint16(fd.FileID[0])<<8 | uint16(fd.FileID[1])
	
	switch fileID {
	case 0x2FE2: // EF_ICCID
		return sim.DecodeICCID(data)
	case 0x6F07: // EF_IMSI
		return sim.DecodeIMSI(data)
	case 0x2F00: // EF_DIR
		return sim.DecodeDIR(data)
	case 0x6F38: // EF_UST
		services := sim.DecodeServiceTableNames(data, false)
		if len(services) > 0 {
			return "Enabled: " + strings.Join(services, ", ")
		}
	case 0x6FAD: // EF_AD
		ad := sim.DecodeAD(data)
		return fmt.Sprintf("Mode: %s, MNC Len: %d", ad.UEMode, ad.MNCLength)
	}
	return ""
}

func (r *ProfileReporter) generatePUKCodes(puk *PUKCodes) {
	r.writeLine("{")
	r.indent++
	for _, code := range puk.Codes {
		r.writeIndent()
		r.writeLine("{")
		r.indent++
		r.writeLine(fmt.Sprintf("keyReference %s,", r.formatKeyRef(code.KeyReference, true)))
		r.writeLine(fmt.Sprintf("pukValue %s, -- %s", r.formatHex(code.PUKValue), decodePINValue(code.PUKValue)))
		r.writeLine(fmt.Sprintf("maxNumOfAttemps-retryNumLeft %d", code.MaxNumOfAttempsRetryNumLeft))
		r.indent--
		r.writeIndent()
		r.writeLine("},")
	}
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generatePINCodes(pin *PINCodes) {
	r.writeLine("{")
	r.indent++
	r.writeIndent()
	r.writeLine("pinCodes pinconfig : {")
	r.indent++
	for _, config := range pin.Configs {
		r.writeIndent()
		r.writeLine("{")
		r.indent++
		r.writeLine(fmt.Sprintf("keyReference %s,", r.formatKeyRef(config.KeyReference, false)))
		r.writeLine(fmt.Sprintf("pinValue %s, -- %s", r.formatHex(config.PINValue), decodePINValue(config.PINValue)))
		if config.UnblockingPINReference != 0 {
			r.writeLine(fmt.Sprintf("unblockingPINReference %s,", r.formatKeyRef(config.UnblockingPINReference, true)))
		}
		r.writeLine(fmt.Sprintf("pinAttributes %d,", config.PINAttributes))
		r.writeLine(fmt.Sprintf("maxNumOfAttemps-retryNumLeft %d", config.MaxNumOfAttempsRetryNumLeft))
		r.indent--
		r.writeIndent()
		r.writeLine("},")
	}
	r.indent--
	r.writeIndent()
	r.writeLine("}")
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) formatKeyRef(ref byte, isPUK bool) string {
	if isPUK {
		switch ref {
		case 0x01: return "puk1"
		case 0x81: return "puk2"
		}
	} else {
		switch ref {
		case 0x01: return "pin1"
		case 0x81: return "pin2"
		case 0x0A: return "adm1"
		case 0x0B: return "adm2"
		}
	}
	return fmt.Sprintf("0x%02X", ref)
}

func (r *ProfileReporter) generateAKA(aka *AKAParameter) {
	r.writeLine("{")
	r.indent++
	if aka.AlgoConfig != nil {
		r.writeIndent()
		r.writeLine("algoConfiguration algoParameter : {")
		r.indent++
		r.writeIndent()
		algoName := "Unknown"
		switch aka.AlgoConfig.AlgorithmID {
		case AlgoMilenage: algoName = "Milenage"
		case AlgoTUAK: algoName = "TUAK"
		case AlgoUSIMTestAlgorithm: algoName = "USIM Test"
		}
		r.writeLine(fmt.Sprintf("algorithmID %s,", algoName))
		r.writeLine(fmt.Sprintf("key %s,", r.formatHex(aka.AlgoConfig.Key)))
		r.writeLine(fmt.Sprintf("opc %s,", r.formatHex(aka.AlgoConfig.OPC)))
		r.indent--
		r.writeIndent()
		r.writeLine("},")
	}
	r.writeLine(fmt.Sprintf("sqnOptions '%02X'H", aka.SQNOptions))
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateTelecom(t *TelecomDF) {
	r.writeLine("{")
	r.indent++
	r.generateEF("ef-arr", t.EF_ARR, 0)
	r.generateEF("ef-sume", t.EF_SUME, 0)
	r.generateEF("ef-psismsc", t.EF_PSISMSC, 0)
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateUSIM(u *USIMApplication) {
	r.writeLine("{")
	r.indent++
	r.generateEF("ef-imsi", u.EF_IMSI, 0)
	r.generateEF("ef-arr", u.EF_ARR, 0)
	r.generateEF("ef-keys", u.EF_Keys, 0)
	r.generateEF("ef-ust", u.EF_UST, 0)
	r.generateEF("ef-spn", u.EF_SPN, 0)
	r.generateEF("ef-est", u.EF_EST, 0)
	r.generateEF("ef-acc", u.EF_ACC, 0)
	r.generateEF("ef-ad", u.EF_AD, 0)
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateOptUSIM(u *OptionalUSIM) {
	r.writeLine("{")
	r.indent++
	r.generateEF("ef-li", u.EF_LI, 0)
	r.generateEF("ef-msisdn", u.EF_MSISDN, 0)
	r.generateEF("ef-ext2", u.EF_EXT2, 0)
	r.generateEF("ef-plmnwact", u.EF_PLMNWACT, 0)
	r.generateEF("ef-hplmnwact", u.EF_HPLMNWACT, 0)
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateISIM(i *ISIMApplication) {
	r.writeLine("{")
	r.indent++
	r.generateEF("ef-impi", i.EF_IMPI, 0)
	r.generateEF("ef-impu", i.EF_IMPU, 0)
	r.generateEF("ef-domain", i.EF_DOMAIN, 0)
	r.generateEF("ef-ist", i.EF_IST, 0)
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateOptISIM(i *OptionalISIM) {
	r.writeLine("{")
	r.indent++
	r.generateEF("ef-pcscf", i.EF_PCSCF, 0)
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateCSIM(c *CSIMApplication) {
	r.writeLine("{")
	r.indent++
	r.generateEF("ef-imsi-m", c.EF_IMSI_M, 0)
	r.generateEF("ef-imsi-t", c.EF_IMSI_T, 0)
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateOptCSIM(c *OptionalCSIM) {
	r.writeLine("{")
	r.indent++
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateGFM(gfm *GenericFileManagement) {
	r.writeLine("{")
	r.indent++
	for _, cmd := range gfm.FileManagementCMDs {
		r.writeIndent()
		r.writeLine("{")
		r.indent++
		for _, item := range cmd {
			r.writeIndent()
			switch item.ItemType {
			case 0: r.writeLine(fmt.Sprintf("filePath : %s,", r.formatHex(item.FilePath)))
			case 1: 
				r.writeLine("createFCP : {")
				r.indent++
				if item.CreateFCP != nil {
					r.writeIndent()
					r.writeLine(fmt.Sprintf("fileID %s,", r.formatHex(item.CreateFCP.FileID)))
					r.writeIndent()
					r.writeLine(fmt.Sprintf("fileDescriptor %s, -- %s", r.formatHex(item.CreateFCP.FileDescriptor), sim.DecodeFCP(item.CreateFCP.FileDescriptor)))
				}
				r.indent--
				r.writeIndent()
				r.writeLine("},")
			case 2: r.writeLine(fmt.Sprintf("fillFileContent : %s,", r.formatHex(item.FillFileContent)))
			case 3: r.writeLine(fmt.Sprintf("fillFileOffset : %d,", item.FillFileOffset))
			}
		}
		r.indent--
		r.writeIndent()
		r.writeLine("},")
	}
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateSD(sd *SecurityDomain) {
	r.writeLine("{")
	r.indent++
	if sd.Instance != nil {
		r.writeIndent()
		r.writeLine("instance {")
		r.indent++
		r.writeIndent()
		r.writeLine(fmt.Sprintf("instanceAID %s,", r.formatHex(sd.Instance.InstanceAID)))
		r.indent--
		r.writeIndent()
		r.writeLine("},")
	}
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateRFM(rfm *RFMConfig) {
	r.writeLine("{")
	r.indent++
	r.writeLine(fmt.Sprintf("instanceAID %s,", r.formatHex(rfm.InstanceAID)))
	if len(rfm.TARList) > 0 {
		r.writeIndent()
		r.write("tarList { ")
		for i, tar := range rfm.TARList {
			r.write(r.formatHex(tar))
			if i < len(rfm.TARList)-1 { r.write(", ") }
		}
		r.writeLine(" },")
	}
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateApp(app *Application) {
	r.writeLine("{")
	r.indent++
	if app.LoadBlock != nil {
		r.writeIndent()
		r.writeLine("loadBlock {")
		r.indent++
		r.writeIndent()
		r.writeLine(fmt.Sprintf("loadPackageAID %s,", r.formatHex(app.LoadBlock.LoadPackageAID)))
		r.writeIndent()
		r.writeLine(fmt.Sprintf("loadBlockObject %s, -- %d bytes", r.formatHex(app.LoadBlock.LoadBlockObject), len(app.LoadBlock.LoadBlockObject)))
		r.indent--
		r.writeIndent()
		r.writeLine("},")
	}
	for _, inst := range app.InstanceList {
		r.writeIndent()
		r.writeLine("instance {")
		r.indent++
		r.writeIndent()
		r.writeLine(fmt.Sprintf("instanceAID %s,", r.formatHex(inst.InstanceAID)))
		r.writeIndent()
		r.writeLine(fmt.Sprintf("classAID %s,", r.formatHex(inst.ClassAID)))
		r.indent--
		r.writeIndent()
		r.writeLine("},")
	}
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateGSMAccess(gsm *GSMAccessDF) {
	r.writeLine("{")
	r.indent++
	r.generateEF("ef-kc", gsm.EF_Kc, 0)
	r.generateEF("ef-kcgprs", gsm.EF_KcGPRS, 0)
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateDF5GS(d *DF5GS) {
	r.writeLine("{")
	r.indent++
	r.generateEF("ef-5gs3gpploci", d.EF_5GS3GPPLOCI, 0)
	r.generateEF("ef-5gs3gppnsc", d.EF_5GS3GPPNSC, 0)
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateDFSAIP(d *DFSAIP) {
	r.writeLine("{")
	r.indent++
	r.generateEF("ef-suci-calc-info-usim", d.EF_SUCI_CALC_INFO_USIM, 0)
	r.indent--
	r.writeIndent()
	r.write("}")
}

func (r *ProfileReporter) generateEnd(e *EndElement) {
	r.writeLine("{}")
}

