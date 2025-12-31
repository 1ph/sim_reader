package esim

import (
	"bytes"
	"sim_reader/esim/asn1"
	"sort"
	"strconv"
	"strings"
)

// EncodeProfile encodes Profile to DER
func EncodeProfile(p *Profile) ([]byte, error) {
	var result []byte

	for _, elem := range p.Elements {
		encoded, err := encodeProfileElement(&elem)
		if err != nil {
			return nil, err
		}
		result = append(result, encoded...)
	}

	return result, nil
}

// encodeProfileElement encodes single ProfileElement
func encodeProfileElement(elem *ProfileElement) ([]byte, error) {
	// Use RawBytes if available for lossless round-trip encoding
	if len(elem.RawBytes) > 0 {
		return elem.RawBytes, nil
	}

	// Fallback: encode from structured data
	var data []byte
	var err error

	switch elem.Tag {
	case TagProfileHeader:
		data, err = encodeProfileHeader(elem.Value.(*ProfileHeader))
	case TagMF:
		data, err = encodeMasterFile(elem.Value.(*MasterFile))
	case TagPukCodes:
		data, err = encodePUKCodes(elem.Value.(*PUKCodes))
	case TagPinCodes:
		data, err = encodePINCodes(elem.Value.(*PINCodes))
	case TagTelecom:
		data, err = encodeTelecom(elem.Value.(*TelecomDF))
	case TagUSIM:
		data, err = encodeUSIM(elem.Value.(*USIMApplication))
	case TagOptUSIM:
		data, err = encodeOptUSIM(elem.Value.(*OptionalUSIM))
	case TagISIM:
		data, err = encodeISIM(elem.Value.(*ISIMApplication))
	case TagOptISIM:
		data, err = encodeOptISIM(elem.Value.(*OptionalISIM))
	case TagCSIM:
		data, err = encodeCSIM(elem.Value.(*CSIMApplication))
	case TagOptCSIM:
		data, err = encodeOptCSIM(elem.Value.(*OptionalCSIM))
	case TagGSMAccess:
		data, err = encodeGSMAccess(elem.Value.(*GSMAccessDF))
	case TagAKAParameter:
		data, err = encodeAKAParameter(elem.Value.(*AKAParameter))
	case TagCDMAParameter:
		data, err = encodeCDMAParameter(elem.Value.(*CDMAParameter))
	case TagDF5GS:
		data, err = encodeDF5GS(elem.Value.(*DF5GS))
	case TagDFSAIP:
		data, err = encodeDFSAIP(elem.Value.(*DFSAIP))
	case TagGenericFileManagement:
		data, err = encodeGenericFileManagement(elem.Value.(*GenericFileManagement))
	case TagSecurityDomain:
		data, err = encodeSecurityDomain(elem.Value.(*SecurityDomain))
	case TagRFM:
		data, err = encodeRFM(elem.Value.(*RFMConfig))
	case TagApplication:
		data, err = encodeApplication(elem.Value.(*Application))
	case TagEnd:
		data, err = encodeEnd(elem.Value.(*EndElement))
	default:
		// Raw data
		if raw, ok := elem.Value.([]byte); ok {
			data = raw
		}
	}

	if err != nil {
		return nil, err
	}

	// Wrap in context-specific constructed tag
	return asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, elem.Tag, data), nil
}

// ============================================================================
// ProfileHeader [0]
// ============================================================================

func encodeProfileHeader(h *ProfileHeader) ([]byte, error) {
	var data []byte

	// [0] major-version
	data = append(data, asn1.Marshal(0x80, nil, byte(h.MajorVersion))...)

	// [1] minor-version
	data = append(data, asn1.Marshal(0x81, nil, byte(h.MinorVersion))...)

	// [2] profileType
	if h.ProfileType != "" {
		data = append(data, asn1.Marshal(0x82, nil, []byte(h.ProfileType)...)...)
	}

	// [3] iccid
	if len(h.ICCID) > 0 {
		data = append(data, asn1.Marshal(0x83, nil, h.ICCID...)...)
	}

	// [4] pol
	if len(h.POL) > 0 {
		data = append(data, asn1.Marshal(0x84, nil, h.POL...)...)
	}

	// [5] eUICC-Mandatory-services (ServicesList is a SEQUENCE)
	if h.MandatoryServices != nil {
		msData := encodeMandatoryServices(h.MandatoryServices)
		data = append(data, asn1.Marshal(0xA5, nil, msData...)...)
	}

	// [6] eUICC-Mandatory-GFSTEList (SEQUENCE OF OBJECT IDENTIFIER)
	if len(h.MandatoryGFSTEList) > 0 {
		listData := encodeOIDList(h.MandatoryGFSTEList)
		data = append(data, asn1.Marshal(0xA6, nil, listData...)...)
	}

	return data, nil
}

func encodeMandatoryServices(ms *MandatoryServices) []byte {
	var data []byte

	if ms.USIM {
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormPrimitive, 1, nil)...)
	}
	if ms.ISIM {
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormPrimitive, 2, nil)...)
	}
	if ms.CSIM {
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormPrimitive, 3, nil)...)
	}
	if ms.USIMTestAlgorithm {
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormPrimitive, 17, nil)...)
	}
	if ms.BERTLV {
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormPrimitive, 18, nil)...)
	}
	if ms.GetIdentity {
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormPrimitive, 21, nil)...)
	}
	if ms.ProfileAX25519 {
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormPrimitive, 22, nil)...)
	}
	if ms.ProfileBP256 {
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormPrimitive, 23, nil)...)
	}

	return data
}

// ============================================================================
// MasterFile [1]
// ============================================================================

func encodeFile(fd *FileDescriptor) []byte {
	if fd == nil {
		return nil
	}
	fdData := encodeFileDescriptor(fd)
	// Choice [1] fileDescriptor
	return asn1.Marshal(0xA1, nil, fdData...)
}

func encodeMasterFile(mf *MasterFile) ([]byte, error) {
	var data []byte

	// [0] mf-header
	if mf.MFHeader != nil {
		ehData := encodeElementHeader(mf.MFHeader)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	// [1] templateID
	if len(mf.TemplateID) > 0 {
		oidData := encodeOID(mf.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	// [2] mf
	if mf.MF != nil {
		fileData := encodeFile(mf.MF)
		data = append(data, asn1.Marshal(0xA2, nil, fileData...)...)
	}

	// [3] ef-pl
	if mf.EF_PL != nil {
		efData := encodeElementaryFile(mf.EF_PL)
		data = append(data, asn1.Marshal(0xA3, nil, efData...)...)
	}

	// [4] ef-iccid
	if mf.EF_ICCID != nil {
		efData := encodeElementaryFile(mf.EF_ICCID)
		data = append(data, asn1.Marshal(0xA4, nil, efData...)...)
	}

	// [5] ef-dir
	if mf.EF_DIR != nil {
		efData := encodeElementaryFile(mf.EF_DIR)
		data = append(data, asn1.Marshal(0xA5, nil, efData...)...)
	}

	// [6] ef-arr
	if mf.EF_ARR != nil {
		efData := encodeElementaryFile(mf.EF_ARR)
		data = append(data, asn1.Marshal(0xA6, nil, efData...)...)
	}

	// [7] ef-umpc
	if mf.EF_UMPC != nil {
		efData := encodeElementaryFile(mf.EF_UMPC)
		data = append(data, asn1.Marshal(0xA7, nil, efData...)...)
	}

	// [8] efList (SEQUENCE OF)
	if len(mf.EFList) > 0 {
		var listData []byte
		for _, ef := range mf.EFList {
			if ef != nil {
				efData := encodeElementaryFile(ef)
				listData = append(listData, efData...)
			}
		}
		data = append(data, asn1.Marshal(0xA8, nil, listData...)...)
	}

	return data, nil
}

// ============================================================================
// Common encoders
// ============================================================================

func encodeElementHeader(eh *ElementHeader) []byte {
	var data []byte

	if eh.Mandated {
		data = append(data, asn1.Marshal(0x80, nil)...) // NULL
	}

	// [1] identification
	data = append(data, asn1.Marshal(0x81, nil, encodeInteger(eh.Identification)...)...)

	return data
}

func encodeFileDescriptor(fd *FileDescriptor) []byte {
	var data []byte

	// [2] fileDescriptor
	if fd.FileDescriptor != nil {
		data = append(data, asn1.Marshal(0x82, nil, fd.FileDescriptor...)...)
	}

	// [3] fileID
	if fd.FileID != nil {
		data = append(data, asn1.Marshal(0x83, nil, fd.FileID...)...)
	}

	// [4] dfName
	if fd.DFName != nil {
		data = append(data, asn1.Marshal(0x84, nil, fd.DFName...)...)
	}

	// [10] lcsi
	if fd.LCSI != nil && !bytes.Equal(fd.LCSI, []byte{0x05}) {
		data = append(data, asn1.Marshal(0x8A, nil, fd.LCSI...)...)
	}

	// [11] securityAttributesReferenced
	if fd.SecurityAttributesReferenced != nil {
		data = append(data, asn1.Marshal(0x8B, nil, fd.SecurityAttributesReferenced...)...)
	}

	// [0] efFileSize
	if fd.EFFileSize != nil {
		data = append(data, asn1.Marshal(0x80, nil, fd.EFFileSize...)...)
	}

	// [8] shortEFID
	if fd.ShortEFID != nil {
		data = append(data, asn1.Marshal(0x88, nil, fd.ShortEFID...)...)
	}

	// [5] proprietaryEFInfo (constructed)
	if fd.ProprietaryEFInfo != nil {
		peiData := encodeProprietaryEFInfo(fd.ProprietaryEFInfo)
		data = append(data, asn1.Marshal(0xA5, nil, peiData...)...)
	}

	// [PRIVATE 6] pinStatusTemplateDO (0xC6 = PRIVATE primitive tag 6)
	if fd.PinStatusTemplateDO != nil {
		data = append(data, asn1.Marshal(0xC6, nil, fd.PinStatusTemplateDO...)...)
	}

	// [PRIVATE 7] linkPath (0xC7 = PRIVATE primitive tag 7)
	if fd.LinkPath != nil {
		data = append(data, asn1.Marshal(0xC7, nil, fd.LinkPath...)...)
	}

	return data
}

func encodeProprietaryEFInfo(pei *ProprietaryEFInfo) []byte {
	var data []byte

	// [PRIVATE 0] specialFileInformation (0xC0)
	if pei.SpecialFileInformation != nil && !bytes.Equal(pei.SpecialFileInformation, []byte{0x00}) {
		data = append(data, asn1.Marshal(0xC0, nil, pei.SpecialFileInformation...)...)
	}

	// [PRIVATE 1] fillPattern (0xC1)
	if pei.FillPattern != nil {
		data = append(data, asn1.Marshal(0xC1, nil, pei.FillPattern...)...)
	}

	// [PRIVATE 2] repeatPattern (0xC2)
	if pei.RepeatPattern != nil {
		data = append(data, asn1.Marshal(0xC2, nil, pei.RepeatPattern...)...)
	}

	// [PRIVATE 3] maximumFileSize (0xC3)
	if pei.MaximumFileSize != nil {
		data = append(data, asn1.Marshal(0xC3, nil, pei.MaximumFileSize...)...)
	}

	// [PRIVATE 4] fileDetails (0xC4)
	if pei.FileDetails != nil {
		data = append(data, asn1.Marshal(0xC4, nil, pei.FileDetails...)...)
	}

	return data
}

func encodeElementaryFile(ef *ElementaryFile) []byte {
	var data []byte

	// If Raw elements are available, use them for exact round-trip encoding
	if len(ef.Raw) > 0 {
		for _, elem := range ef.Raw {
			switch elem.Type {
			case FileElementDoNotCreate:
				// [0] doNotCreate NULL
				data = append(data, asn1.Marshal(0x80, nil)...)
			case FileElementDescriptor:
				// [1] fileDescriptor Fcp (constructed)
				if elem.Descriptor != nil {
					fdData := encodeFileDescriptor(elem.Descriptor)
					data = append(data, asn1.Marshal(0xA1, nil, fdData...)...)
				}
			case FileElementOffset:
				// [2] fillFileOffset UInt16
				data = append(data, asn1.Marshal(0x82, nil, encodeInteger(elem.Offset)...)...)
			case FileElementContent:
				// [3] fillFileContent OCTET STRING
				data = append(data, asn1.Marshal(0x83, nil, elem.Content...)...)
			}
		}
		return data
	}

	// Fallback: build from simplified fields
	// [1] fileDescriptor Fcp (constructed)
	if ef.Descriptor != nil {
		fdData := encodeFileDescriptor(ef.Descriptor)
		data = append(data, asn1.Marshal(0xA1, nil, fdData...)...)
	}

	// Encode fill contents with offsets
	for _, fc := range ef.FillContents {
		if fc.Offset > 0 {
			// [2] fillFileOffset
			data = append(data, asn1.Marshal(0x82, nil, encodeInteger(fc.Offset)...)...)
		}
		// [3] fillFileContent
		data = append(data, asn1.Marshal(0x83, nil, fc.Content...)...)
	}

	return data
}

// ============================================================================
// PUK/PIN Codes [2], [3]
// ============================================================================

func encodePUKCodes(puk *PUKCodes) ([]byte, error) {
	var data []byte

	// [0] puk-Header
	if puk.Header != nil {
		ehData := encodeElementHeader(puk.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	// [1] pukCodes
	if len(puk.Codes) > 0 {
		var codesData []byte
		for _, code := range puk.Codes {
			codeData := encodePUKCode(code)
			codesData = append(codesData, asn1.Marshal(0x30, nil, codeData...)...)
		}
		data = append(data, asn1.Marshal(0xA1, nil, codesData...)...)
	}

	return data, nil
}

func encodePUKCode(code PUKCode) []byte {
	var data []byte

	// [0] keyReference
	data = append(data, asn1.Marshal(0x80, nil, code.KeyReference)...)

	// [1] pukValue
	if len(code.PUKValue) > 0 {
		data = append(data, asn1.Marshal(0x81, nil, code.PUKValue...)...)
	}

	// [2] maxNumOfAttemps-retryNumLeft
	data = append(data, asn1.Marshal(0x82, nil, code.MaxNumOfAttempsRetryNumLeft)...)

	return data
}

func encodePINCodes(pin *PINCodes) ([]byte, error) {
	var data []byte

	// [0] pin-Header
	if pin.Header != nil {
		ehData := encodeElementHeader(pin.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	// [1] pinCodes
	if len(pin.Configs) > 0 {
		var configsData []byte
		for _, config := range pin.Configs {
			configData := encodePINConfig(config)
			configsData = append(configsData, asn1.Marshal(0x30, nil, configData...)...)
		}
		// Wrap in CHOICE [0] pinconfig
		choice0Data := asn1.Marshal(0xA0, nil, configsData...)
		data = append(data, asn1.Marshal(0xA1, nil, choice0Data...)...)
	}

	return data, nil
}

func encodePINConfig(config PINConfig) []byte {
	var data []byte

	// [0] keyReference
	data = append(data, asn1.Marshal(0x80, nil, config.KeyReference)...)

	// [1] pinValue
	if len(config.PINValue) > 0 {
		data = append(data, asn1.Marshal(0x81, nil, config.PINValue...)...)
	}

	// [2] unblockingPINReference
	if config.UnblockingPINReference != 0 {
		data = append(data, asn1.Marshal(0x82, nil, config.UnblockingPINReference)...)
	}

	// [3] pinAttributes
	data = append(data, asn1.Marshal(0x83, nil, config.PINAttributes)...)

	// [4] maxNumOfAttemps-retryNumLeft
	data = append(data, asn1.Marshal(0x84, nil, config.MaxNumOfAttempsRetryNumLeft)...)

	return data
}

// ============================================================================
// Telecom [4]
// ============================================================================

func encodeTelecom(t *TelecomDF) ([]byte, error) {
	var data []byte

	if t.Header != nil {
		ehData := encodeElementHeader(t.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(t.TemplateID) > 0 {
		oidData := encodeOID(t.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	if t.DFTelecom != nil {
		fileData := encodeFile(t.DFTelecom)
		data = append(data, asn1.Marshal(0xA2, nil, fileData...)...)
	}

	efList := []struct {
		tag int
		ef  *ElementaryFile
	}{
		{3, t.EF_ARR},
		{4, t.EF_RMA},
		{5, t.EF_SUME},
		{6, t.EF_ICE_DN},
		{7, t.EF_ICE_FF},
		{8, t.EF_PSISMSC},
	}

	for _, item := range efList {
		if item.ef != nil {
			efData := encodeElementaryFile(item.ef)
			data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, item.tag, efData)...)
		}
	}

	if t.DFGraphics != nil {
		fileData := encodeFile(t.DFGraphics)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 9, fileData)...)
	}

	if t.EF_IMG != nil {
		efData := encodeElementaryFile(t.EF_IMG)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 10, efData)...)
	}

	if t.EF_IIDF != nil {
		efData := encodeElementaryFile(t.EF_IIDF)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 11, efData)...)
	}

	if t.EF_ICE_Graphics != nil {
		efData := encodeElementaryFile(t.EF_ICE_Graphics)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 12, efData)...)
	}

	if t.EF_LaunchSCWS != nil {
		efData := encodeElementaryFile(t.EF_LaunchSCWS)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 13, efData)...)
	}

	if t.EF_ICON != nil {
		efData := encodeElementaryFile(t.EF_ICON)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 14, efData)...)
	}

	if t.DFPhonebook != nil {
		fileData := encodeFile(t.DFPhonebook)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 15, fileData)...)
	}

	efList2 := []struct {
		tag int
		ef  *ElementaryFile
	}{
		{16, t.EF_PBR},
		{17, t.EF_EXT1},
		{18, t.EF_AAS},
		{19, t.EF_GAS},
		{20, t.EF_PSC},
		{21, t.EF_CC},
		{22, t.EF_PUID},
		{23, t.EF_IAP},
		{24, t.EF_ADN},
	}

	for _, item := range efList2 {
		if item.ef != nil {
			efData := encodeElementaryFile(item.ef)
			data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, item.tag, efData)...)
		}
	}

	// df-mmss can be tag 25 or 36 - for encoding we use the one from decoder or default
	if t.DFMMSS != nil {
		fileData := encodeFile(t.DFMMSS)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 25, fileData)...)
	}

	if t.EF_MLPL != nil {
		efData := encodeElementaryFile(t.EF_MLPL)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 26, efData)...)
	}

	if t.EF_MSPL != nil {
		efData := encodeElementaryFile(t.EF_MSPL)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 27, efData)...)
	}

	if t.EF_MMSSCONF != nil {
		efData := encodeElementaryFile(t.EF_MMSSCONF)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 28, efData)...)
	}

	if t.EF_MMSSID != nil {
		efData := encodeElementaryFile(t.EF_MMSSID)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 29, efData)...)
	}

	return data, nil
}

// ============================================================================
// USIM [8]
// ============================================================================

func encodeAdditionalEFs(additional map[string]*ElementaryFile) []byte {
	var data []byte
	if len(additional) == 0 {
		return data
	}

	keys := make([]string, 0, len(additional))
	for k := range additional {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		ef := additional[k]
		if ef == nil {
			continue
		}

		tag := 0
		if strings.HasPrefix(k, "tag_") {
			tag, _ = strconv.Atoi(k[4:])
		} else {
			// Try to find tag from name? For now just skip if no tag
			continue
		}

		efData := encodeElementaryFile(ef)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, tag, efData)...)
	}

	return data
}

func encodeUSIM(u *USIMApplication) ([]byte, error) {
	var data []byte

	if u.Header != nil {
		ehData := encodeElementHeader(u.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(u.TemplateID) > 0 {
		oidData := encodeOID(u.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	if u.ADFUSIM != nil {
		fileData := encodeFile(u.ADFUSIM)
		data = append(data, asn1.Marshal(0xA2, nil, fileData...)...)
	}

	// Main EF files
	efList := []struct {
		tag int
		ef  *ElementaryFile
	}{
		{3, u.EF_IMSI},
		{4, u.EF_ARR},
		{5, u.EF_Keys},
		{6, u.EF_KeysPS},
		{7, u.EF_HPPLMN},
		{8, u.EF_UST},
		{9, u.EF_FDN},
		{10, u.EF_SMS},
		{11, u.EF_SMSP},
		{12, u.EF_SMSS},
		{13, u.EF_SPN},
		{14, u.EF_EST},
		{15, u.EF_StartHFN},
		{16, u.EF_Threshold},
		{17, u.EF_PSLOCI},
		{18, u.EF_ACC},
		{19, u.EF_FPLMN},
		{20, u.EF_LOCI},
		{21, u.EF_AD},
		{22, u.EF_ECC},
		{23, u.EF_NETPAR},
		{24, u.EF_EPSLOCI},
		{25, u.EF_EPSNSC},
		{26, u.EF_WLAN},
		{27, u.EF_DEB_PK},
	}

	for _, item := range efList {
		if item.ef != nil {
			efData := encodeElementaryFile(item.ef)
			data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, item.tag, efData)...)
		}
	}

	data = append(data, encodeAdditionalEFs(u.AdditionalEFs)...)

	return data, nil
}

func encodeOptUSIM(u *OptionalUSIM) ([]byte, error) {
	var data []byte

	if u.Header != nil {
		ehData := encodeElementHeader(u.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(u.TemplateID) > 0 {
		oidData := encodeOID(u.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	efFields := []struct {
		tag int
		ef  *ElementaryFile
	}{
		{2, u.EF_LI},
		{3, u.EF_ACMAX},
		{4, u.EF_ACM},
		{5, u.EF_GID1},
		{6, u.EF_GID2},
		{7, u.EF_MSISDN},
		{8, u.EF_PUCT},
		{9, u.EF_CBMI},
		{10, u.EF_CBMID},
		{11, u.EF_SDN},
		{12, u.EF_EXT2},
		{13, u.EF_EXT3},
		{14, u.EF_CBMIR},
		{15, u.EF_PLMNWACT},
		{16, u.EF_OPLMNWACT},
		{17, u.EF_HPLMNWACT},
		{18, u.EF_DCK},
		{19, u.EF_CNL},
		{20, u.EF_SMSR},
		{21, u.EF_BDN},
		{22, u.EF_EXT5},
		{23, u.EF_CCP2},
		{24, u.EF_EXT4},
		{25, u.EF_ACL},
		{26, u.EF_CMI},
		{27, u.EF_ICI},
		{28, u.EF_OCI},
		{29, u.EF_ICT},
		{30, u.EF_OCT},
		{31, u.EF_VGCS},
		{32, u.EF_VGCSS},
		{33, u.EF_VBS},
		{34, u.EF_VBSS},
		{35, u.EF_EMLPP},
		{36, u.EF_AAEM},
		{37, u.EF_HIDDENKEY},
		{38, u.EF_PNN},
		{39, u.EF_OPL},
		{40, u.EF_MBDN},
		{41, u.EF_EXT6},
		{42, u.EF_MBI},
		{43, u.EF_MWIS},
		{44, u.EF_CFIS},
		{45, u.EF_EXT7},
		{46, u.EF_SPDI},
		{47, u.EF_MMSN},
		{48, u.EF_EXT8},
		{49, u.EF_MMSICP},
		{50, u.EF_MMSUP},
		{51, u.EF_MMSUCP},
		{52, u.EF_NIA},
		{53, u.EF_VGCSCA},
		{54, u.EF_VBSCA},
		{55, u.EF_GBABP},
		{56, u.EF_MSK},
		{57, u.EF_MUK},
		{58, u.EF_EHPLMN},
		{59, u.EF_GBANL},
		{60, u.EF_EHPLMNPI},
		{61, u.EF_LRPLMNSI},
		{62, u.EF_NAFKCA},
		{63, u.EF_SPNI},
		{64, u.EF_PNNI},
		{65, u.EF_NCP_IP},
		{66, u.EF_UFC},
		{67, u.EF_NASCONFIG},
		{68, u.EF_UICCIARI},
		{69, u.EF_PWS},
		{70, u.EF_FDNURI},
		{71, u.EF_BDNURI},
		{72, u.EF_SDNURI},
		{73, u.EF_IAL},
		{74, u.EF_IPS},
		{75, u.EF_IPD},
		{76, u.EF_EPDGID},
		{77, u.EF_EPDGSELECTION},
		{78, u.EF_EPDGIDEM},
		{79, u.EF_EPDGSELECTIONEM},
		{80, u.EF_FROMPREFERRED},
		{81, u.EF_IMSCONFIGDATA},
		{82, u.EF_3GPPPSDATAOFF},
		{83, u.EF_3GPPPSDATAOFFSERVICELIST},
		{84, u.EF_XCAPCONFIGDATA},
		{85, u.EF_EARFCNLIST},
		{86, u.EF_MUDMIDCONFIGDATA},
		{87, u.EF_EAKA},
	}

	for _, f := range efFields {
		if f.ef != nil {
			efData := encodeElementaryFile(f.ef)
			data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, f.tag, efData)...)
		}
	}

	return data, nil
}

// ============================================================================
// ISIM [10]
// ============================================================================

func encodeISIM(i *ISIMApplication) ([]byte, error) {
	var data []byte

	if i.Header != nil {
		ehData := encodeElementHeader(i.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(i.TemplateID) > 0 {
		oidData := encodeOID(i.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	if i.ADFISIM != nil {
		fileData := encodeFile(i.ADFISIM)
		data = append(data, asn1.Marshal(0xA2, nil, fileData...)...)
	}

	efList := []struct {
		tag int
		ef  *ElementaryFile
	}{
		{3, i.EF_IMPI},
		{4, i.EF_IMPU},
		{5, i.EF_DOMAIN},
		{6, i.EF_IST},
		{7, i.EF_AD},
		{8, i.EF_ARR},
	}

	for _, item := range efList {
		if item.ef != nil {
			efData := encodeElementaryFile(item.ef)
			data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, item.tag, efData)...)
		}
	}

	data = append(data, encodeAdditionalEFs(i.AdditionalEFs)...)

	return data, nil
}

func encodeOptISIM(i *OptionalISIM) ([]byte, error) {
	var data []byte

	if i.Header != nil {
		ehData := encodeElementHeader(i.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(i.TemplateID) > 0 {
		oidData := encodeOID(i.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	efFields := []struct {
		tag int
		ef  *ElementaryFile
	}{
		{2, i.EF_PCSCF},
		{3, i.EF_GBABP},
		{4, i.EF_GBANL},
		{5, i.EF_NASCONFIG},
		{6, i.EF_UICCIARI},
		{7, i.EF_3GPPPSDATAOFF},
		{8, i.EF_3GPPPSDATAOFFSERVICELIST},
		{9, i.EF_XCAPCONFIGDATA},
		{10, i.EF_EAKA},
	}

	for _, f := range efFields {
		if f.ef != nil {
			efData := encodeElementaryFile(f.ef)
			data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, f.tag, efData)...)
		}
	}

	return data, nil
}

// ============================================================================
// CSIM [12]
// ============================================================================

func encodeCSIM(c *CSIMApplication) ([]byte, error) {
	var data []byte

	if c.Header != nil {
		ehData := encodeElementHeader(c.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(c.TemplateID) > 0 {
		oidData := encodeOID(c.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	if c.ADFCSIM != nil {
		fileData := encodeFile(c.ADFCSIM)
		data = append(data, asn1.Marshal(0xA2, nil, fileData...)...)
	}

	efFields := []struct {
		tag int
		ef  *ElementaryFile
	}{
		{3, c.EF_ARR},
		{4, c.EF_CallCount},
		{5, c.EF_IMSI_M},
		{6, c.EF_IMSI_T},
		{7, c.EF_TMSI},
		{8, c.EF_AH},
		{9, c.EF_AOP},
		{10, c.EF_ALOC},
		{11, c.EF_CDMAHOME},
		{12, c.EF_ZNREGI},
		{13, c.EF_SNREGI},
		{14, c.EF_DISTREGI},
		{15, c.EF_ACCOLC},
		{16, c.EF_TERM},
		{17, c.EF_ACP},
		{18, c.EF_PRL},
		{19, c.EF_RUIMID},
		{20, c.EF_CSIM_ST},
		{21, c.EF_SPC},
		{22, c.EF_OTAPASPC},
		{23, c.EF_NAMLOCK},
		{24, c.EF_OTA},
		{25, c.EF_SP},
		{26, c.EF_ESN_MEID_ME},
		{27, c.EF_LI},
		{28, c.EF_USGIND},
		{29, c.EF_AD},
		{30, c.EF_MAX_PRL},
		{31, c.EF_SPCS},
		{32, c.EF_MECRP},
		{33, c.EF_HOME_TAG},
		{34, c.EF_GROUP_TAG},
		{35, c.EF_SPECIFIC_TAG},
		{36, c.EF_CALL_PROMPT},
	}

	for _, f := range efFields {
		if f.ef != nil {
			efData := encodeElementaryFile(f.ef)
			data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, f.tag, efData)...)
		}
	}

	data = append(data, encodeAdditionalEFs(c.AdditionalEFs)...)

	return data, nil
}

func encodeOptCSIM(c *OptionalCSIM) ([]byte, error) {
	var data []byte

	if c.Header != nil {
		ehData := encodeElementHeader(c.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(c.TemplateID) > 0 {
		oidData := encodeOID(c.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	efFields := []struct {
		tag int
		ef  *ElementaryFile
	}{
		{2, c.EF_SSCI},
		{3, c.EF_FDN},
		{4, c.EF_SMS},
		{5, c.EF_SMSP},
		{6, c.EF_SMSS},
		{7, c.EF_SSFC},
		{8, c.EF_SPN},
		{9, c.EF_MDN},
		{10, c.EF_ECC},
		{11, c.EF_ME3GPDOPC},
		{12, c.EF_3GPDOPM},
		{13, c.EF_SIPCAP},
		{14, c.EF_MIPCAP},
		{15, c.EF_SIPUPP},
		{16, c.EF_MIPUPP},
		{17, c.EF_SIPSP},
		{18, c.EF_MIPSP},
		{19, c.EF_SIPPAPSS},
		{20, c.EF_PUZL},
		{21, c.EF_MAX_PUZL},
		{22, c.EF_HRPDCAP},
		{23, c.EF_HRPDUPP},
		{24, c.EF_CSSPR},
		{25, c.EF_ATC},
		{26, c.EF_EPRL},
		{30, c.EF_BCSMSP},
		{33, c.EF_MMSN},
		{34, c.EF_EXT8},
		{35, c.EF_MMSICP},
		{36, c.EF_MMSUP},
		{37, c.EF_MMSUCP},
		{39, c.EF_3GCIK},
		{41, c.EF_GID1},
		{42, c.EF_GID2},
		{44, c.EF_SF_EUIMID},
		{45, c.EF_EST},
		{46, c.EF_HIDDEN_KEY},
		{49, c.EF_SDN},
		{50, c.EF_EXT2},
		{51, c.EF_EXT3},
		{52, c.EF_ICI},
		{53, c.EF_OCI},
		{54, c.EF_EXT5},
		{55, c.EF_CCP2},
		{57, c.EF_MODEL},
		{58, c.EF_MEIDME},
	}

	for _, f := range efFields {
		if f.ef != nil {
			efData := encodeElementaryFile(f.ef)
			data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, f.tag, efData)...)
		}
	}

	return data, nil
}

// ============================================================================
// GSM Access [20]
// ============================================================================

func encodeGSMAccess(g *GSMAccessDF) ([]byte, error) {
	var data []byte

	if g.Header != nil {
		ehData := encodeElementHeader(g.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(g.TemplateID) > 0 {
		oidData := encodeOID(g.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	if g.DFGSMAccess != nil {
		fileData := encodeFile(g.DFGSMAccess)
		data = append(data, asn1.Marshal(0xA2, nil, fileData...)...)
	}

	efList := []struct {
		tag byte
		ef  *ElementaryFile
	}{
		{0xA3, g.EF_Kc},
		{0xA4, g.EF_KcGPRS},
		{0xA5, g.EF_CPBCCH},
		{0xA6, g.EF_INVSCAN},
	}

	for _, item := range efList {
		if item.ef != nil {
			efData := encodeElementaryFile(item.ef)
			data = append(data, asn1.Marshal(item.tag, nil, efData...)...)
		}
	}

	return data, nil
}

// ============================================================================
// DF-5GS [24]
// ============================================================================

func encodeDF5GS(d *DF5GS) ([]byte, error) {
	var data []byte

	if d.Header != nil {
		ehData := encodeElementHeader(d.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(d.TemplateID) > 0 {
		oidData := encodeOID(d.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	if d.DFDF5GS != nil {
		fileData := encodeFile(d.DFDF5GS)
		data = append(data, asn1.Marshal(0xA2, nil, fileData...)...)
	}

	efFields := []struct {
		tag int
		ef  *ElementaryFile
	}{
		{3, d.EF_5GS3GPPLOCI},
		{4, d.EF_5GSN3GPPLOCI},
		{5, d.EF_5GS3GPPNSC},
		{6, d.EF_5GSN3GPPNSC},
		{7, d.EF_5GAUTHKEYS},
		{8, d.EF_UAC_AIC},
		{9, d.EF_SUCI_CALC_INFO},
		{10, d.EF_OPL5G},
		{12, d.EF_ROUTING_INDICATOR},
	}

	for _, f := range efFields {
		if f.ef != nil {
			efData := encodeElementaryFile(f.ef)
			data = append(data, asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, f.tag, efData)...)
		}
	}

	return data, nil
}

// ============================================================================
// DF-SAIP [25]
// ============================================================================

func encodeDFSAIP(d *DFSAIP) ([]byte, error) {
	var data []byte

	if d.Header != nil {
		ehData := encodeElementHeader(d.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(d.TemplateID) > 0 {
		oidData := encodeOID(d.TemplateID)
		data = append(data, asn1.Marshal(0x81, nil, oidData...)...)
	}

	if d.DFDFSAIP != nil {
		fileData := encodeFile(d.DFDFSAIP)
		data = append(data, asn1.Marshal(0xA2, nil, fileData...)...)
	}

	if d.EF_SUCI_CALC_INFO_USIM != nil {
		efData := encodeElementaryFile(d.EF_SUCI_CALC_INFO_USIM)
		data = append(data, asn1.Marshal(0xA3, nil, efData...)...)
	}

	return data, nil
}

// ============================================================================
// AKA Parameter [22]
// ============================================================================

func encodeAKAParameter(aka *AKAParameter) ([]byte, error) {
	var data []byte

	// [0] aka-header
	if aka.Header != nil {
		ehData := encodeElementHeader(aka.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	// [1] algoConfiguration
	if aka.AlgoConfig != nil {
		acData := encodeAlgoConfiguration(aka.AlgoConfig)
		data = append(data, asn1.Marshal(0xA1, nil, acData...)...)
	}

	// [2] sqnOptions
	data = append(data, asn1.Marshal(0x82, nil, aka.SQNOptions)...)

	// [3] sqnDelta
	if len(aka.SQNDelta) > 0 {
		data = append(data, asn1.Marshal(0x83, nil, aka.SQNDelta...)...)
	}

	// [4] sqnAgeLimit
	if len(aka.SQNAgeLimit) > 0 {
		data = append(data, asn1.Marshal(0x84, nil, aka.SQNAgeLimit...)...)
	}

	// [5] sqnInit
	if len(aka.SQNInit) > 0 {
		var sqnData []byte
		for _, sqn := range aka.SQNInit {
			sqnData = append(sqnData, asn1.Marshal(0x04, nil, sqn...)...) // OCTET STRING
		}
		data = append(data, asn1.Marshal(0xA5, nil, sqnData...)...)
	}

	return data, nil
}

func encodeAlgoConfiguration(ac *AlgoConfiguration) []byte {
	var data []byte

	// [0] algorithmID
	data = append(data, asn1.Marshal(0x80, nil, encodeInteger(int(ac.AlgorithmID))...)...)

	// [1] algorithmOptions
	data = append(data, asn1.Marshal(0x81, nil, ac.AlgorithmOptions)...)

	// [2] key
	if len(ac.Key) > 0 {
		data = append(data, asn1.Marshal(0x82, nil, ac.Key...)...)
	}

	// [3] opc
	if len(ac.OPC) > 0 {
		data = append(data, asn1.Marshal(0x83, nil, ac.OPC...)...)
	}

	// [4] rotationConstants
	if len(ac.RotationConstants) > 0 {
		data = append(data, asn1.Marshal(0x84, nil, ac.RotationConstants...)...)
	}

	// [5] xoringConstants
	if len(ac.XoringConstants) > 0 {
		data = append(data, asn1.Marshal(0x85, nil, ac.XoringConstants...)...)
	}

	// [6] numberOfKeccak
	if ac.NumberOfKeccak > 0 {
		data = append(data, asn1.Marshal(0x86, nil, encodeInteger(ac.NumberOfKeccak)...)...)
	}

	// Wrap in CHOICE based on algorithm type
	// For simplicity, we assume Milenage/USIMTestAlgorithm uses [0]
	// and Tuak uses [1]
	choiceTag := byte(0xA0) // [0] milenage
	if ac.AlgorithmID == AlgoTUAK {
		choiceTag = 0xA1 // [1] tuak
	}

	return asn1.Marshal(choiceTag, nil, data...)
}

// ============================================================================
// CDMA Parameter [23]
// ============================================================================

func encodeCDMAParameter(c *CDMAParameter) ([]byte, error) {
	var data []byte

	if c.Header != nil {
		ehData := encodeElementHeader(c.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(c.AuthenticationKey) > 0 {
		data = append(data, asn1.Marshal(0x81, nil, c.AuthenticationKey...)...)
	}

	if len(c.SSD) > 0 {
		data = append(data, asn1.Marshal(0x82, nil, c.SSD...)...)
	}

	if len(c.HRPDAccessAuthenticationData) > 0 {
		data = append(data, asn1.Marshal(0x83, nil, c.HRPDAccessAuthenticationData...)...)
	}

	if len(c.SimpleIPAuthenticationData) > 0 {
		data = append(data, asn1.Marshal(0x84, nil, c.SimpleIPAuthenticationData...)...)
	}

	if len(c.MobileIPAuthenticationData) > 0 {
		data = append(data, asn1.Marshal(0x85, nil, c.MobileIPAuthenticationData...)...)
	}

	return data, nil
}

// ============================================================================
// Generic File Management [26]
// ============================================================================

func encodeGenericFileManagement(gfm *GenericFileManagement) ([]byte, error) {
	var data []byte

	if gfm.Header != nil {
		ehData := encodeElementHeader(gfm.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(gfm.FileManagementCMDs) > 0 {
		var cmdsData []byte
		for _, cmd := range gfm.FileManagementCMDs {
			cmdData := encodeFileManagementCMD(cmd)
			// Each FileManagementCMD is a SEQUENCE
			cmdsData = append(cmdsData, asn1.Marshal(0x30, nil, cmdData...)...)
		}
		data = append(data, asn1.Marshal(0xA1, nil, cmdsData...)...)
	}

	return data, nil
}

func encodeFileManagementCMD(cmd FileManagementCMD) []byte {
	var data []byte

	for _, item := range cmd {
		switch item.ItemType {
		case 0: // filePath
			data = append(data, asn1.Marshal(0x80, nil, item.FilePath...)...)
		case 1: // createFCP - uses FCP template tag 0x62
			if item.CreateFCP != nil {
				fdData := encodeFileDescriptor(item.CreateFCP)
				data = append(data, asn1.Marshal(0x62, nil, fdData...)...)
			}
		case 2: // fillFileContent
			data = append(data, asn1.Marshal(0x81, nil, item.FillFileContent...)...)
		case 3: // fillFileOffset
			data = append(data, asn1.Marshal(0x82, nil, encodeInteger(item.FillFileOffset)...)...)
		}
	}

	return data
}

// ============================================================================
// Security Domain [55]
// ============================================================================

func encodeSecurityDomain(sd *SecurityDomain) ([]byte, error) {
	var data []byte

	if sd.Header != nil {
		ehData := encodeElementHeader(sd.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if sd.Instance != nil {
		instData := encodeSDInstance(sd.Instance)
		data = append(data, asn1.Marshal(0xA1, nil, instData...)...)
	}

	if len(sd.KeyList) > 0 {
		var keysData []byte
		for _, key := range sd.KeyList {
			keyData := encodeSDKey(key)
			keysData = append(keysData, asn1.Marshal(0x30, nil, keyData...)...)
		}
		data = append(data, asn1.Marshal(0xA2, nil, keysData...)...)
	}

	if len(sd.SDPersoData) > 0 {
		var persoData []byte
		for _, data := range sd.SDPersoData {
			persoData = append(persoData, asn1.Marshal(0x04, nil, data...)...)
		}
		data = append(data, asn1.Marshal(0xA3, nil, persoData...)...)
	}

	return data, nil
}

func encodeSDInstance(inst *SDInstance) []byte {
	var data []byte

	// [APPLICATION 15] fields in order (0x4F)
	if len(inst.ApplicationLoadPackageAID) > 0 {
		data = append(data, asn1.Marshal(0x4F, nil, inst.ApplicationLoadPackageAID...)...)
	}
	if len(inst.ClassAID) > 0 {
		data = append(data, asn1.Marshal(0x4F, nil, inst.ClassAID...)...)
	}
	if len(inst.InstanceAID) > 0 {
		data = append(data, asn1.Marshal(0x4F, nil, inst.InstanceAID...)...)
	}

	// [2] applicationPrivileges (0x82)
	if len(inst.ApplicationPrivileges) > 0 {
		data = append(data, asn1.Marshal(0x82, nil, inst.ApplicationPrivileges...)...)
	}

	// [3] lifeCycleState (0x83)
	data = append(data, asn1.Marshal(0x83, nil, inst.LifeCycleState)...)

	// [PRIVATE 9] applicationSpecificParametersC9 (0xC9)
	if len(inst.ApplicationSpecificParamsC9) > 0 {
		data = append(data, asn1.Marshal(0xC9, nil, inst.ApplicationSpecificParamsC9...)...)
	}

	// [PRIVATE 10] CONSTRUCTED applicationParameters (0xEA)
	if inst.ApplicationParameters != nil {
		apData := encodeApplicationParameters(inst.ApplicationParameters)
		data = append(data, asn1.Marshal(0xEA, nil, apData...)...)
	}

	return data
}

func encodeApplicationParameters(ap *ApplicationParameters) []byte {
	var data []byte

	if len(ap.UIICToolkitApplicationSpecificParametersField) > 0 {
		data = append(data, asn1.Marshal(0x80, nil, ap.UIICToolkitApplicationSpecificParametersField...)...)
	}

	return data
}

func encodeSDKey(key SDKey) []byte {
	var data []byte

	// [21] keyUsageQualifier (0x95 = context-specific primitive 21)
	data = append(data, asn1.Marshal(0x95, nil, key.KeyUsageQualifier)...)

	// [22] keyAccess (0x96 = context-specific primitive 22)
	data = append(data, asn1.Marshal(0x96, nil, key.KeyAccess)...)

	// [2] keyIdentifier (0x82)
	data = append(data, asn1.Marshal(0x82, nil, key.KeyIdentifier)...)

	// [3] keyVersionNumber (0x83)
	data = append(data, asn1.Marshal(0x83, nil, key.KeyVersionNumber)...)

	// keyCompontents - SEQUENCE
	if len(key.KeyCompontents) > 0 {
		var compData []byte
		for _, comp := range key.KeyCompontents {
			cd := encodeKeyComponent(comp)
			compData = append(compData, asn1.Marshal(0x30, nil, cd...)...)
		}
		data = append(data, asn1.Marshal(0x30, nil, compData...)...)
	}

	return data
}

func encodeKeyComponent(kc KeyComponent) []byte {
	var data []byte

	// [0] keyType
	data = append(data, asn1.Marshal(0x80, nil, kc.KeyType)...)

	// [6] keyData
	if len(kc.KeyData) > 0 {
		data = append(data, asn1.Marshal(0x86, nil, kc.KeyData...)...)
	}

	// [7] macLength
	if kc.MACLength > 0 {
		data = append(data, asn1.Marshal(0x87, nil, encodeInteger(kc.MACLength)...)...)
	}

	return data
}

// ============================================================================
// RFM [56]
// ============================================================================

func encodeRFM(rfm *RFMConfig) ([]byte, error) {
	var data []byte

	if rfm.Header != nil {
		ehData := encodeElementHeader(rfm.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	if len(rfm.InstanceAID) > 0 {
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassApplication, asn1.FormPrimitive, 15, rfm.InstanceAID)...)
	}

	if len(rfm.TARList) > 0 {
		var tarData []byte
		for _, tar := range rfm.TARList {
			tarData = append(tarData, asn1.Marshal(0x04, nil, tar...)...)
		}
		data = append(data, asn1.Marshal(0xA0, nil, tarData...)...)
	}

	if rfm.MinimumSecurityLevel != 0 {
		data = append(data, asn1.Marshal(0x81, nil, rfm.MinimumSecurityLevel)...)
	}

	data = append(data, asn1.Marshal(0x04, nil, rfm.UICCAccessDomain)...)
	data = append(data, asn1.Marshal(0x04, nil, rfm.UICCAdminAccessDomain)...)

	if rfm.ADFRFMAccess != nil {
		accData := encodeADFRFMAccess(rfm.ADFRFMAccess)
		data = append(data, asn1.MarshalWithFullTag(asn1.ClassUniversal, asn1.FormConstructed, 16, accData)...)
	}

	return data, nil
}

func encodeADFRFMAccess(acc *ADFRFMAccess) []byte {
	var data []byte

	if len(acc.ADFAID) > 0 {
		data = append(data, asn1.Marshal(0x80, nil, acc.ADFAID...)...)
	}

	data = append(data, asn1.Marshal(0x81, nil, acc.ADFAccessDomain)...)
	data = append(data, asn1.Marshal(0x82, nil, acc.ADFAdminAccessDomain)...)

	return data
}

// ============================================================================
// Application [8] - PE-Application for Java Card applets
// ============================================================================

func encodeApplication(app *Application) ([]byte, error) {
	// If RawBytes available, use for lossless round-trip
	if len(app.RawBytes) > 0 {
		return app.RawBytes, nil
	}

	var data []byte

	// [0] app-Header
	if app.Header != nil {
		ehData := encodeElementHeader(app.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	// [1] loadBlock
	if app.LoadBlock != nil {
		lbData := encodeApplicationLoadPackage(app.LoadBlock)
		data = append(data, asn1.Marshal(0xA1, nil, lbData...)...)
	}

	// [2] instanceList
	if len(app.InstanceList) > 0 {
		var instListData []byte
		for _, inst := range app.InstanceList {
			instData := encodeApplicationInstance(inst)
			instListData = append(instListData, asn1.Marshal(0x30, nil, instData...)...)
		}
		data = append(data, asn1.Marshal(0xA2, nil, instListData...)...)
	}

	return data, nil
}

func encodeApplicationLoadPackage(pkg *ApplicationLoadPackage) []byte {
	var data []byte

	// [APPLICATION 15] loadPackageAID (0x4F = APPLICATION 15)
	if len(pkg.LoadPackageAID) > 0 {
		data = append(data, asn1.Marshal(0x4F, nil, pkg.LoadPackageAID...)...)
	}

	// [APPLICATION 15] securityDomainAID (optional, same tag)
	if len(pkg.SecurityDomainAID) > 0 {
		data = append(data, asn1.Marshal(0x4F, nil, pkg.SecurityDomainAID...)...)
	}

	// [PRIVATE 6] nonVolatileCodeLimitC6 (0xC6)
	if len(pkg.NonVolatileCodeLimitC6) > 0 {
		data = append(data, asn1.Marshal(0xC6, nil, pkg.NonVolatileCodeLimitC6...)...)
	}

	// [PRIVATE 7] volatileDataLimitC7 (0xC7)
	if len(pkg.VolatileDataLimitC7) > 0 {
		data = append(data, asn1.Marshal(0xC7, nil, pkg.VolatileDataLimitC7...)...)
	}

	// [PRIVATE 8] nonVolatileDataLimitC8 (0xC8)
	if len(pkg.NonVolatileDataLimitC8) > 0 {
		data = append(data, asn1.Marshal(0xC8, nil, pkg.NonVolatileDataLimitC8...)...)
	}

	// [PRIVATE 1] hashValue (0xC1)
	if len(pkg.HashValue) > 0 {
		data = append(data, asn1.Marshal(0xC1, nil, pkg.HashValue...)...)
	}

	// [PRIVATE 4] loadBlockObject (0xC4) - CAP file content
	if len(pkg.LoadBlockObject) > 0 {
		data = append(data, asn1.Marshal(0xC4, nil, pkg.LoadBlockObject...)...)
	}

	return data
}

func encodeApplicationInstance(inst *ApplicationInstance) []byte {
	var data []byte

	// [APPLICATION 15] fields in order (0x4F)
	if len(inst.ApplicationLoadPackageAID) > 0 {
		data = append(data, asn1.Marshal(0x4F, nil, inst.ApplicationLoadPackageAID...)...)
	}
	if len(inst.ClassAID) > 0 {
		data = append(data, asn1.Marshal(0x4F, nil, inst.ClassAID...)...)
	}
	if len(inst.InstanceAID) > 0 {
		data = append(data, asn1.Marshal(0x4F, nil, inst.InstanceAID...)...)
	}
	if len(inst.ExtraditeSecurityDomainAID) > 0 {
		data = append(data, asn1.Marshal(0x4F, nil, inst.ExtraditeSecurityDomainAID...)...)
	}

	// [2] applicationPrivileges (0x82)
	if len(inst.ApplicationPrivileges) > 0 {
		data = append(data, asn1.Marshal(0x82, nil, inst.ApplicationPrivileges...)...)
	}

	// [3] lifeCycleState (0x83)
	data = append(data, asn1.Marshal(0x83, nil, inst.LifeCycleState)...)

	// [PRIVATE 9] applicationSpecificParametersC9 (0xC9)
	if len(inst.ApplicationSpecificParamsC9) > 0 {
		data = append(data, asn1.Marshal(0xC9, nil, inst.ApplicationSpecificParamsC9...)...)
	}

	// [PRIVATE 15] systemSpecificParameters (0xCF)
	if len(inst.SystemSpecificParams) > 0 {
		data = append(data, asn1.Marshal(0xCF, nil, inst.SystemSpecificParams...)...)
	}

	// [PRIVATE 10] applicationParameters (0xEA)
	if inst.ApplicationParameters != nil {
		apData := encodeApplicationParameters(inst.ApplicationParameters)
		data = append(data, asn1.Marshal(0xEA, nil, apData...)...)
	}

	// processData - SEQUENCE OF OCTET STRING
	if len(inst.ProcessData) > 0 {
		var pdData []byte
		for _, apdu := range inst.ProcessData {
			pdData = append(pdData, asn1.Marshal(0x04, nil, apdu...)...) // OCTET STRING
		}
		data = append(data, asn1.Marshal(0x30, nil, pdData...)...) // SEQUENCE
	}

	// [16] controlReferenceTemplate (0xB0 = context-specific constructed 16)
	if len(inst.ControlReferenceTemplate) > 0 {
		data = append(data, asn1.Marshal(0xB0, nil, inst.ControlReferenceTemplate...)...)
	}

	return data
}

// ============================================================================
// End [10]
// ============================================================================

func encodeEnd(end *EndElement) ([]byte, error) {
	var data []byte

	if end.Header != nil {
		ehData := encodeElementHeader(end.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	return data, nil
}
