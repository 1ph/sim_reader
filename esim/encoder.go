package esim

import (
	"sim_reader/esim/asn1"
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

	// [4] eUICC-Mandatory-services
	if h.MandatoryServices != nil {
		msData := encodeMandatoryServices(h.MandatoryServices)
		data = append(data, asn1.Marshal(0xA4, nil, msData...)...)
	}

	// [5] eUICC-Mandatory-GFSTEList
	if len(h.MandatoryGFSTEList) > 0 {
		listData := encodeOIDList(h.MandatoryGFSTEList)
		data = append(data, asn1.Marshal(0xA5, nil, listData...)...)
	}

	return data, nil
}

func encodeMandatoryServices(ms *MandatoryServices) []byte {
	var data []byte

	if ms.USIM {
		data = append(data, asn1.Marshal(0x80, nil)...) // NULL
	}
	if ms.ISIM {
		data = append(data, asn1.Marshal(0x81, nil)...)
	}
	if ms.CSIM {
		data = append(data, asn1.Marshal(0x82, nil)...)
	}
	if ms.USIMTestAlgorithm {
		data = append(data, asn1.Marshal(0x83, nil)...)
	}
	if ms.BERTLV {
		data = append(data, asn1.Marshal(0x85, nil)...)
	}
	if ms.GetIdentity {
		data = append(data, asn1.Marshal(0x86, nil)...)
	}
	if ms.ProfileAX25519 {
		data = append(data, asn1.Marshal(0x87, nil)...)
	}
	if ms.ProfileBP256 {
		data = append(data, asn1.Marshal(0x88, nil)...)
	}

	return data
}

// ============================================================================
// MasterFile [1]
// ============================================================================

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
		fdData := encodeFileDescriptor(mf.MF)
		data = append(data, asn1.Marshal(0xA2, nil, fdData...)...)
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

	// Tags must be encoded in ascending order per DER rules
	// Fcp field order by tag: [0], [2], [3], [4], [5], [8], [10], [11], [PRIVATE 6], [PRIVATE 7]

	// [0] efFileSize
	if fd.EFFileSize > 0 {
		data = append(data, asn1.Marshal(0x80, nil, encodeInteger(fd.EFFileSize)...)...)
	}

	// [2] fileDescriptor
	if len(fd.FileDescriptor) > 0 {
		data = append(data, asn1.Marshal(0x82, nil, fd.FileDescriptor...)...)
	}

	// [3] fileID
	if fd.FileID != 0 {
		data = append(data, asn1.Marshal(0x83, nil, encodeUint16BE(fd.FileID)...)...)
	}

	// [4] dfName
	if len(fd.DFName) > 0 {
		data = append(data, asn1.Marshal(0x84, nil, fd.DFName...)...)
	}

	// [5] proprietaryEFInfo (constructed)
	if fd.ProprietaryEFInfo != nil {
		peiData := encodeProprietaryEFInfo(fd.ProprietaryEFInfo)
		data = append(data, asn1.Marshal(0xA5, nil, peiData...)...)
	}

	// [8] shortEFID
	if fd.ShortEFID != 0 {
		data = append(data, asn1.Marshal(0x88, nil, fd.ShortEFID)...)
	}

	// [10] lcsi
	if fd.LCSI != 0 {
		data = append(data, asn1.Marshal(0x8A, nil, fd.LCSI)...)
	}

	// [11] securityAttributesReferenced
	if len(fd.SecurityAttributesReferenced) > 0 {
		data = append(data, asn1.Marshal(0x8B, nil, fd.SecurityAttributesReferenced...)...)
	}

	// [PRIVATE 6] pinStatusTemplateDO (0xC6 = PRIVATE primitive tag 6)
	if len(fd.PinStatusTemplateDO) > 0 {
		data = append(data, asn1.Marshal(0xC6, nil, fd.PinStatusTemplateDO...)...)
	}

	// [PRIVATE 7] linkPath (0xC7 = PRIVATE primitive tag 7)
	if len(fd.LinkPath) > 0 {
		data = append(data, asn1.Marshal(0xC7, nil, fd.LinkPath...)...)
	}

	return data
}

func encodeProprietaryEFInfo(pei *ProprietaryEFInfo) []byte {
	var data []byte

	// [0] specialFileInformation
	data = append(data, asn1.Marshal(0x80, nil, pei.SpecialFileInformation)...)

	// [1] fillPattern
	if len(pei.FillPattern) > 0 {
		data = append(data, asn1.Marshal(0x81, nil, pei.FillPattern...)...)
	}

	// [2] repeatPattern
	if len(pei.RepeatPattern) > 0 {
		data = append(data, asn1.Marshal(0x82, nil, pei.RepeatPattern...)...)
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
		data = append(data, asn1.Marshal(0xA1, nil, configsData...)...)
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
		fdData := encodeFileDescriptor(t.DFTelecom)
		data = append(data, asn1.Marshal(0xA2, nil, fdData...)...)
	}

	// Remaining EF files in tag order
	efList := []struct {
		tag byte
		ef  *ElementaryFile
	}{
		{0xA3, t.EF_ARR},
		{0xA4, t.EF_SUME},
		{0xA5, t.EF_PSISMSC},
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
// USIM [8]
// ============================================================================

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
		fdData := encodeFileDescriptor(u.ADFUSIM)
		data = append(data, asn1.Marshal(0xA2, nil, fdData...)...)
	}

	// Main EF files
	efList := []struct {
		tag byte
		ef  *ElementaryFile
	}{
		{0xA3, u.EF_IMSI},
		{0xA4, u.EF_ARR},
		{0xA5, u.EF_Keys},
		{0xA6, u.EF_KeysPS},
		{0xA7, u.EF_HPPLMN},
		{0xA8, u.EF_UST},
		{0xA9, u.EF_FDN},
		{0xAA, u.EF_SMS},
	}

	for _, item := range efList {
		if item.ef != nil {
			efData := encodeElementaryFile(item.ef)
			data = append(data, asn1.Marshal(item.tag, nil, efData...)...)
		}
	}

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

	// Main optional EF
	if u.EF_LI != nil {
		efData := encodeElementaryFile(u.EF_LI)
		data = append(data, asn1.Marshal(0xA2, nil, efData...)...)
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
		fdData := encodeFileDescriptor(i.ADFISIM)
		data = append(data, asn1.Marshal(0xA2, nil, fdData...)...)
	}

	efList := []struct {
		tag byte
		ef  *ElementaryFile
	}{
		{0xA3, i.EF_IMPI},
		{0xA4, i.EF_IMPU},
		{0xA5, i.EF_DOMAIN},
		{0xA6, i.EF_IST},
		{0xA7, i.EF_AD},
		{0xA8, i.EF_ARR},
	}

	for _, item := range efList {
		if item.ef != nil {
			efData := encodeElementaryFile(item.ef)
			data = append(data, asn1.Marshal(item.tag, nil, efData...)...)
		}
	}

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
		fdData := encodeFileDescriptor(c.ADFCSIM)
		data = append(data, asn1.Marshal(0xA2, nil, fdData...)...)
	}

	if c.EF_ARR != nil {
		efData := encodeElementaryFile(c.EF_ARR)
		data = append(data, asn1.Marshal(0xA3, nil, efData...)...)
	}

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
		fdData := encodeFileDescriptor(g.DFGSMAccess)
		data = append(data, asn1.Marshal(0xA2, nil, fdData...)...)
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
		fdData := encodeFileDescriptor(d.DFDF5GS)
		data = append(data, asn1.Marshal(0xA2, nil, fdData...)...)
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
		fdData := encodeFileDescriptor(d.DFDFSAIP)
		data = append(data, asn1.Marshal(0xA2, nil, fdData...)...)
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

	return data
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
			cmdsData = append(cmdsData, cmdData...)
		}
		data = append(data, asn1.Marshal(0xA1, nil, cmdsData...)...)
	}

	return data, nil
}

func encodeFileManagementCMD(cmd FileManagementCMD) []byte {
	var data []byte

	if len(cmd.FilePath) > 0 {
		data = append(data, asn1.Marshal(0x80, nil, cmd.FilePath...)...)
	}

	if cmd.CreateFCP != nil {
		fdData := encodeFileDescriptor(cmd.CreateFCP)
		data = append(data, asn1.Marshal(0xA1, nil, fdData...)...)
	}

	for _, fc := range cmd.FillFileContent {
		if fc.Offset > 0 {
			data = append(data, asn1.Marshal(0x83, nil, encodeInteger(fc.Offset)...)...)
		}
		data = append(data, asn1.Marshal(0x82, nil, fc.Content...)...)
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
		data = append(data, asn1.Marshal(0xA3, nil, sd.SDPersoData...)...)
	}

	return data, nil
}

func encodeSDInstance(inst *SDInstance) []byte {
	var data []byte

	if len(inst.ApplicationLoadPackageAID) > 0 {
		data = append(data, asn1.Marshal(0x80, nil, inst.ApplicationLoadPackageAID...)...)
	}

	if len(inst.ClassAID) > 0 {
		data = append(data, asn1.Marshal(0x81, nil, inst.ClassAID...)...)
	}

	if len(inst.InstanceAID) > 0 {
		data = append(data, asn1.Marshal(0x82, nil, inst.InstanceAID...)...)
	}

	if len(inst.ApplicationPrivileges) > 0 {
		data = append(data, asn1.Marshal(0x83, nil, inst.ApplicationPrivileges...)...)
	}

	data = append(data, asn1.Marshal(0x84, nil, inst.LifeCycleState)...)

	if len(inst.ApplicationSpecificParamsC9) > 0 {
		data = append(data, asn1.Marshal(0x85, nil, inst.ApplicationSpecificParamsC9...)...)
	}

	if inst.ApplicationParameters != nil {
		apData := encodeApplicationParameters(inst.ApplicationParameters)
		data = append(data, asn1.Marshal(0xA6, nil, apData...)...)
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

	data = append(data, asn1.Marshal(0x80, nil, key.KeyUsageQualifier)...)
	data = append(data, asn1.Marshal(0x81, nil, key.KeyAccess)...)
	data = append(data, asn1.Marshal(0x82, nil, key.KeyIdentifier)...)
	data = append(data, asn1.Marshal(0x83, nil, key.KeyVersionNumber)...)

	if len(key.KeyComponents) > 0 {
		var compData []byte
		for _, comp := range key.KeyComponents {
			cd := encodeKeyComponent(comp)
			compData = append(compData, asn1.Marshal(0x30, nil, cd...)...)
		}
		data = append(data, asn1.Marshal(0xA4, nil, compData...)...)
	}

	return data
}

func encodeKeyComponent(kc KeyComponent) []byte {
	var data []byte

	data = append(data, asn1.Marshal(0x80, nil, kc.KeyType)...)

	if len(kc.KeyData) > 0 {
		data = append(data, asn1.Marshal(0x81, nil, kc.KeyData...)...)
	}

	if kc.MACLength > 0 {
		data = append(data, asn1.Marshal(0x82, nil, encodeInteger(kc.MACLength)...)...)
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
		data = append(data, asn1.Marshal(0x81, nil, rfm.InstanceAID...)...)
	}

	if len(rfm.TARList) > 0 {
		var tarData []byte
		for _, tar := range rfm.TARList {
			tarData = append(tarData, asn1.Marshal(0x04, nil, tar...)...)
		}
		data = append(data, asn1.Marshal(0xA2, nil, tarData...)...)
	}

	data = append(data, asn1.Marshal(0x83, nil, rfm.MinimumSecurityLevel)...)
	data = append(data, asn1.Marshal(0x84, nil, rfm.UICCAccessDomain)...)
	data = append(data, asn1.Marshal(0x85, nil, rfm.UICCAdminAccessDomain)...)

	if rfm.ADFRFMAccess != nil {
		accData := encodeADFRFMAccess(rfm.ADFRFMAccess)
		data = append(data, asn1.Marshal(0xA6, nil, accData...)...)
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
// End [63]
// ============================================================================

func encodeEnd(end *EndElement) ([]byte, error) {
	var data []byte

	if end.Header != nil {
		ehData := encodeElementHeader(end.Header)
		data = append(data, asn1.Marshal(0xA0, nil, ehData...)...)
	}

	return data, nil
}
