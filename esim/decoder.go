package esim

import (
	"fmt"
	"sim_reader/esim/asn1"
)

// DecodeProfile decodes DER file into Profile structure
func DecodeProfile(data []byte) (*Profile, error) {
	profile := &Profile{
		Elements: make([]ProfileElement, 0),
	}

	offset := 0
	a := asn1.Init(data)

	for a.Unmarshal() {
		// Calculate raw bytes for this element (full TLV)
		elemLen := a.FullLen()
		rawBytes := copyBytes(data[offset : offset+elemLen])
		offset += elemLen

		elem, err := decodeProfileElement(a, rawBytes)
		if err != nil {
			return nil, fmt.Errorf("decode element at offset: %w", err)
		}

		profile.Elements = append(profile.Elements, *elem)

		// populate convenience references
		assignToProfile(profile, elem)
	}

	return profile, nil
}

// decodeProfileElement decodes single ProfileElement (CHOICE)
func decodeProfileElement(a *asn1.ASN1, rawBytes []byte) (*ProfileElement, error) {
	tagNum := getTagNumber(a)

	elem := &ProfileElement{Tag: tagNum, RawBytes: rawBytes}
	inner := asn1.Init(a.Data)

	var err error
	switch tagNum {
	case TagProfileHeader:
		elem.Value, err = decodeProfileHeader(inner)
	case TagMF:
		elem.Value, err = decodeMasterFile(inner)
	case TagPukCodes:
		elem.Value, err = decodePUKCodes(inner)
	case TagPinCodes:
		elem.Value, err = decodePINCodes(inner)
	case TagTelecom:
		elem.Value, err = decodeTelecom(inner)
	case TagUSIM:
		elem.Value, err = decodeUSIM(inner)
	case TagOptUSIM:
		elem.Value, err = decodeOptUSIM(inner)
	case TagISIM:
		elem.Value, err = decodeISIM(inner)
	case TagOptISIM:
		elem.Value, err = decodeOptISIM(inner)
	case TagCSIM:
		elem.Value, err = decodeCSIM(inner)
	case TagOptCSIM:
		elem.Value, err = decodeOptCSIM(inner)
	case TagGSMAccess:
		elem.Value, err = decodeGSMAccess(inner)
	case TagAKAParameter:
		elem.Value, err = decodeAKAParameter(inner)
	case TagCDMAParameter:
		elem.Value, err = decodeCDMAParameter(inner)
	case TagDF5GS:
		elem.Value, err = decodeDF5GS(inner)
	case TagDFSAIP:
		elem.Value, err = decodeDFSAIP(inner)
	case TagGenericFileManagement:
		elem.Value, err = decodeGenericFileManagement(inner)
	case TagSecurityDomain:
		elem.Value, err = decodeSecurityDomain(inner)
	case TagRFM:
		elem.Value, err = decodeRFM(inner)
	case TagApplication:
		elem.Value, err = decodeApplication(inner)
	case TagEnd:
		elem.Value, err = decodeEnd(inner)
	default:
		// Unknown tag - save raw data
		elem.Value = copyBytes(a.Data)
	}

	if err != nil {
		return nil, fmt.Errorf("tag %d: %w", tagNum, err)
	}

	return elem, nil
}

// ============================================================================
// ProfileHeader [0]
// ============================================================================

func decodeProfileHeader(a *asn1.ASN1) (*ProfileHeader, error) {
	h := &ProfileHeader{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		// Tags according to PE_Definitions ASN.1 with AUTOMATIC TAGS:
		// 0=major-version, 1=minor-version, 2=profileType, 3=iccid
		// 4=pol, 5=eUICC-Mandatory-services, 6=eUICC-Mandatory-GFSTEList
		// 7=connectivityParameters, 8=eUICC-Mandatory-AIDs, 9=iotOptions
		switch tagNum {
		case 0: // major-version
			h.MajorVersion = decodeInteger(a.Data)
		case 1: // minor-version
			h.MinorVersion = decodeInteger(a.Data)
		case 2: // profileType
			h.ProfileType = string(a.Data)
		case 3: // iccid
			h.ICCID = copyBytes(a.Data)
		case 4: // pol (optional)
			// Skip for now
		case 5: // eUICC-Mandatory-services
			h.MandatoryServices = decodeMandatoryServices(inner)
		case 6: // eUICC-Mandatory-GFSTEList
			h.MandatoryGFSTEList = decodeOIDList(inner)
		}
	}

	return h, nil
}

func decodeMandatoryServices(a *asn1.ASN1) *MandatoryServices {
	ms := &MandatoryServices{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		// Tags according to PE_Definitions ASN.1 with AUTOMATIC TAGS:
		// 0=contactless, 1=usim, 2=isim, 3=csim, 4=milenage, 5=tuak128, 6=cave
		// 7=gba-usim, 8=gba-isim, 9=mbms, 10=eap, 11=javacard, 12=multos
		// 13=multiple-usim, 14=multiple-isim, 15=multiple-csim, 16=tuak256
		// 17=usim-test-algorithm, 18=ber-tlv, 19=dfLink, 20=cat-tp
		// 21=get-identity, 22=profile-a-x25519, 23=profile-b-p256
		// 24=suciCalculatorApi, 25=dns-resolution, 26=scp11ac
		// 27=scp11c-authorization-mechanism, 28=s16mode, 29=eaka
		switch tagNum {
		case 1:
			ms.USIM = true
		case 2:
			ms.ISIM = true
		case 3:
			ms.CSIM = true
		case 17:
			ms.USIMTestAlgorithm = true
		case 18:
			ms.BERTLV = true
		case 21:
			ms.GetIdentity = true
		case 22:
			ms.ProfileAX25519 = true
		case 23:
			ms.ProfileBP256 = true
		}
	}

	return ms
}

// ============================================================================
// MasterFile [1]
// ============================================================================

func decodeMasterFile(a *asn1.ASN1) (*MasterFile, error) {
	mf := &MasterFile{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // mf-header
			mf.MFHeader = decodeElementHeader(inner)
		case 1: // templateID
			mf.TemplateID = decodeOID(a.Data)
		case 2: // mf - File (SEQUENCE OF CHOICE)
			mf.MF = decodeFileFromFile(inner)
		case 3: // ef-pl
			mf.EF_PL = decodeElementaryFile(inner)
		case 4: // ef-iccid
			mf.EF_ICCID = decodeElementaryFile(inner)
		case 5: // ef-dir
			mf.EF_DIR = decodeElementaryFile(inner)
		case 6: // ef-arr
			mf.EF_ARR = decodeElementaryFile(inner)
		case 7: // ef-umpc
			mf.EF_UMPC = decodeElementaryFile(inner)
		case 8: // efList
			for inner.Unmarshal() {
				mf.EFList = append(mf.EFList, decodeElementaryFile(asn1.Init(inner.Data)))
			}
		}
	}

	return mf, nil
}

// ============================================================================
// Common decoders
// ============================================================================

func decodeElementHeader(a *asn1.ASN1) *ElementHeader {
	eh := &ElementHeader{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // mandated
			eh.Mandated = true
		case 1: // identification
			eh.Identification = decodeInteger(a.Data)
		}
	}

	return eh
}

func decodeFileDescriptor(a *asn1.ASN1) *FileDescriptor {
	fd := &FileDescriptor{
		LCSI: []byte{0x05}, // Default value
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		// Handle PRIVATE class tags first
		if a.Class == asn1.ClassPrivate {
			switch tagNum {
			case 6: // pinStatusTemplateDO [PRIVATE 6]
				fd.PinStatusTemplateDO = copyBytes(a.Data)
			case 7: // linkPath [PRIVATE 7]
				fd.LinkPath = copyBytes(a.Data)
			}
			continue
		}

		// Context-specific tags (Fcp uses AUTOMATIC TAGS starting from defined numbers)
		switch tagNum {
		case 0: // efFileSize [0]
			fd.EFFileSize = copyBytes(a.Data)
		case 2: // fileDescriptor [2]
			fd.FileDescriptor = copyBytes(a.Data)
		case 3: // fileID [3]
			fd.FileID = copyBytes(a.Data)
		case 4: // dfName [4]
			fd.DFName = copyBytes(a.Data)
		case 5: // proprietaryEFInfo [5]
			fd.ProprietaryEFInfo = decodeProprietaryEFInfo(inner)
		case 8: // shortEFID [8]
			fd.ShortEFID = copyBytes(a.Data)
		case 10: // lcsi [10]
			fd.LCSI = copyBytes(a.Data)
		case 11: // securityAttributesReferenced [11]
			fd.SecurityAttributesReferenced = copyBytes(a.Data)
		}
	}

	return fd
}

func decodeProprietaryEFInfo(a *asn1.ASN1) *ProprietaryEFInfo {
	pei := &ProprietaryEFInfo{
		SpecialFileInformation: []byte{0x00}, // Default value
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // specialFileInformation
			pei.SpecialFileInformation = copyBytes(a.Data)
		case 1: // fillPattern
			pei.FillPattern = copyBytes(a.Data)
		case 2: // repeatPattern
			pei.RepeatPattern = copyBytes(a.Data)
		case 4: // fileDetails
			pei.FileDetails = copyBytes(a.Data)
		case 6: // maximumFileSize
			pei.MaximumFileSize = copyBytes(a.Data)
		}
	}

	return pei
}

// decodeFileFromFile extracts FileDescriptor from File (SEQUENCE OF CHOICE)
// This is used for DF/ADF entries which are File type containing fileDescriptor [1] Fcp
func decodeFileFromFile(a *asn1.ASN1) *FileDescriptor {
	for a.Unmarshal() {
		tagNum := getContextTag(a)
		if tagNum == 1 { // fileDescriptor [1] Fcp
			return decodeFileDescriptor(asn1.Init(a.Data))
		}
	}
	return &FileDescriptor{}
}

func decodeElementaryFile(a *asn1.ASN1) *ElementaryFile {
	ef := &ElementaryFile{
		FillContents: make([]FillContent, 0),
		Raw:          make(File, 0),
	}

	var currentOffset int

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		// File ::= SEQUENCE OF CHOICE { doNotCreate[0], fileDescriptor[1], fillFileOffset[2], fillFileContent[3] }
		switch tagNum {
		case 0: // doNotCreate NULL
			ef.Raw = append(ef.Raw, FileElement{Type: FileElementDoNotCreate})
		case 1: // fileDescriptor Fcp
			fd := decodeFileDescriptor(inner)
			ef.Descriptor = fd
			ef.Raw = append(ef.Raw, FileElement{Type: FileElementDescriptor, Descriptor: fd})
		case 2: // fillFileOffset UInt16
			currentOffset = decodeInteger(a.Data)
			ef.Raw = append(ef.Raw, FileElement{Type: FileElementOffset, Offset: currentOffset})
		case 3: // fillFileContent OCTET STRING
			content := copyBytes(a.Data)
			ef.FillContents = append(ef.FillContents, FillContent{
				Offset:  currentOffset,
				Content: content,
			})
			ef.Raw = append(ef.Raw, FileElement{Type: FileElementContent, Content: content})
		}
	}

	return ef
}

// ============================================================================
// PUK/PIN Codes [2], [3]
// ============================================================================

func decodePUKCodes(a *asn1.ASN1) (*PUKCodes, error) {
	puk := &PUKCodes{
		Codes: make([]PUKCode, 0),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // puk-Header
			puk.Header = decodeElementHeader(inner)
		case 1: // pukCodes
			for inner.Unmarshal() {
				code := decodePUKCode(asn1.Init(inner.Data))
				puk.Codes = append(puk.Codes, code)
			}
		}
	}

	return puk, nil
}

func decodePUKCode(a *asn1.ASN1) PUKCode {
	code := PUKCode{
		MaxNumOfAttempsRetryNumLeft: 170, // Default value
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // keyReference - INTEGER encoded, may have leading zero for values >= 0x80
			code.KeyReference = byte(decodeInteger(a.Data))
		case 1: // pukValue
			code.PUKValue = copyBytes(a.Data)
		case 2: // maxNumOfAttemps-retryNumLeft - INTEGER encoded
			code.MaxNumOfAttempsRetryNumLeft = byte(decodeInteger(a.Data))
		}
	}

	return code
}

func decodePINCodes(a *asn1.ASN1) (*PINCodes, error) {
	pin := &PINCodes{
		Configs: make([]PINConfig, 0),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // pin-Header
			pin.Header = decodeElementHeader(inner)
		case 1: // pinCodes (CHOICE: [0] pinconfig or [1] pincodesUncompressed)
			// First parse the CHOICE tag
			if inner.Unmarshal() {
				choiceTag := getContextTag(inner)
				choiceInner := asn1.Init(inner.Data)

				switch choiceTag {
				case 0: // pinconfig - SEQUENCE OF PINConfiguration
					for choiceInner.Unmarshal() {
						config := decodePINConfig(asn1.Init(choiceInner.Data))
						pin.Configs = append(pin.Configs, config)
					}
				case 1: // pincodesUncompressed - SEQUENCE OF PINConfigurationUncompressed
					for choiceInner.Unmarshal() {
						config := decodePINConfig(asn1.Init(choiceInner.Data))
						pin.Configs = append(pin.Configs, config)
					}
				}
			}
		}
	}

	return pin, nil
}

func decodePINConfig(a *asn1.ASN1) PINConfig {
	config := PINConfig{
		PINAttributes:               7,  // Default value
		MaxNumOfAttempsRetryNumLeft: 51, // Default value
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // keyReference - INTEGER encoded, may have leading zero for values >= 0x80
			config.KeyReference = byte(decodeInteger(a.Data))
		case 1: // pinValue
			config.PINValue = copyBytes(a.Data)
		case 2: // unblockingPINReference - INTEGER encoded
			config.UnblockingPINReference = byte(decodeInteger(a.Data))
		case 3: // pinAttributes - INTEGER encoded
			config.PINAttributes = byte(decodeInteger(a.Data))
		case 4: // maxNumOfAttemps-retryNumLeft - INTEGER encoded
			config.MaxNumOfAttempsRetryNumLeft = byte(decodeInteger(a.Data))
		}
	}

	return config
}

// ============================================================================
// Telecom [4]
// ============================================================================

func decodeTelecom(a *asn1.ASN1) (*TelecomDF, error) {
	t := &TelecomDF{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // telecom-header
			t.Header = decodeElementHeader(inner)
		case 1: // templateID
			t.TemplateID = decodeOID(a.Data)
		case 2: // df-telecom
			t.DFTelecom = decodeFileFromFile(inner)
		case 3: // ef-arr
			t.EF_ARR = decodeElementaryFile(inner)
		case 4: // ef-rma
			t.EF_RMA = decodeElementaryFile(inner)
		case 5: // ef-sume
			t.EF_SUME = decodeElementaryFile(inner)
		case 6: // ef-ice-dn
			t.EF_ICE_DN = decodeElementaryFile(inner)
		case 7: // ef-ice-ff
			t.EF_ICE_FF = decodeElementaryFile(inner)
		case 8: // ef-psismsc
			t.EF_PSISMSC = decodeElementaryFile(inner)
		case 9: // df-graphics
			t.DFGraphics = decodeFileFromFile(inner)
		case 10: // ef-img
			t.EF_IMG = decodeElementaryFile(inner)
		case 11: // ef-iidf
			t.EF_IIDF = decodeElementaryFile(inner)
		case 12: // ef-ice-graphics
			t.EF_ICE_Graphics = decodeElementaryFile(inner)
		case 13: // ef-launch-scws
			t.EF_LaunchSCWS = decodeElementaryFile(inner)
		case 14: // ef-icon
			t.EF_ICON = decodeElementaryFile(inner)
		case 15: // df-phonebook
			t.DFPhonebook = decodeFileFromFile(inner)
		case 16: // ef-pbr
			t.EF_PBR = decodeElementaryFile(inner)
		case 17: // ef-ext1
			t.EF_EXT1 = decodeElementaryFile(inner)
		case 18: // ef-aas
			t.EF_AAS = decodeElementaryFile(inner)
		case 19: // ef-gas
			t.EF_GAS = decodeElementaryFile(inner)
		case 20: // ef-psc
			t.EF_PSC = decodeElementaryFile(inner)
		case 21: // ef-cc
			t.EF_CC = decodeElementaryFile(inner)
		case 22: // ef-puid
			t.EF_PUID = decodeElementaryFile(inner)
		case 23: // ef-iap
			t.EF_IAP = decodeElementaryFile(inner)
		case 24: // ef-adn
			t.EF_ADN = decodeElementaryFile(inner)
		case 25, 36: // df-mmss
			t.DFMMSS = decodeFileFromFile(inner)
		case 26, 37: // ef-mlpl
			t.EF_MLPL = decodeElementaryFile(inner)
		case 27, 38: // ef-mspl
			t.EF_MSPL = decodeElementaryFile(inner)
		case 28, 39: // ef-mmssconf
			t.EF_MMSSCONF = decodeElementaryFile(inner)
		case 29, 40: // ef-mmssid
			t.EF_MMSSID = decodeElementaryFile(inner)
		default:
			ef := decodeElementaryFile(inner)
			t.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return t, nil
}

// ============================================================================
// USIM [8]
// ============================================================================

func decodeUSIM(a *asn1.ASN1) (*USIMApplication, error) {
	u := &USIMApplication{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // usim-header
			u.Header = decodeElementHeader(inner)
		case 1: // templateID
			u.TemplateID = decodeOID(a.Data)
		case 2: // adf-usim - File (SEQUENCE OF CHOICE)
			u.ADFUSIM = decodeFileFromFile(inner)
		case 3: // ef-imsi
			u.EF_IMSI = decodeElementaryFile(inner)
		case 4: // ef-arr
			u.EF_ARR = decodeElementaryFile(inner)
		case 5: // ef-keys
			u.EF_Keys = decodeElementaryFile(inner)
		case 6: // ef-keysPS
			u.EF_KeysPS = decodeElementaryFile(inner)
		case 7: // ef-hpplmn
			u.EF_HPPLMN = decodeElementaryFile(inner)
		case 8: // ef-ust
			u.EF_UST = decodeElementaryFile(inner)
		case 9: // ef-fdn
			u.EF_FDN = decodeElementaryFile(inner)
		case 10: // ef-sms
			u.EF_SMS = decodeElementaryFile(inner)
		case 11: // ef-smsp
			u.EF_SMSP = decodeElementaryFile(inner)
		case 12: // ef-smss
			u.EF_SMSS = decodeElementaryFile(inner)
		case 13: // ef-spn
			u.EF_SPN = decodeElementaryFile(inner)
		case 14: // ef-est
			u.EF_EST = decodeElementaryFile(inner)
		case 15: // ef-start-hfn
			u.EF_StartHFN = decodeElementaryFile(inner)
		case 16: // ef-threshold
			u.EF_Threshold = decodeElementaryFile(inner)
		case 17: // ef-psloci
			u.EF_PSLOCI = decodeElementaryFile(inner)
		case 18: // ef-acc
			u.EF_ACC = decodeElementaryFile(inner)
		case 19: // ef-fplmn
			u.EF_FPLMN = decodeElementaryFile(inner)
		case 20: // ef-loci
			u.EF_LOCI = decodeElementaryFile(inner)
		case 21: // ef-ad
			u.EF_AD = decodeElementaryFile(inner)
		case 22: // ef-ecc
			u.EF_ECC = decodeElementaryFile(inner)
		case 23: // ef-netpar
			u.EF_NETPAR = decodeElementaryFile(inner)
		case 24: // ef-epsloci
			u.EF_EPSLOCI = decodeElementaryFile(inner)
		case 25: // ef-epsnsc
			u.EF_EPSNSC = decodeElementaryFile(inner)
		default:
			ef := decodeElementaryFile(inner)
			u.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return u, nil
}

func decodeOptUSIM(a *asn1.ASN1) (*OptionalUSIM, error) {
	u := &OptionalUSIM{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // optusim-header
			u.Header = decodeElementHeader(inner)
		case 1: // templateID
			u.TemplateID = decodeOID(a.Data)
		case 2: // ef-li
			u.EF_LI = decodeElementaryFile(inner)
		case 3: // ef-acmax
			u.EF_ACMAX = decodeElementaryFile(inner)
		case 4: // ef-acm
			u.EF_ACM = decodeElementaryFile(inner)
		case 5: // ef-gid1
			u.EF_GID1 = decodeElementaryFile(inner)
		case 6: // ef-gid2
			u.EF_GID2 = decodeElementaryFile(inner)
		case 7: // ef-msisdn
			u.EF_MSISDN = decodeElementaryFile(inner)
		case 8: // ef-puct
			u.EF_PUCT = decodeElementaryFile(inner)
		case 9: // ef-cbmi
			u.EF_CBMI = decodeElementaryFile(inner)
		case 10: // ef-cbmid
			u.EF_CBMID = decodeElementaryFile(inner)
		case 11: // ef-sdn
			u.EF_SDN = decodeElementaryFile(inner)
		case 12: // ef-ext2
			u.EF_EXT2 = decodeElementaryFile(inner)
		case 13: // ef-ext3
			u.EF_EXT3 = decodeElementaryFile(inner)
		case 14: // ef-cbmir
			u.EF_CBMIR = decodeElementaryFile(inner)
		case 15: // ef-plmnwact
			u.EF_PLMNWACT = decodeElementaryFile(inner)
		case 16: // ef-oplmnwact
			u.EF_OPLMNWACT = decodeElementaryFile(inner)
		case 17: // ef-hplmnwact
			u.EF_HPLMNWACT = decodeElementaryFile(inner)
		default:
			ef := decodeElementaryFile(inner)
			u.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return u, nil
}

// ============================================================================
// ISIM [10]
// ============================================================================

func decodeISIM(a *asn1.ASN1) (*ISIMApplication, error) {
	i := &ISIMApplication{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // isim-header
			i.Header = decodeElementHeader(inner)
		case 1: // templateID
			i.TemplateID = decodeOID(a.Data)
		case 2: // adf-isim - File (SEQUENCE OF CHOICE)
			i.ADFISIM = decodeFileFromFile(inner)
		case 3: // ef-impi
			i.EF_IMPI = decodeElementaryFile(inner)
		case 4: // ef-impu
			i.EF_IMPU = decodeElementaryFile(inner)
		case 5: // ef-domain
			i.EF_DOMAIN = decodeElementaryFile(inner)
		case 6: // ef-ist
			i.EF_IST = decodeElementaryFile(inner)
		case 7: // ef-ad
			i.EF_AD = decodeElementaryFile(inner)
		case 8: // ef-arr
			i.EF_ARR = decodeElementaryFile(inner)
		default:
			ef := decodeElementaryFile(inner)
			i.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return i, nil
}

func decodeOptISIM(a *asn1.ASN1) (*OptionalISIM, error) {
	i := &OptionalISIM{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // optisim-header
			i.Header = decodeElementHeader(inner)
		case 1: // templateID
			i.TemplateID = decodeOID(a.Data)
		case 2: // ef-pcscf
			i.EF_PCSCF = decodeElementaryFile(inner)
		case 3: // ef-gbabp
			i.EF_GBABP = decodeElementaryFile(inner)
		case 4: // ef-gbanl
			i.EF_GBANL = decodeElementaryFile(inner)
		default:
			ef := decodeElementaryFile(inner)
			i.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return i, nil
}

// ============================================================================
// CSIM [12]
// ============================================================================

func decodeCSIM(a *asn1.ASN1) (*CSIMApplication, error) {
	c := &CSIMApplication{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // csim-header
			c.Header = decodeElementHeader(inner)
		case 1: // templateID
			c.TemplateID = decodeOID(a.Data)
		case 2: // adf-csim - File (SEQUENCE OF CHOICE)
			c.ADFCSIM = decodeFileFromFile(inner)
		case 3: // ef-arr
			c.EF_ARR = decodeElementaryFile(inner)
		default:
			ef := decodeElementaryFile(inner)
			c.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return c, nil
}

func decodeOptCSIM(a *asn1.ASN1) (*OptionalCSIM, error) {
	c := &OptionalCSIM{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // optcsim-header
			c.Header = decodeElementHeader(inner)
		case 1: // templateID
			c.TemplateID = decodeOID(a.Data)
		default:
			ef := decodeElementaryFile(inner)
			c.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return c, nil
}

// ============================================================================
// GSM Access [20]
// ============================================================================

func decodeGSMAccess(a *asn1.ASN1) (*GSMAccessDF, error) {
	g := &GSMAccessDF{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // gsm-access-header
			g.Header = decodeElementHeader(inner)
		case 1: // templateID
			g.TemplateID = decodeOID(a.Data)
		case 2: // df-gsm-access - File (SEQUENCE OF CHOICE)
			g.DFGSMAccess = decodeFileFromFile(inner)
		case 3: // ef-kc
			g.EF_Kc = decodeElementaryFile(inner)
		case 4: // ef-kcgprs
			g.EF_KcGPRS = decodeElementaryFile(inner)
		case 5: // ef-cpbcch
			g.EF_CPBCCH = decodeElementaryFile(inner)
		case 6: // ef-invscan
			g.EF_INVSCAN = decodeElementaryFile(inner)
		default:
			ef := decodeElementaryFile(inner)
			g.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return g, nil
}

// ============================================================================
// DF-5GS [24]
// ============================================================================

func decodeDF5GS(a *asn1.ASN1) (*DF5GS, error) {
	d := &DF5GS{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // df-5gs-header
			d.Header = decodeElementHeader(inner)
		case 1: // templateID
			d.TemplateID = decodeOID(a.Data)
		case 2: // df-df-5gs - File (SEQUENCE OF CHOICE)
			d.DFDF5GS = decodeFileFromFile(inner)
		case 3: // ef-5gs3gpploci
			d.EF_5GS3GPPLOCI = decodeElementaryFile(inner)
		case 4: // ef-5gsn3gpploci
			d.EF_5GSN3GPPLOCI = decodeElementaryFile(inner)
		case 5: // ef-5gs3gppnsc
			d.EF_5GS3GPPNSC = decodeElementaryFile(inner)
		case 6: // ef-5gsn3gppnsc
			d.EF_5GSN3GPPNSC = decodeElementaryFile(inner)
		case 7: // ef-5gauthkeys
			d.EF_5GAUTHKEYS = decodeElementaryFile(inner)
		case 8: // ef-uac-aic
			d.EF_UAC_AIC = decodeElementaryFile(inner)
		case 9: // ef-suci-calc-info
			d.EF_SUCI_CALC_INFO = decodeElementaryFile(inner)
		case 10: // ef-opl5g
			d.EF_OPL5G = decodeElementaryFile(inner)
		case 11: // ef-routing-indicator
			d.EF_ROUTING_INDICATOR = decodeElementaryFile(inner)
		default:
			ef := decodeElementaryFile(inner)
			d.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return d, nil
}

// ============================================================================
// DF-SAIP [25]
// ============================================================================

func decodeDFSAIP(a *asn1.ASN1) (*DFSAIP, error) {
	d := &DFSAIP{
		AdditionalEFs: make(map[string]*ElementaryFile),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // df-saip-header
			d.Header = decodeElementHeader(inner)
		case 1: // templateID
			d.TemplateID = decodeOID(a.Data)
		case 2: // df-df-saip - File (SEQUENCE OF CHOICE)
			d.DFDFSAIP = decodeFileFromFile(inner)
		case 3: // ef-suci-calc-info-usim
			d.EF_SUCI_CALC_INFO_USIM = decodeElementaryFile(inner)
		default:
			ef := decodeElementaryFile(inner)
			d.AdditionalEFs[fmt.Sprintf("tag_%d", tagNum)] = ef
		}
	}

	return d, nil
}

// ============================================================================
// AKA Parameter [22]
// ============================================================================

func decodeAKAParameter(a *asn1.ASN1) (*AKAParameter, error) {
	aka := &AKAParameter{
		SQNInit: make([][]byte, 0),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // aka-header
			aka.Header = decodeElementHeader(inner)
		case 1: // algoConfiguration (CHOICE)
			aka.AlgoConfig = decodeAlgoConfiguration(inner)
		case 2: // sqnOptions
			if len(a.Data) > 0 {
				aka.SQNOptions = a.Data[0]
			}
		case 3: // sqnDelta
			aka.SQNDelta = copyBytes(a.Data)
		case 4: // sqnAgeLimit
			aka.SQNAgeLimit = copyBytes(a.Data)
		case 5: // sqnInit
			for inner.Unmarshal() {
				aka.SQNInit = append(aka.SQNInit, copyBytes(inner.Data))
			}
		}
	}

	return aka, nil
}

func decodeAlgoConfiguration(a *asn1.ASN1) *AlgoConfiguration {
	ac := &AlgoConfiguration{}

	// AlgoConfiguration may be:
	// 1. Direct fields (tag [0] algorithmID, etc.) - simple encoding
	// 2. CHOICE wrapper with [0] or [1] containing AlgoParameter - SAIP 2.3 style
	
	// Try to parse first element
	if !a.Unmarshal() {
		return ac
	}
	
	firstTag := getContextTag(a)
	
	// Check if this is a CHOICE wrapper (tag [0] or [1] with inner AlgoParameter)
	if (firstTag == 0 || firstTag == 1) && len(a.Data) > 5 {
		// Check if inner data starts with [0] (algorithmID)
		innerProbe := asn1.Init(a.Data)
		if innerProbe.Unmarshal() && getContextTag(innerProbe) == 0 {
			// This is CHOICE wrapper style - parse from inside
			inner := asn1.Init(a.Data)
			for inner.Unmarshal() {
				parseAlgoField(inner, ac)
			}
			return ac
		}
	}
	
	// Direct style - first element is already a field
	parseAlgoField(a, ac)
	
	// Parse remaining fields
	for a.Unmarshal() {
		parseAlgoField(a, ac)
	}

	return ac
}

func parseAlgoField(a *asn1.ASN1, ac *AlgoConfiguration) {
	tagNum := getContextTag(a)
	switch tagNum {
	case 0: // algorithmID
		ac.AlgorithmID = AlgorithmID(decodeInteger(a.Data))
	case 1: // algorithmOptions
		if len(a.Data) > 0 {
			ac.AlgorithmOptions = a.Data[0]
		}
	case 2: // key
		ac.Key = copyBytes(a.Data)
	case 3: // opc
		ac.OPC = copyBytes(a.Data)
	case 4: // rotationConstants
		ac.RotationConstants = copyBytes(a.Data)
	case 5: // xoringConstants
		ac.XoringConstants = copyBytes(a.Data)
	case 6: // numberOfKeccak
		ac.NumberOfKeccak = decodeInteger(a.Data)
	}
}

// ============================================================================
// CDMA Parameter [23]
// ============================================================================

func decodeCDMAParameter(a *asn1.ASN1) (*CDMAParameter, error) {
	c := &CDMAParameter{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // cdma-header
			c.Header = decodeElementHeader(inner)
		case 1: // authenticationKey
			c.AuthenticationKey = copyBytes(a.Data)
		case 2: // ssd
			c.SSD = copyBytes(a.Data)
		case 3: // hrpdAccessAuthenticationData
			c.HRPDAccessAuthenticationData = copyBytes(a.Data)
		case 4: // simpleIPAuthenticationData
			c.SimpleIPAuthenticationData = copyBytes(a.Data)
		case 5: // mobileIPAuthenticationData
			c.MobileIPAuthenticationData = copyBytes(a.Data)
		}
	}

	return c, nil
}

// ============================================================================
// Generic File Management [26]
// ============================================================================

func decodeGenericFileManagement(a *asn1.ASN1) (*GenericFileManagement, error) {
	gfm := &GenericFileManagement{
		FileManagementCMDs: make([]FileManagementCMD, 0),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // gfm-header
			gfm.Header = decodeElementHeader(inner)
		case 1: // fileManagementCMD - SEQUENCE OF FileManagementCMD
			// [1] contains SEQUENCE OF FileManagementCMD
			// Each FileManagementCMD is itself SEQUENCE OF CHOICE
			for inner.Unmarshal() {
				// Each unmarshal gives us one FileManagementCMD (SEQUENCE)
				cmdInner := asn1.Init(inner.Data)
				cmd := decodeFileManagementCMD(cmdInner)
				gfm.FileManagementCMDs = append(gfm.FileManagementCMDs, cmd)
			}
		}
	}

	return gfm, nil
}

func decodeFileManagementCMD(a *asn1.ASN1) FileManagementCMD {
	cmd := make(FileManagementCMD, 0)

	for a.Unmarshal() {
		item := FileManagementItem{}

		// Check raw tag - FileManagementCMD uses IMPLICIT tags
		// 0x80 = [0] filePath (PRIMITIVE)
		// 0x62 = APPLICATION [2] createFCP (FCP template)
		// 0x82 = [2] fillFileContent (PRIMITIVE)
		// 0x83 = [3] fillFileOffset (PRIMITIVE)
		switch a.Tag {
		case 0x80: // filePath [0]
			item.ItemType = 0
			item.FilePath = copyBytes(a.Data)
		case 0x62: // createFCP - FCP template (APPLICATION [2])
			item.ItemType = 1
			item.CreateFCP = decodeFileDescriptor(asn1.Init(a.Data))
		case 0x82: // fillFileContent [2]
			item.ItemType = 2
			item.FillFileContent = copyBytes(a.Data)
		case 0x83: // fillFileOffset [3]
			item.ItemType = 3
			item.FillFileOffset = decodeInteger(a.Data)
		default:
			continue
		}
		cmd = append(cmd, item)
	}

	return cmd
}

// ============================================================================
// Security Domain [55]
// ============================================================================

func decodeSecurityDomain(a *asn1.ASN1) (*SecurityDomain, error) {
	sd := &SecurityDomain{
		KeyList: make([]SDKey, 0),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // sd-Header
			sd.Header = decodeElementHeader(inner)
		case 1: // instance
			sd.Instance = decodeSDInstance(inner)
		case 2: // keyList
			for inner.Unmarshal() {
				key := decodeSDKey(asn1.Init(inner.Data))
				sd.KeyList = append(sd.KeyList, key)
			}
		case 3: // sdPersoData
			for inner.Unmarshal() {
				sd.SDPersoData = append(sd.SDPersoData, inner.Data...)
			}
		}
	}

	return sd, nil
}

func decodeSDInstance(a *asn1.ASN1) *SDInstance {
	inst := &SDInstance{}

	// Track APPLICATION 15 tag occurrences for ordered fields
	appTagCount := 0

	for a.Unmarshal() {
		// Check raw tag for better matching
		switch a.Tag {
		case 0x4F: // APPLICATION [15] - used for AIDs
			switch appTagCount {
			case 0:
				inst.ApplicationLoadPackageAID = copyBytes(a.Data)
			case 1:
				inst.ClassAID = copyBytes(a.Data)
			case 2:
				inst.InstanceAID = copyBytes(a.Data)
			}
			appTagCount++

		case 0x82: // [2] applicationPrivileges
			inst.ApplicationPrivileges = copyBytes(a.Data)

		case 0x83: // [3] lifeCycleState
			if len(a.Data) > 0 {
				inst.LifeCycleState = a.Data[0]
			}

		case 0xC9: // PRIVATE [9] applicationSpecificParametersC9
			inst.ApplicationSpecificParamsC9 = copyBytes(a.Data)

		case 0xEA: // PRIVATE [10] CONSTRUCTED applicationParameters
			inner := asn1.Init(a.Data)
			inst.ApplicationParameters = decodeApplicationParameters(inner)
		}
	}

	return inst
}

func decodeApplicationParameters(a *asn1.ASN1) *ApplicationParameters {
	ap := &ApplicationParameters{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // uiccToolkitApplicationSpecificParametersField
			ap.UIICToolkitApplicationSpecificParametersField = copyBytes(a.Data)
		}
	}

	return ap
}

func decodeSDKey(a *asn1.ASN1) SDKey {
	key := SDKey{
		KeyCompontents: make([]KeyComponent, 0),
	}

	for a.Unmarshal() {
		// SDKey uses GlobalPlatform specific tags:
		// 0x95 = [21] IMPLICIT keyUsageQualifier
		// 0x96 = [22] IMPLICIT keyAccess (optional, DEFAULT 00)
		// 0x82 = [2] keyIdentifier
		// 0x83 = [3] keyVersionNumber
		// 0x30 = SEQUENCE for keyCompontents
		switch a.Tag {
		case 0x95: // keyUsageQualifier [21]
			if len(a.Data) > 0 {
				key.KeyUsageQualifier = a.Data[0]
			}
		case 0x96: // keyAccess [22]
			if len(a.Data) > 0 {
				key.KeyAccess = a.Data[0]
			}
		case 0x82: // keyIdentifier [2]
			if len(a.Data) > 0 {
				key.KeyIdentifier = a.Data[0]
			}
		case 0x83: // keyVersionNumber [3]
			if len(a.Data) > 0 {
				key.KeyVersionNumber = a.Data[0]
			}
		case 0x30: // SEQUENCE = keyCompontents
			inner := asn1.Init(a.Data)
			for inner.Unmarshal() {
				comp := decodeKeyComponent(asn1.Init(inner.Data))
				key.KeyCompontents = append(key.KeyCompontents, comp)
			}
		}
	}

	return key
}

func decodeKeyComponent(a *asn1.ASN1) KeyComponent {
	kc := KeyComponent{
		MACLength: 8, // Default value
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // keyType [0]
			if len(a.Data) > 0 {
				kc.KeyType = a.Data[0]
			}
		case 6: // keyData [6] - GlobalPlatform uses [6] for key data
			kc.KeyData = copyBytes(a.Data)
		case 7: // macLength [7] - if present after keyData
			kc.MACLength = decodeInteger(a.Data)
		}
	}

	return kc
}

// ============================================================================
// RFM [56]
// ============================================================================

func decodeRFM(a *asn1.ASN1) (*RFMConfig, error) {
	rfm := &RFMConfig{
		TARList: make([][]byte, 0),
	}

	for a.Unmarshal() {
		switch {
		case a.Class == asn1.ClassApplication && getTagNumber(a) == 15:
			// [APPLICATION 15] instanceAID
			rfm.InstanceAID = copyBytes(a.Data)

		case a.Class == asn1.ClassContextSpecific:
			tagNum := getContextTag(a)
			inner := asn1.Init(a.Data)

			switch tagNum {
			case 0: // rfm-header or tarList (context-specific [0])
				// Check if this contains header fields (has mandated/identification)
				// or TAR values (raw octet strings)
				probe := asn1.Init(a.Data)
				if probe.Unmarshal() && probe.Class == asn1.ClassContextSpecific {
					// It's the header
					rfm.Header = decodeElementHeader(inner)
				} else {
					// It's tarList
					for inner.Unmarshal() {
						rfm.TARList = append(rfm.TARList, copyBytes(inner.Data))
					}
				}
			case 1: // minimumSecurityLevel
				if len(a.Data) > 0 {
					rfm.MinimumSecurityLevel = a.Data[0]
				}
			case 2: // uiccAccessDomain
				if len(a.Data) > 0 {
					rfm.UICCAccessDomain = a.Data[0]
				}
			case 3: // uiccAdminAccessDomain
				if len(a.Data) > 0 {
					rfm.UICCAdminAccessDomain = a.Data[0]
				}
			case 4: // adfRFMAccess
				rfm.ADFRFMAccess = decodeADFRFMAccess(inner)
			}

		case a.Class == asn1.ClassUniversal:
			// Handle universal types if any
		}
	}

	return rfm, nil
}

func decodeADFRFMAccess(a *asn1.ASN1) *ADFRFMAccess {
	acc := &ADFRFMAccess{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // adfAID
			acc.ADFAID = copyBytes(a.Data)
		case 1: // adfAccessDomain
			if len(a.Data) > 0 {
				acc.ADFAccessDomain = a.Data[0]
			}
		case 2: // adfAdminAccessDomain
			if len(a.Data) > 0 {
				acc.ADFAdminAccessDomain = a.Data[0]
			}
		}
	}

	return acc
}

// ============================================================================
// Application [8] - PE-Application for Java Card applets
// ============================================================================

func decodeApplication(a *asn1.ASN1) (*Application, error) {
	app := &Application{
		InstanceList: make([]*ApplicationInstance, 0),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // app-Header
			app.Header = decodeElementHeader(inner)
		case 1: // loadBlock
			app.LoadBlock = decodeApplicationLoadPackage(inner)
		case 2: // instanceList
			for inner.Unmarshal() {
				inst := decodeApplicationInstance(asn1.Init(inner.Data))
				app.InstanceList = append(app.InstanceList, inst)
			}
		}
	}

	return app, nil
}

func decodeApplicationLoadPackage(a *asn1.ASN1) *ApplicationLoadPackage {
	pkg := &ApplicationLoadPackage{}

	for a.Unmarshal() {
		// APPLICATION and PRIVATE class tags
		switch {
		case a.Class == asn1.ClassApplication && getTagNumber(a) == 15:
			// [APPLICATION 15] - could be loadPackageAID or securityDomainAID
			// First occurrence is loadPackageAID, second is securityDomainAID
			if pkg.LoadPackageAID == nil {
				pkg.LoadPackageAID = copyBytes(a.Data)
			} else {
				pkg.SecurityDomainAID = copyBytes(a.Data)
			}
		case a.Class == asn1.ClassPrivate:
			tagNum := getTagNumber(a)
			switch tagNum {
			case 1: // hashValue
				pkg.HashValue = copyBytes(a.Data)
			case 4: // loadBlockObject
				pkg.LoadBlockObject = copyBytes(a.Data)
			case 6: // nonVolatileCodeLimitC6
				pkg.NonVolatileCodeLimitC6 = copyBytes(a.Data)
			case 7: // volatileDataLimitC7
				pkg.VolatileDataLimitC7 = copyBytes(a.Data)
			case 8: // nonVolatileDataLimitC8
				pkg.NonVolatileDataLimitC8 = copyBytes(a.Data)
			}
		}
	}

	return pkg
}

func decodeApplicationInstance(a *asn1.ASN1) *ApplicationInstance {
	inst := &ApplicationInstance{
		LifeCycleState: 0x07, // default per GP spec
		ProcessData:    make([][]byte, 0),
	}

	// Track APPLICATION 15 tag occurrences for ordered fields
	appTagCount := 0

	for a.Unmarshal() {
		switch {
		case a.Class == asn1.ClassApplication && getTagNumber(a) == 15:
			// [APPLICATION 15] fields in order:
			// 0: applicationLoadPackageAID
			// 1: classAID
			// 2: instanceAID
			// 3: extraditeSecurityDomainAID (optional)
			switch appTagCount {
			case 0:
				inst.ApplicationLoadPackageAID = copyBytes(a.Data)
			case 1:
				inst.ClassAID = copyBytes(a.Data)
			case 2:
				inst.InstanceAID = copyBytes(a.Data)
			case 3:
				inst.ExtraditeSecurityDomainAID = copyBytes(a.Data)
			}
			appTagCount++

		case a.Class == asn1.ClassContextSpecific:
			tagNum := getContextTag(a)
			switch tagNum {
			case 2: // applicationPrivileges
				inst.ApplicationPrivileges = copyBytes(a.Data)
			case 3: // lifeCycleState
				if len(a.Data) > 0 {
					inst.LifeCycleState = a.Data[0]
				}
			case 16: // controlReferenceTemplate
				inst.ControlReferenceTemplate = copyBytes(a.Data)
			}

		case a.Class == asn1.ClassPrivate:
			tagNum := getTagNumber(a)
			switch tagNum {
			case 9: // applicationSpecificParametersC9
				inst.ApplicationSpecificParamsC9 = copyBytes(a.Data)
			case 10: // applicationParameters (UICCApplicationParameters)
				inst.ApplicationParameters = copyBytes(a.Data)
			case 15: // systemSpecificParameters
				inst.SystemSpecificParams = copyBytes(a.Data)
			}

		case a.Class == asn1.ClassUniversal && a.Tag == 0x30:
			// SEQUENCE - this is processData (SEQUENCE OF OCTET STRING)
			inner := asn1.Init(a.Data)
			for inner.Unmarshal() {
				if inner.Tag == 0x04 { // OCTET STRING
					inst.ProcessData = append(inst.ProcessData, copyBytes(inner.Data))
				}
			}
		}
	}

	return inst
}

// ============================================================================
// End [10]
// ============================================================================

func decodeEnd(a *asn1.ASN1) (*EndElement, error) {
	end := &EndElement{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // end-header
			end.Header = decodeElementHeader(inner)
		}
	}

	return end, nil
}
