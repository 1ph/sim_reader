package esim

import (
	"encoding/hex"
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
		case 18: // ef-dck
			u.EF_DCK = decodeElementaryFile(inner)
		case 19: // ef-cnl
			u.EF_CNL = decodeElementaryFile(inner)
		case 20: // ef-smsr
			u.EF_SMSR = decodeElementaryFile(inner)
		case 21: // ef-bdn
			u.EF_BDN = decodeElementaryFile(inner)
		case 22: // ef-ext5
			u.EF_EXT5 = decodeElementaryFile(inner)
		case 23: // ef-ccp2
			u.EF_CCP2 = decodeElementaryFile(inner)
		case 24: // ef-ext4
			u.EF_EXT4 = decodeElementaryFile(inner)
		case 25: // ef-acl
			u.EF_ACL = decodeElementaryFile(inner)
		case 26: // ef-cmi
			u.EF_CMI = decodeElementaryFile(inner)
		case 27: // ef-ici
			u.EF_ICI = decodeElementaryFile(inner)
		case 28: // ef-oci
			u.EF_OCI = decodeElementaryFile(inner)
		case 29: // ef-ict
			u.EF_ICT = decodeElementaryFile(inner)
		case 30: // ef-oct
			u.EF_OCT = decodeElementaryFile(inner)
		case 31: // ef-vgcs
			u.EF_VGCS = decodeElementaryFile(inner)
		case 32: // ef-vgcss
			u.EF_VGCSS = decodeElementaryFile(inner)
		case 33: // ef-vbs
			u.EF_VBS = decodeElementaryFile(inner)
		case 34: // ef-vbss
			u.EF_VBSS = decodeElementaryFile(inner)
		case 35: // ef-emlpp
			u.EF_EMLPP = decodeElementaryFile(inner)
		case 36: // ef-aaem
			u.EF_AAEM = decodeElementaryFile(inner)
		case 37: // ef-hiddenkey
			u.EF_HIDDENKEY = decodeElementaryFile(inner)
		case 38: // ef-pnn
			u.EF_PNN = decodeElementaryFile(inner)
		case 39: // ef-opl
			u.EF_OPL = decodeElementaryFile(inner)
		case 40: // ef-mbdn
			u.EF_MBDN = decodeElementaryFile(inner)
		case 41: // ef-ext6
			u.EF_EXT6 = decodeElementaryFile(inner)
		case 42: // ef-mbi
			u.EF_MBI = decodeElementaryFile(inner)
		case 43: // ef-mwis
			u.EF_MWIS = decodeElementaryFile(inner)
		case 44: // ef-cfis
			u.EF_CFIS = decodeElementaryFile(inner)
		case 45: // ef-ext7
			u.EF_EXT7 = decodeElementaryFile(inner)
		case 46: // ef-spdi
			u.EF_SPDI = decodeElementaryFile(inner)
		case 47: // ef-mmsn
			u.EF_MMSN = decodeElementaryFile(inner)
		case 48: // ef-ext8
			u.EF_EXT8 = decodeElementaryFile(inner)
		case 49: // ef-mmsicp
			u.EF_MMSICP = decodeElementaryFile(inner)
		case 50: // ef-mmsup
			u.EF_MMSUP = decodeElementaryFile(inner)
		case 51: // ef-mmsucp
			u.EF_MMSUCP = decodeElementaryFile(inner)
		case 52: // ef-nia
			u.EF_NIA = decodeElementaryFile(inner)
		case 53: // ef-vgcsca
			u.EF_VGCSCA = decodeElementaryFile(inner)
		case 54: // ef-vbsca
			u.EF_VBSCA = decodeElementaryFile(inner)
		case 55: // ef-gbabp
			u.EF_GBABP = decodeElementaryFile(inner)
		case 56: // ef-msk
			u.EF_MSK = decodeElementaryFile(inner)
		case 57: // ef-muk
			u.EF_MUK = decodeElementaryFile(inner)
		case 58: // ef-ehplmn
			u.EF_EHPLMN = decodeElementaryFile(inner)
		case 59: // ef-gbanl
			u.EF_GBANL = decodeElementaryFile(inner)
		case 60: // ef-ehplmnpi
			u.EF_EHPLMNPI = decodeElementaryFile(inner)
		case 61: // ef-lrplmnsi
			u.EF_LRPLMNSI = decodeElementaryFile(inner)
		case 62: // ef-nafkca
			u.EF_NAFKCA = decodeElementaryFile(inner)
		case 63: // ef-spni
			u.EF_SPNI = decodeElementaryFile(inner)
		case 64: // ef-pnni
			u.EF_PNNI = decodeElementaryFile(inner)
		case 65: // ef-ncp-ip
			u.EF_NCP_IP = decodeElementaryFile(inner)
		case 66: // ef-ufc
			u.EF_UFC = decodeElementaryFile(inner)
		case 67: // ef-nasconfig
			u.EF_NASCONFIG = decodeElementaryFile(inner)
		case 68: // ef-uicciari
			u.EF_UICCIARI = decodeElementaryFile(inner)
		case 69: // ef-pws
			u.EF_PWS = decodeElementaryFile(inner)
		case 70: // ef-fdnuri
			u.EF_FDNURI = decodeElementaryFile(inner)
		case 71: // ef-bdnuri
			u.EF_BDNURI = decodeElementaryFile(inner)
		case 72: // ef-sdnuri
			u.EF_SDNURI = decodeElementaryFile(inner)
		case 73: // ef-ial
			u.EF_IAL = decodeElementaryFile(inner)
		case 74: // ef-ips
			u.EF_IPS = decodeElementaryFile(inner)
		case 75: // ef-ipd
			u.EF_IPD = decodeElementaryFile(inner)
		case 76: // ef-epdgid
			u.EF_EPDGID = decodeElementaryFile(inner)
		case 77: // ef-epdgselection
			u.EF_EPDGSELECTION = decodeElementaryFile(inner)
		case 78: // ef-epdgidem
			u.EF_EPDGIDEM = decodeElementaryFile(inner)
		case 79: // ef-epdgselectionem
			u.EF_EPDGSELECTIONEM = decodeElementaryFile(inner)
		case 80: // ef-frompreferred
			u.EF_FROMPREFERRED = decodeElementaryFile(inner)
		case 81: // ef-imsconfigdata
			u.EF_IMSCONFIGDATA = decodeElementaryFile(inner)
		case 82: // ef-3gpppsdataoff
			u.EF_3GPPPSDATAOFF = decodeElementaryFile(inner)
		case 83: // ef-3gpppsdataoffservicelist
			u.EF_3GPPPSDATAOFFSERVICELIST = decodeElementaryFile(inner)
		case 84: // ef-xcapconfigdata
			u.EF_XCAPCONFIGDATA = decodeElementaryFile(inner)
		case 85: // ef-earfcnlist
			u.EF_EARFCNLIST = decodeElementaryFile(inner)
		case 86: // ef-mudmidconfigdata
			u.EF_MUDMIDCONFIGDATA = decodeElementaryFile(inner)
		case 87: // ef-eaka
			u.EF_EAKA = decodeElementaryFile(inner)
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
		case 3, 7: // ef-gbabp (can be 3 or 7 depending on spec version)
			i.EF_GBABP = decodeElementaryFile(inner)
		case 4, 8: // ef-gbanl (can be 4 or 8 depending on spec version)
			i.EF_GBANL = decodeElementaryFile(inner)
		case 5: // ef-nasconfig
			i.EF_NASCONFIG = decodeElementaryFile(inner)
		case 6: // ef-uicciari
			i.EF_UICCIARI = decodeElementaryFile(inner)
		case 9: // ef-xcapconfigdata
			i.EF_XCAPCONFIGDATA = decodeElementaryFile(inner)
		case 10: // ef-eaka
			i.EF_EAKA = decodeElementaryFile(inner)
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
		case 4: // ef-call-count
			c.EF_CallCount = decodeElementaryFile(inner)
		case 5: // ef-imsi-m
			c.EF_IMSI_M = decodeElementaryFile(inner)
		case 6: // ef-imsi-t
			c.EF_IMSI_T = decodeElementaryFile(inner)
		case 7: // ef-tmsi
			c.EF_TMSI = decodeElementaryFile(inner)
		case 8: // ef-ah
			c.EF_AH = decodeElementaryFile(inner)
		case 9: // ef-aop
			c.EF_AOP = decodeElementaryFile(inner)
		case 10: // ef-aloc
			c.EF_ALOC = decodeElementaryFile(inner)
		case 11: // ef-cdmahome
			c.EF_CDMAHOME = decodeElementaryFile(inner)
		case 12: // ef-znregi
			c.EF_ZNREGI = decodeElementaryFile(inner)
		case 13: // ef-snregi
			c.EF_SNREGI = decodeElementaryFile(inner)
		case 14: // ef-distregi
			c.EF_DISTREGI = decodeElementaryFile(inner)
		case 15: // ef-accolc
			c.EF_ACCOLC = decodeElementaryFile(inner)
		case 16: // ef-term
			c.EF_TERM = decodeElementaryFile(inner)
		case 17: // ef-acp
			c.EF_ACP = decodeElementaryFile(inner)
		case 18: // ef-prl
			c.EF_PRL = decodeElementaryFile(inner)
		case 19: // ef-ruimid
			c.EF_RUIMID = decodeElementaryFile(inner)
		case 20: // ef-csim-st
			c.EF_CSIM_ST = decodeElementaryFile(inner)
		case 21: // ef-spc
			c.EF_SPC = decodeElementaryFile(inner)
		case 22: // ef-otapaspc
			c.EF_OTAPASPC = decodeElementaryFile(inner)
		case 23: // ef-namlock
			c.EF_NAMLOCK = decodeElementaryFile(inner)
		case 24: // ef-ota
			c.EF_OTA = decodeElementaryFile(inner)
		case 25: // ef-sp
			c.EF_SP = decodeElementaryFile(inner)
		case 26: // ef-esn-meid-me
			c.EF_ESN_MEID_ME = decodeElementaryFile(inner)
		case 27: // ef-li
			c.EF_LI = decodeElementaryFile(inner)
		case 28: // ef-usgind
			c.EF_USGIND = decodeElementaryFile(inner)
		case 29: // ef-ad
			c.EF_AD = decodeElementaryFile(inner)
		case 30: // ef-max-prl
			c.EF_MAX_PRL = decodeElementaryFile(inner)
		case 31: // ef-spcs
			c.EF_SPCS = decodeElementaryFile(inner)
		case 32: // ef-mecrp
			c.EF_MECRP = decodeElementaryFile(inner)
		case 33: // ef-home-tag
			c.EF_HOME_TAG = decodeElementaryFile(inner)
		case 34: // ef-group-tag
			c.EF_GROUP_TAG = decodeElementaryFile(inner)
		case 35: // ef-specific-tag
			c.EF_SPECIFIC_TAG = decodeElementaryFile(inner)
		case 36: // ef-call-prompt
			c.EF_CALL_PROMPT = decodeElementaryFile(inner)
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
		case 2: // ef-ssci
			c.EF_SSCI = decodeElementaryFile(inner)
		case 3: // ef-fdn
			c.EF_FDN = decodeElementaryFile(inner)
		case 4: // ef-sms
			c.EF_SMS = decodeElementaryFile(inner)
		case 5: // ef-smsp
			c.EF_SMSP = decodeElementaryFile(inner)
		case 6: // ef-smss
			c.EF_SMSS = decodeElementaryFile(inner)
		case 7: // ef-ssfc
			c.EF_SSFC = decodeElementaryFile(inner)
		case 8: // ef-spn
			c.EF_SPN = decodeElementaryFile(inner)
		case 9: // ef-mdn
			c.EF_MDN = decodeElementaryFile(inner)
		case 10: // ef-ecc
			c.EF_ECC = decodeElementaryFile(inner)
		case 11: // ef-me3gpdopc
			c.EF_ME3GPDOPC = decodeElementaryFile(inner)
		case 12: // ef-3gpdopm
			c.EF_3GPDOPM = decodeElementaryFile(inner)
		case 13: // ef-sipcap
			c.EF_SIPCAP = decodeElementaryFile(inner)
		case 14: // ef-mipcap
			c.EF_MIPCAP = decodeElementaryFile(inner)
		case 15: // ef-sipupp
			c.EF_SIPUPP = decodeElementaryFile(inner)
		case 16: // ef-mipupp
			c.EF_MIPUPP = decodeElementaryFile(inner)
		case 17: // ef-sipsp
			c.EF_SIPSP = decodeElementaryFile(inner)
		case 18: // ef-mipsp
			c.EF_MIPSP = decodeElementaryFile(inner)
		case 19: // ef-sippapss
			c.EF_SIPPAPSS = decodeElementaryFile(inner)
		case 22: // ef-hrpdcap
			c.EF_HRPDCAP = decodeElementaryFile(inner)
		case 23: // ef-hrpdupp
			c.EF_HRPDUPP = decodeElementaryFile(inner)
		case 24: // ef-csspr
			c.EF_CSSPR = decodeElementaryFile(inner)
		case 25: // ef-atc
			c.EF_ATC = decodeElementaryFile(inner)
		case 26: // ef-eprl
			c.EF_EPRL = decodeElementaryFile(inner)
		case 30: // ef-bcsmsp
			c.EF_BCSMSP = decodeElementaryFile(inner)
		case 33: // ef-mmsn
			c.EF_MMSN = decodeElementaryFile(inner)
		case 34: // ef-ext8
			c.EF_EXT8 = decodeElementaryFile(inner)
		case 35: // ef-mmsicp
			c.EF_MMSICP = decodeElementaryFile(inner)
		case 36: // ef-mmsup
			c.EF_MMSUP = decodeElementaryFile(inner)
		case 37: // ef-mmsucp
			c.EF_MMSUCP = decodeElementaryFile(inner)
		case 39: // ef-3gcik
			c.EF_3GCIK = decodeElementaryFile(inner)
		case 41: // ef-gid1
			c.EF_GID1 = decodeElementaryFile(inner)
		case 42: // ef-gid2
			c.EF_GID2 = decodeElementaryFile(inner)
		case 44: // ef-sf-euimid
			c.EF_SF_EUIMID = decodeElementaryFile(inner)
		case 45: // ef-est
			c.EF_EST = decodeElementaryFile(inner)
		case 46: // ef-hidden-key
			c.EF_HIDDEN_KEY = decodeElementaryFile(inner)
		case 49: // ef-sdn
			c.EF_SDN = decodeElementaryFile(inner)
		case 50: // ef-ext2
			c.EF_EXT2 = decodeElementaryFile(inner)
		case 51: // ef-ext3
			c.EF_EXT3 = decodeElementaryFile(inner)
		case 52: // ef-ici
			c.EF_ICI = decodeElementaryFile(inner)
		case 53: // ef-oci
			c.EF_OCI = decodeElementaryFile(inner)
		case 54: // ef-ext5
			c.EF_EXT5 = decodeElementaryFile(inner)
		case 55: // ef-ccp2
			c.EF_CCP2 = decodeElementaryFile(inner)
		case 57: // ef-model
			c.EF_MODEL = decodeElementaryFile(inner)
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
		case 11: // ef-suci-calc-info-ni (added in later specs)
			// d.EF_SUCI_CALC_INFO_NI = decodeElementaryFile(inner)
		case 12: // ef-routing-indicator
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
		SQNInit:    make([][]byte, 0),
		SQNOptions: 0x02, // Default from reference if missing
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

	// Set defaults for missing fields if USIM Test Algorithm
	if aka.AlgoConfig != nil && aka.AlgoConfig.AlgorithmID == AlgoUSIMTestAlgorithm {
		if len(aka.SQNDelta) == 0 {
			aka.SQNDelta, _ = hex.DecodeString("000010000000")
		}
		if len(aka.SQNAgeLimit) == 0 {
			aka.SQNAgeLimit, _ = hex.DecodeString("000010000000")
		}
		if len(aka.SQNInit) == 0 {
			for i := 0; i < 32; i++ {
				aka.SQNInit = append(aka.SQNInit, make([]byte, 6))
			}
		}
	}

	return aka, nil
}

func decodeAlgoConfiguration(a *asn1.ASN1) *AlgoConfiguration {
	ac := &AlgoConfiguration{
		NumberOfKeccak: 1, // Default from reference
	}

	// AlgoConfiguration is a CHOICE: [0] milenage, [1] tuak
	if !a.Unmarshal() {
		return ac
	}

	// choiceTag := getContextTag(a)
	inner := asn1.Init(a.Data)

	// Fields inside are AlgoParameter (SEQUENCE)
	for inner.Unmarshal() {
		parseAlgoField(inner, ac)
	}

	// Set defaults for Milenage/USIMTestAlgorithm if missing
	if ac.AlgorithmID == AlgoMilenage || ac.AlgorithmID == AlgoUSIMTestAlgorithm {
		if len(ac.RotationConstants) == 0 {
			ac.RotationConstants, _ = hex.DecodeString("4000204060")
		}
		if len(ac.XoringConstants) == 0 {
			ac.XoringConstants, _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000020000000000000000000000000000000400000000000000000000000000000008")
		}
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

		// SGP.22 PE-GenericFileManagement:
		// FileManagementCMD ::= SEQUENCE OF CHOICE {
		//   filePath [0] OCTET STRING,
		//   createFCP FCP-Template, (APPLICATION 2)
		//   fillFileContent [1] OCTET STRING,
		//   fillFileOffset [2] UInt16
		// }
		
		tagNum := getContextTag(a)
		
		switch {
		case a.Class == asn1.ClassContextSpecific && tagNum == 0: // filePath [0]
			item.ItemType = 0
			item.FilePath = copyBytes(a.Data)
		case a.Tag == 0x62: // createFCP (APPLICATION 2)
			item.ItemType = 1
			item.CreateFCP = decodeFileDescriptor(asn1.Init(a.Data))
		case a.Class == asn1.ClassContextSpecific && tagNum == 1: // fillFileContent [1]
			item.ItemType = 2
			item.FillFileContent = copyBytes(a.Data)
		case a.Class == asn1.ClassContextSpecific && tagNum == 2: // fillFileOffset [2]
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

	uiccAccessSet := false

	for a.Unmarshal() {
		switch {
		case a.Class == asn1.ClassContextSpecific && getTagNumber(a) == 0:
			inner := asn1.Init(a.Data)
			if rfm.Header == nil {
				rfm.Header = decodeElementHeader(inner)
			} else {
				// tarList [0]
				for inner.Unmarshal() {
					rfm.TARList = append(rfm.TARList, copyBytes(inner.Data))
				}
			}

		case a.Class == asn1.ClassApplication && getTagNumber(a) == 15:
			rfm.InstanceAID = copyBytes(a.Data)

		case a.Class == asn1.ClassContextSpecific && getTagNumber(a) == 1:
			if len(a.Data) > 0 {
				rfm.MinimumSecurityLevel = a.Data[0]
			}

		case a.Class == asn1.ClassUniversal && getTagNumber(a) == 4:
			if !uiccAccessSet {
				if len(a.Data) > 0 {
					rfm.UICCAccessDomain = a.Data[0]
				}
				uiccAccessSet = true
			} else {
				if len(a.Data) > 0 {
					rfm.UICCAdminAccessDomain = a.Data[0]
				}
			}

		case a.Class == asn1.ClassUniversal && getTagNumber(a) == 16:
			inner := asn1.Init(a.Data)
			rfm.ADFRFMAccess = decodeADFRFMAccess(inner)

		case a.Class == asn1.ClassContextSpecific && getTagNumber(a) == 5:
			// Fallback if adfRFMAccess is [5]
			inner := asn1.Init(a.Data)
			rfm.ADFRFMAccess = decodeADFRFMAccess(inner)
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
