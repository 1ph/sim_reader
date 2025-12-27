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

	a := asn1.Init(data)

	for a.Unmarshal() {
		elem, err := decodeProfileElement(a)
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
func decodeProfileElement(a *asn1.ASN1) (*ProfileElement, error) {
	tagNum := getTagNumber(a)

	elem := &ProfileElement{Tag: tagNum}
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
		case 2: // mf
			mf.MF = decodeFileDescriptor(inner)
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
	fd := &FileDescriptor{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // fileDescriptor
			fd.FileDescriptor = copyBytes(a.Data)
		case 1: // fileID
			fd.FileID = decodeUint16BE(a.Data)
		case 2: // lcsi
			if len(a.Data) > 0 {
				fd.LCSI = a.Data[0]
			}
		case 3: // securityAttributesReferenced
			fd.SecurityAttributesReferenced = copyBytes(a.Data)
		case 4: // shortEFID
			if len(a.Data) > 0 {
				fd.ShortEFID = a.Data[0]
			}
		case 5: // efFileSize
			fd.EFFileSize = decodeInteger(a.Data)
		case 6: // dfName
			fd.DFName = copyBytes(a.Data)
		case 7: // pinStatusTemplateDO
			fd.PinStatusTemplateDO = copyBytes(a.Data)
		case 8: // proprietaryEFInfo
			fd.ProprietaryEFInfo = decodeProprietaryEFInfo(inner)
		case 9: // linkPath
			fd.LinkPath = copyBytes(a.Data)
		}
	}

	return fd
}

func decodeProprietaryEFInfo(a *asn1.ASN1) *ProprietaryEFInfo {
	pei := &ProprietaryEFInfo{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // specialFileInformation
			if len(a.Data) > 0 {
				pei.SpecialFileInformation = a.Data[0]
			}
		case 1: // fillPattern
			pei.FillPattern = copyBytes(a.Data)
		case 2: // repeatPattern
			pei.RepeatPattern = copyBytes(a.Data)
		}
	}

	return pei
}

func decodeElementaryFile(a *asn1.ASN1) *ElementaryFile {
	ef := &ElementaryFile{
		FillContents: make([]FillContent, 0),
	}

	var currentOffset int

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // fileDescriptor
			ef.Descriptor = decodeFileDescriptor(inner)
		case 1: // fillFileContent
			ef.FillContents = append(ef.FillContents, FillContent{
				Offset:  currentOffset,
				Content: copyBytes(a.Data),
			})
		case 2: // fillFileOffset
			currentOffset = decodeInteger(a.Data)
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
	code := PUKCode{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // keyReference
			if len(a.Data) > 0 {
				code.KeyReference = a.Data[0]
			}
		case 1: // pukValue
			code.PUKValue = copyBytes(a.Data)
		case 2: // maxNumOfAttemps-retryNumLeft
			if len(a.Data) > 0 {
				code.MaxNumOfAttempsRetryNumLeft = a.Data[0]
			}
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
		case 1: // pinCodes (CHOICE - pinconfig)
			for inner.Unmarshal() {
				config := decodePINConfig(asn1.Init(inner.Data))
				pin.Configs = append(pin.Configs, config)
			}
		}
	}

	return pin, nil
}

func decodePINConfig(a *asn1.ASN1) PINConfig {
	config := PINConfig{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // keyReference
			if len(a.Data) > 0 {
				config.KeyReference = a.Data[0]
			}
		case 1: // pinValue
			config.PINValue = copyBytes(a.Data)
		case 2: // unblockingPINReference
			if len(a.Data) > 0 {
				config.UnblockingPINReference = a.Data[0]
			}
		case 3: // pinAttributes
			if len(a.Data) > 0 {
				config.PINAttributes = a.Data[0]
			}
		case 4: // maxNumOfAttemps-retryNumLeft
			if len(a.Data) > 0 {
				config.MaxNumOfAttempsRetryNumLeft = a.Data[0]
			}
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
			t.DFTelecom = decodeFileDescriptor(inner)
		case 3: // ef-arr
			t.EF_ARR = decodeElementaryFile(inner)
		case 4: // ef-sume
			t.EF_SUME = decodeElementaryFile(inner)
		case 5: // ef-psismsc
			t.EF_PSISMSC = decodeElementaryFile(inner)
		case 6: // df-graphics
			t.DFGraphics = decodeFileDescriptor(inner)
		case 7: // ef-img
			t.EF_IMG = decodeElementaryFile(inner)
		case 8: // ef-launch-scws
			t.EF_LaunchSCWS = decodeElementaryFile(inner)
		case 9: // df-phonebook
			t.DFPhonebook = decodeFileDescriptor(inner)
		case 10: // ef-pbr
			t.EF_PBR = decodeElementaryFile(inner)
		case 11: // ef-psc
			t.EF_PSC = decodeElementaryFile(inner)
		case 12: // ef-cc
			t.EF_CC = decodeElementaryFile(inner)
		case 13: // ef-puid
			t.EF_PUID = decodeElementaryFile(inner)
		case 14: // df-mmss
			t.DFMMSS = decodeFileDescriptor(inner)
		case 15: // ef-mlpl
			t.EF_MLPL = decodeElementaryFile(inner)
		case 16: // ef-mspl
			t.EF_MSPL = decodeElementaryFile(inner)
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
		case 2: // adf-usim
			u.ADFUSIM = decodeFileDescriptor(inner)
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
		case 2: // adf-isim
			i.ADFISIM = decodeFileDescriptor(inner)
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
		case 2: // adf-csim
			c.ADFCSIM = decodeFileDescriptor(inner)
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
		case 2: // df-gsm-access
			g.DFGSMAccess = decodeFileDescriptor(inner)
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
		case 2: // df-df-5gs
			d.DFDF5GS = decodeFileDescriptor(inner)
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
		case 2: // df-df-saip
			d.DFDFSAIP = decodeFileDescriptor(inner)
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

	for a.Unmarshal() {
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

	return ac
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
		case 1: // fileManagementCMD
			cmd := decodeFileManagementCMD(inner)
			gfm.FileManagementCMDs = append(gfm.FileManagementCMDs, cmd)
		}
	}

	return gfm, nil
}

func decodeFileManagementCMD(a *asn1.ASN1) FileManagementCMD {
	cmd := FileManagementCMD{
		FillFileContent: make([]FillContent, 0),
	}

	var currentOffset int

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // filePath
			cmd.FilePath = copyBytes(a.Data)
		case 1: // createFCP
			cmd.CreateFCP = decodeFileDescriptor(inner)
		case 2: // fillFileContent
			cmd.FillFileContent = append(cmd.FillFileContent, FillContent{
				Offset:  currentOffset,
				Content: copyBytes(a.Data),
			})
		case 3: // fillFileOffset
			currentOffset = decodeInteger(a.Data)
		}
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

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // applicationLoadPackageAID
			inst.ApplicationLoadPackageAID = copyBytes(a.Data)
		case 1: // classAID
			inst.ClassAID = copyBytes(a.Data)
		case 2: // instanceAID
			inst.InstanceAID = copyBytes(a.Data)
		case 3: // applicationPrivileges
			inst.ApplicationPrivileges = copyBytes(a.Data)
		case 4: // lifeCycleState
			if len(a.Data) > 0 {
				inst.LifeCycleState = a.Data[0]
			}
		case 5: // applicationSpecificParametersC9
			inst.ApplicationSpecificParamsC9 = copyBytes(a.Data)
		case 6: // applicationParameters
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
		KeyComponents: make([]KeyComponent, 0),
	}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // keyUsageQualifier
			if len(a.Data) > 0 {
				key.KeyUsageQualifier = a.Data[0]
			}
		case 1: // keyAccess
			if len(a.Data) > 0 {
				key.KeyAccess = a.Data[0]
			}
		case 2: // keyIdentifier
			if len(a.Data) > 0 {
				key.KeyIdentifier = a.Data[0]
			}
		case 3: // keyVersionNumber
			if len(a.Data) > 0 {
				key.KeyVersionNumber = a.Data[0]
			}
		case 4: // keyComponents
			for inner.Unmarshal() {
				comp := decodeKeyComponent(asn1.Init(inner.Data))
				key.KeyComponents = append(key.KeyComponents, comp)
			}
		}
	}

	return key
}

func decodeKeyComponent(a *asn1.ASN1) KeyComponent {
	kc := KeyComponent{}

	for a.Unmarshal() {
		tagNum := getContextTag(a)
		switch tagNum {
		case 0: // keyType
			if len(a.Data) > 0 {
				kc.KeyType = a.Data[0]
			}
		case 1: // keyData
			kc.KeyData = copyBytes(a.Data)
		case 2: // macLength
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
		tagNum := getContextTag(a)
		inner := asn1.Init(a.Data)

		switch tagNum {
		case 0: // rfm-header
			rfm.Header = decodeElementHeader(inner)
		case 1: // instanceAID
			rfm.InstanceAID = copyBytes(a.Data)
		case 2: // tarList
			for inner.Unmarshal() {
				rfm.TARList = append(rfm.TARList, copyBytes(inner.Data))
			}
		case 3: // minimumSecurityLevel
			if len(a.Data) > 0 {
				rfm.MinimumSecurityLevel = a.Data[0]
			}
		case 4: // uiccAccessDomain
			if len(a.Data) > 0 {
				rfm.UICCAccessDomain = a.Data[0]
			}
		case 5: // uiccAdminAccessDomain
			if len(a.Data) > 0 {
				rfm.UICCAdminAccessDomain = a.Data[0]
			}
		case 6: // adfRFMAccess
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
// End [63]
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
