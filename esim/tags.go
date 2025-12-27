package esim

// ProfileElement CHOICE tags according to SGP.22 / TS48
// Context-specific class, constructed form
const (
	TagProfileHeader         = 0  // [0] A0
	TagMF                    = 1  // [1] A1
	TagPukCodes              = 2  // [2] A2
	TagPinCodes              = 3  // [3] A3
	TagTelecom               = 4  // [4] A4
	TagUSIM                  = 8  // [8] A8
	TagOptUSIM               = 9  // [9] A9
	TagISIM                  = 10 // [10] AA
	TagOptISIM               = 11 // [11] AB
	TagCSIM                  = 12 // [12] AC
	TagOptCSIM               = 13 // [13] AD
	TagGSMAccess             = 20 // [20] BF 14
	TagAKAParameter          = 22 // [22] BF 16
	TagCDMAParameter         = 23 // [23] BF 17
	TagDF5GS                 = 24 // [24] BF 18
	TagDFSAIP                = 25 // [25] BF 19
	TagGenericFileManagement = 26 // [26] BF 1A
	TagSecurityDomain        = 55 // [55] BF 37
	TagRFM                   = 56 // [56] BF 38
	TagApplication           = 57 // [57] BF 39
	TagEnd                   = 63 // [63] BF 3F
)

// Universal ASN.1 tags
const (
	TagBoolean         = 0x01
	TagInteger         = 0x02
	TagBitString       = 0x03
	TagOctetString     = 0x04
	TagNull            = 0x05
	TagOID             = 0x06
	TagUTF8String      = 0x0C
	TagSequence        = 0x30
	TagSet             = 0x31
	TagPrintableString = 0x13
	TagIA5String       = 0x16
	TagUTCTime         = 0x17
	TagGeneralizedTime = 0x18
	TagVisibleString   = 0x1A
	TagGeneralString   = 0x1B
	TagUniversalString = 0x1C
	TagBMPString       = 0x1E
)

// Context-specific primitive tags (commonly used)
const (
	TagContext0Primitive  = 0x80 // [0] IMPLICIT
	TagContext1Primitive  = 0x81 // [1] IMPLICIT
	TagContext2Primitive  = 0x82 // [2] IMPLICIT
	TagContext3Primitive  = 0x83 // [3] IMPLICIT
	TagContext4Primitive  = 0x84 // [4] IMPLICIT
	TagContext5Primitive  = 0x85 // [5] IMPLICIT
	TagContext6Primitive  = 0x86 // [6] IMPLICIT
	TagContext7Primitive  = 0x87 // [7] IMPLICIT
	TagContext8Primitive  = 0x88 // [8] IMPLICIT
	TagContext9Primitive  = 0x89 // [9] IMPLICIT
	TagContext10Primitive = 0x8A // [10] IMPLICIT
)

// Context-specific constructed tags
const (
	TagContext0Constructed  = 0xA0 // [0] EXPLICIT
	TagContext1Constructed  = 0xA1 // [1] EXPLICIT
	TagContext2Constructed  = 0xA2 // [2] EXPLICIT
	TagContext3Constructed  = 0xA3 // [3] EXPLICIT
	TagContext4Constructed  = 0xA4 // [4] EXPLICIT
	TagContext5Constructed  = 0xA5 // [5] EXPLICIT
	TagContext6Constructed  = 0xA6 // [6] EXPLICIT
	TagContext7Constructed  = 0xA7 // [7] EXPLICIT
	TagContext8Constructed  = 0xA8 // [8] EXPLICIT
	TagContext9Constructed  = 0xA9 // [9] EXPLICIT
	TagContext10Constructed = 0xAA // [10] EXPLICIT
)

// FileDescriptor internal tags for file description
const (
	TagFileDescriptorByte          = 0x82
	TagFileID                      = 0x83
	TagDFName                      = 0x84
	TagProprietaryNotTLV           = 0x85
	TagSecurityAttributeReferenced = 0x8B
	TagSecurityAttributeExpanded   = 0xAB
	TagSecurityAttributeCompact    = 0x8C
	TagFCIExtension                = 0xA5
	TagLifeCycleStatus             = 0x8A
	TagShortEFID                   = 0x88
	TagTotalFileSize               = 0x81
	TagPinStatusTemplateDO         = 0xC6
)

// AlgorithmID constants for authentication algorithm type
const (
	AlgoIDMilenage          = 1
	AlgoIDTUAK              = 2
	AlgoIDUSIMTestAlgorithm = 3
)

// PUK/PIN key references
const (
	KeyRefPIN1       = 0x01
	KeyRefPIN2       = 0x81
	KeyRefPUK1       = 0x01
	KeyRefPUK2       = 0x81
	KeyRefADM1       = 0x0A
	KeyRefADM2       = 0x0B
	KeyRefSecondPIN1 = 0x0B
	KeyRefSecondPUK1 = 0x8B
)

// GetProfileElementName returns profile element name by tag
func GetProfileElementName(tag int) string {
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
		return "unknown"
	}
}
