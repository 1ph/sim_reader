package esim

// ProfileElement tags according to PE_Definitions ASN.1 with AUTOMATIC TAGS
// Tags are assigned sequentially in the order they appear in the CHOICE
const (
	// First group: non-file-system related PEs
	TagProfileHeader         = 0  // header ProfileHeader
	TagGenericFileManagement = 1  // genericFileManagement PE-GenericFileManagement
	TagPinCodes              = 2  // pinCodes PE-PINCodes
	TagPukCodes              = 3  // pukCodes PE-PUKCodes
	TagAKAParameter          = 4  // akaParameter PE-AKAParameter
	TagCDMAParameter         = 5  // cdmaParameter PE-CDMAParameter
	TagSecurityDomain        = 6  // securityDomain PE-SecurityDomain
	TagRFM                   = 7  // rfm PE-RFM
	TagApplication           = 8  // application PE-Application
	TagNonStandard           = 9  // nonStandard PE-NonStandard
	TagEnd                   = 10 // end PE-End
	TagRFU1                  = 11 // rfu1 PE-Dummy
	TagRFU2                  = 12 // rfu2 PE-Dummy
	TagRFU3                  = 13 // rfu3 PE-Dummy
	TagRFU4                  = 14 // rfu4 PE-Dummy
	TagRFU5                  = 15 // rfu5 PE-Dummy

	// Second group: file system related PEs using templates
	TagMF        = 16 // mf PE-MF
	TagCD        = 17 // cd PE-CD
	TagTelecom   = 18 // telecom PE-TELECOM
	TagUSIM      = 19 // usim PE-USIM
	TagOptUSIM   = 20 // opt-usim PE-OPT-USIM
	TagISIM      = 21 // isim PE-ISIM
	TagOptISIM   = 22 // opt-isim PE-OPT-ISIM
	TagPhonebook = 23 // phonebook PE-PHONEBOOK
	TagGSMAccess = 24 // gsm-access PE-GSM-ACCESS
	TagCSIM      = 25 // csim PE-CSIM
	TagOptCSIM   = 26 // opt-csim PE-OPT-CSIM
	TagEAP       = 27 // eap PE-EAP
	TagDF5GS     = 28 // df-5gs PE-DF-5GS
	TagDFSAIP    = 29 // df-saip PE-DF-SAIP
	TagDFSNPN    = 30 // df-snpn PE-DF-SNPN
	TagDF5GPROSE = 31 // df-5gprose PE-DF-5GPROSE
	TagIoT       = 32 // iot PE-IoT
	TagOptIoT    = 33 // opt-iot PE-OPT-IoT
)

// GetProfileElementName returns human-readable name for profile element tag
func GetProfileElementName(tag int) string {
	switch tag {
	case TagProfileHeader:
		return "header"
	case TagGenericFileManagement:
		return "genericFileManagement"
	case TagPinCodes:
		return "pinCodes"
	case TagPukCodes:
		return "pukCodes"
	case TagAKAParameter:
		return "akaParameter"
	case TagCDMAParameter:
		return "cdmaParameter"
	case TagSecurityDomain:
		return "securityDomain"
	case TagRFM:
		return "rfm"
	case TagApplication:
		return "application"
	case TagNonStandard:
		return "nonStandard"
	case TagEnd:
		return "end"
	case TagRFU1, TagRFU2, TagRFU3, TagRFU4, TagRFU5:
		return "rfu"
	case TagMF:
		return "mf"
	case TagCD:
		return "cd"
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
	default:
		return "unknown"
	}
}
