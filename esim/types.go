package esim

// OID represents ASN.1 Object Identifier
type OID []int

// Profile represents a complete eSIM profile
type Profile struct {
	Elements []ProfileElement // all elements in order

	// Convenience references (populated during decoding)
	Header          *ProfileHeader
	MF              *MasterFile
	CD              *CDDF
	PukCodes        *PUKCodes
	PinCodes        []*PINCodes
	Telecom         *TelecomDF
	USIM            *USIMApplication
	OptUSIM         *OptionalUSIM
	ISIM            *ISIMApplication
	OptISIM         *OptionalISIM
	Phonebook       *PhonebookDF
	CSIM            *CSIMApplication
	OptCSIM         *OptionalCSIM
	EAP             *EAPDF
	GSMAccess       *GSMAccessDF
	DF5GS           *DF5GS
	DFSAIP          *DFSAIP
	DFSNPN          *DFSNPN
	DF5GPROSE       *DF5GPROSE
	IoT             *IoTPE
	OptIoT          *OptionalIoT
	AKAParams       []*AKAParameter
	CDMAParams      *CDMAParameter
	GFM             []*GenericFileManagement
	SecurityDomains []*SecurityDomain
	RFM             []*RFMConfig
	Applications    []*Application
	End             *EndElement
}

// ProfileElement represents one profile element (CHOICE)
type ProfileElement struct {
	Tag   int
	Value interface{}
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// ProfileHeader [0]
// ============================================================================

// ProfileHeader represents profile header
type ProfileHeader struct {
	MajorVersion           int
	MinorVersion           int
	ProfileType            string
	ICCID                  []byte
	POL                    []byte
	MandatoryServices      *MandatoryServices
	MandatoryGFSTEList     []OID
	ConnectivityParameters []byte
	MandatoryAIDs          []MandatoryAID
	IOTOptions             *IOTOptions
}

// IOTOptions represents IoT Minimal Profile options
type IOTOptions struct {
	PIX []byte
}

// MandatoryAID represents an entry in eUICC-Mandatory-AIDs
type MandatoryAID struct {
	AID     []byte
	Version []byte
}

// ControlReferenceTemplate represents Control Reference Template
type ControlReferenceTemplate struct {
	ApplicationProviderIdentifier []byte
}

// MandatoryServices represents mandatory eUICC services
type MandatoryServices struct {
	Contactless       bool // tag 0
	USIM              bool // tag 1
	ISIM              bool // tag 2
	CSIM              bool // tag 3
	Milenage          bool // tag 4
	TUAK128           bool // tag 5
	CAVE              bool // tag 6
	GBAUSIM           bool // tag 7
	GBAISIM           bool // tag 8
	MBMS              bool // tag 9
	EAP               bool // tag 10
	JavaCard          bool // tag 11
	Multos            bool // tag 12
	MultipleUSIM      bool // tag 13
	MultipleISIM      bool // tag 14
	MultipleCSIM      bool // tag 15
	TUAK256           bool // tag 16
	USIMTestAlgorithm bool // tag 17
	BERTLV            bool // tag 18
	DFLink            bool // tag 19
	CatTP             bool // tag 20
	GetIdentity       bool // tag 21
	ProfileAX25519    bool // tag 22
	ProfileBP256      bool // tag 23
	SuciCalculatorApi bool // tag 24
	DNSResolution     bool // tag 25
	SCP11ac           bool // tag 26
	SCP11cAuth        bool // tag 27
	S16Mode           bool // tag 28
	EAKA              bool // tag 29
}

// ============================================================================
// MasterFile [1]
// ============================================================================

// MasterFile represents root file system
type MasterFile struct {
	MFHeader   *ElementHeader
	TemplateID OID
	MF         *FileDescriptor
	EF_PL      *ElementaryFile
	EF_ICCID   *ElementaryFile
	EF_DIR     *ElementaryFile
	EF_ARR     *ElementaryFile
	EF_UMPC    *ElementaryFile
	EFList     []*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// CD [17]
// ============================================================================

// CDDF represents CD directory
type CDDF struct {
	Header       *ElementHeader
	TemplateID   OID
	DFCD         *FileDescriptor
	EF_LaunchPad *ElementaryFile
	EF_Icon      *ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// Common types
// ============================================================================

// ElementHeader represents profile element header
type ElementHeader struct {
	Mandated       bool
	Identification int
}

// FileDescriptor represents file/directory description
type FileDescriptor struct {
	FileDescriptor               []byte
	FileID                       []byte
	LCSI                         []byte
	SecurityAttributesReferenced []byte
	ShortEFID                    []byte
	EFFileSize                   []byte
	DFName                       []byte // AID for ADF
	PinStatusTemplateDO          []byte
	ProprietaryEFInfo            *ProprietaryEFInfo
	LinkPath                     []byte
	UnknownTag                   []byte // [PRIVATE 99]
}

// ProprietaryEFInfo represents proprietary file information
type ProprietaryEFInfo struct {
	SpecialFileInformation []byte
	FillPattern            []byte
	RepeatPattern          []byte
	MaximumFileSize        []byte
	FileDetails            []byte
}

// FileElementType represents the type of File CHOICE element
type FileElementType int

const (
	FileElementDoNotCreate FileElementType = iota // NULL - file shall not be created
	FileElementDescriptor                         // Fcp - file descriptor
	FileElementOffset                             // UInt16 - fill file offset
	FileElementContent                            // OCTET STRING - fill file content
)

// FileElement represents one element of File SEQUENCE OF CHOICE
// File ::= SEQUENCE OF CHOICE { doNotCreate NULL, fileDescriptor Fcp, fillFileOffset UInt16, fillFileContent OCTET STRING }
type FileElement struct {
	Type       FileElementType
	Descriptor *FileDescriptor // when Type == FileElementDescriptor
	Offset     int             // when Type == FileElementOffset
	Content    []byte          // when Type == FileElementContent
}

// File represents ASN.1 File type - SEQUENCE OF CHOICE
type File []FileElement

// ElementaryFile represents elementary file with content (simplified view)
// Internally uses File structure for full ASN.1 representation
type ElementaryFile struct {
	Descriptor   *FileDescriptor
	FillContents []FillContent
	// Raw preserves original File elements for exact round-trip encoding
	Raw File
}

// FillContent represents file content with optional offset
type FillContent struct {
	Offset  int
	Content []byte
}

// ============================================================================
// PUK/PIN Codes [2], [3]
// ============================================================================

// PUKCodes represents PUK codes block
type PUKCodes struct {
	Header   *ElementHeader
	FilePath []byte
	Codes    []PUKCode
}

// PUKCode represents single PUK code
type PUKCode struct {
	KeyReference                byte
	PUKValue                    []byte
	MaxNumOfAttempsRetryNumLeft byte // packed: high nibble = max, low nibble = left
}

// PINCodes represents PIN codes block
type PINCodes struct {
	Header   *ElementHeader
	FilePath []byte
	Configs  []PINConfig
}

// PINConfig represents single PIN configuration
type PINConfig struct {
	KeyReference                byte
	PINValue                    []byte
	UnblockingPINReference      byte
	PINAttributes               byte
	MaxNumOfAttempsRetryNumLeft byte // packed: high nibble = max, low nibble = left
}

// ============================================================================
// Telecom [4]
// ============================================================================

// TelecomDF represents telecom directory
type TelecomDF struct {
	Header        *ElementHeader
	TemplateID    OID
	DFTelecom     *FileDescriptor
	EF_ARR        *ElementaryFile
	EF_RMA        *ElementaryFile
	EF_SUME       *ElementaryFile
	EF_ICE_DN     *ElementaryFile
	EF_ICE_FF     *ElementaryFile
	EF_PSISMSC    *ElementaryFile
	DFGraphics    *FileDescriptor
	EF_IMG        *ElementaryFile
	EF_IIDF       *ElementaryFile
	EF_ICE_Graphics *ElementaryFile
	EF_LaunchSCWS *ElementaryFile
	EF_ICON       *ElementaryFile
	DFPhonebook   *FileDescriptor
	EF_PBR        *ElementaryFile
	EF_EXT1       *ElementaryFile
	EF_AAS        *ElementaryFile
	EF_GAS        *ElementaryFile
	EF_PSC        *ElementaryFile
	EF_CC         *ElementaryFile
	EF_PUID       *ElementaryFile
	EF_IAP        *ElementaryFile
	EF_ADN        *ElementaryFile
	EF_PBC        *ElementaryFile
	EF_ANR        *ElementaryFile
	EF_PURI       *ElementaryFile
	EF_EMAIL      *ElementaryFile
	EF_SNE        *ElementaryFile
	EF_UID        *ElementaryFile
	EF_GRP        *ElementaryFile
	EF_CCP1       *ElementaryFile
	DFMultimedia  *FileDescriptor
	EF_MML        *ElementaryFile
	EF_MMDF       *ElementaryFile
	DFMMSS        *FileDescriptor
	EF_MLPL       *ElementaryFile
	EF_MSPL       *ElementaryFile
	EF_MMSSMODE   *ElementaryFile
	EF_MMSSCONF   *ElementaryFile
	EF_MMSSID     *ElementaryFile
	DFMCS         *FileDescriptor
	EF_MST        *ElementaryFile
	EF_MCSConfig  *ElementaryFile
	DFV2X         *FileDescriptor
	EF_VST        *ElementaryFile
	EF_V2XConfig  *ElementaryFile
	EF_V2XPPC5    *ElementaryFile
	EF_V2XPUu     *ElementaryFile
	// UseNewMMSSTags: if true, use tags 36-40 (SAIP 2.3+), otherwise use tags 25-29
	UseNewMMSSTags bool
	// Additional fields as needed
	AdditionalEFs map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// Phonebook [23]
// ============================================================================

// PhonebookDF represents phonebook directory
type PhonebookDF struct {
	Header      *ElementHeader
	TemplateID  OID
	DFPhonebook *FileDescriptor
	EF_PBR      *ElementaryFile
	EF_EXT1     *ElementaryFile
	EF_AAS      *ElementaryFile
	EF_GAS      *ElementaryFile
	EF_PSC      *ElementaryFile
	EF_CC       *ElementaryFile
	EF_PUID     *ElementaryFile
	EF_IAP      *ElementaryFile
	EF_ADN      *ElementaryFile
	EF_PBC      *ElementaryFile
	EF_ANR      *ElementaryFile
	EF_PURI     *ElementaryFile
	EF_EMAIL    *ElementaryFile
	EF_SNE      *ElementaryFile
	EF_UID      *ElementaryFile
	EF_GRP      *ElementaryFile
	EF_CCP1     *ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// USIM [8]
// ============================================================================

// USIMApplication represents USIM application
type USIMApplication struct {
	Header       *ElementHeader
	TemplateID   OID
	ADFUSIM      *FileDescriptor
	EF_IMSI      *ElementaryFile
	EF_ARR       *ElementaryFile
	EF_Keys      *ElementaryFile
	EF_KeysPS    *ElementaryFile
	EF_HPPLMN    *ElementaryFile
	EF_UST       *ElementaryFile
	EF_FDN       *ElementaryFile
	EF_SMS       *ElementaryFile
	EF_SMSP      *ElementaryFile
	EF_SMSS      *ElementaryFile
	EF_SPN       *ElementaryFile
	EF_EST       *ElementaryFile
	EF_StartHFN  *ElementaryFile
	EF_Threshold *ElementaryFile
	EF_PSLOCI    *ElementaryFile
	EF_ACC       *ElementaryFile
	EF_FPLMN     *ElementaryFile
	EF_LOCI      *ElementaryFile
	EF_AD        *ElementaryFile
	EF_ECC       *ElementaryFile
	EF_NETPAR    *ElementaryFile
	EF_EPSLOCI   *ElementaryFile
	EF_EPSNSC    *ElementaryFile
	EF_WLAN      *ElementaryFile
	EF_DEB_PK    *ElementaryFile
	AdditionalEFs map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// OptionalUSIM represents optional USIM files
type OptionalUSIM struct {
	Header        *ElementHeader
	TemplateID    OID
	EF_LI         *ElementaryFile
	EF_ACMAX      *ElementaryFile
	EF_ACM        *ElementaryFile
	EF_GID1       *ElementaryFile
	EF_GID2       *ElementaryFile
	EF_MSISDN     *ElementaryFile
	EF_PUCT       *ElementaryFile
	EF_CBMI       *ElementaryFile
	EF_CBMID      *ElementaryFile
	EF_SDN        *ElementaryFile
	EF_EXT2       *ElementaryFile
	EF_EXT3       *ElementaryFile
	EF_CBMIR      *ElementaryFile
	EF_PLMNWACT   *ElementaryFile
	EF_OPLMNWACT  *ElementaryFile
	EF_HPLMNWACT  *ElementaryFile
	EF_DCK         *ElementaryFile
	EF_CNL         *ElementaryFile
	EF_SMSR        *ElementaryFile
	EF_BDN         *ElementaryFile
	EF_EXT5        *ElementaryFile
	EF_CCP2        *ElementaryFile
	EF_EXT4        *ElementaryFile
	EF_ACL         *ElementaryFile
	EF_CMI         *ElementaryFile
	EF_ICI         *ElementaryFile
	EF_OCI         *ElementaryFile
	EF_ICT         *ElementaryFile
	EF_OCT         *ElementaryFile
	EF_VGCS        *ElementaryFile
	EF_VGCSS       *ElementaryFile
	EF_VBS         *ElementaryFile
	EF_VBSS        *ElementaryFile
	EF_EMLPP       *ElementaryFile
	EF_AAEM        *ElementaryFile
	EF_HIDDENKEY   *ElementaryFile
	EF_PNN         *ElementaryFile
	EF_OPL         *ElementaryFile
	EF_MBDN        *ElementaryFile
	EF_EXT6        *ElementaryFile
	EF_MBI         *ElementaryFile
	EF_MWIS        *ElementaryFile
	EF_CFIS        *ElementaryFile
	EF_EXT7        *ElementaryFile
	EF_SPDI        *ElementaryFile
	EF_MMSN        *ElementaryFile
	EF_EXT8        *ElementaryFile
	EF_MMSICP      *ElementaryFile
	EF_MMSUP       *ElementaryFile
	EF_MMSUCP      *ElementaryFile
	EF_NIA         *ElementaryFile
	EF_VGCSCA      *ElementaryFile
	EF_VBSCA       *ElementaryFile
	EF_GBABP       *ElementaryFile
	EF_MSK         *ElementaryFile
	EF_MUK         *ElementaryFile
	EF_EHPLMN      *ElementaryFile
	EF_GBANL       *ElementaryFile
	EF_EHPLMNPI    *ElementaryFile
	EF_LRPLMNSI    *ElementaryFile
	EF_NAFKCA      *ElementaryFile
	EF_SPNI        *ElementaryFile
	EF_PNNI        *ElementaryFile
	EF_NCP_IP      *ElementaryFile
	EF_UFC         *ElementaryFile
	EF_NASCONFIG   *ElementaryFile
	EF_UICCIARI    *ElementaryFile
	EF_PWS         *ElementaryFile
	EF_FDNURI      *ElementaryFile
	EF_BDNURI      *ElementaryFile
	EF_SDNURI      *ElementaryFile
	EF_IAL         *ElementaryFile
	EF_IPS         *ElementaryFile
	EF_IPD         *ElementaryFile
	EF_EPDGID      *ElementaryFile
	EF_EPDGSELECTION   *ElementaryFile
	EF_EPDGIDEM        *ElementaryFile
	EF_EPDGSELECTIONEM *ElementaryFile
	EF_FROMPREFERRED   *ElementaryFile
	EF_IMSCONFIGDATA   *ElementaryFile
	EF_3GPPPSDATAOFF   *ElementaryFile
	EF_3GPPPSDATAOFFSERVICELIST *ElementaryFile
	EF_XCAPCONFIGDATA  *ElementaryFile
	EF_EARFCNLIST      *ElementaryFile
	EF_MUDMIDCONFIGDATA *ElementaryFile
	EF_EAKA            *ElementaryFile
	// ... additional optional files can be added as needed
	AdditionalEFs map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// ISIM [10]
// ============================================================================

// ISIMApplication represents ISIM application
type ISIMApplication struct {
	Header        *ElementHeader
	TemplateID    OID
	ADFISIM       *FileDescriptor
	EF_IMPI       *ElementaryFile
	EF_IMPU       *ElementaryFile
	EF_DOMAIN     *ElementaryFile
	EF_IST        *ElementaryFile
	EF_AD         *ElementaryFile
	EF_ARR        *ElementaryFile
	AdditionalEFs map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// OptionalISIM represents optional ISIM files
type OptionalISIM struct {
	Header              *ElementHeader
	TemplateID          OID
	EF_PCSCF            *ElementaryFile
	EF_SMS              *ElementaryFile
	EF_SMSP             *ElementaryFile
	EF_SMSS             *ElementaryFile
	EF_SMSR             *ElementaryFile
	EF_GBABP            *ElementaryFile
	EF_GBANL            *ElementaryFile
	EF_NAFKCA           *ElementaryFile
	EF_UICCIARI         *ElementaryFile
	EF_FROMPREFERRED    *ElementaryFile
	EF_IMSCONFIGDATA    *ElementaryFile
	EF_XCAPCONFIGDATA    *ElementaryFile
	EF_WEBRTCURI        *ElementaryFile
	EF_MUDMIDCONFIGDATA  *ElementaryFile
	EF_NASCONFIG        *ElementaryFile
	EF_EAKA             *ElementaryFile
	// UseNewGBATags: if true, use tags 7-8 (SAIP 2.3+), otherwise use tags 3-4
	UseNewGBATags bool
	AdditionalEFs map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// CSIM [12]
// ============================================================================

// CSIMApplication represents CSIM application
type CSIMApplication struct {
	Header          *ElementHeader
	TemplateID      OID
	ADFCSIM         *FileDescriptor
	EF_ARR          *ElementaryFile
	EF_CallCount    *ElementaryFile
	EF_IMSI_M       *ElementaryFile
	EF_IMSI_T       *ElementaryFile
	EF_TMSI         *ElementaryFile
	EF_AH           *ElementaryFile
	EF_AOP          *ElementaryFile
	EF_ALOC         *ElementaryFile
	EF_CDMAHOME     *ElementaryFile
	EF_ZNREGI       *ElementaryFile
	EF_SNREGI       *ElementaryFile
	EF_DISTREGI     *ElementaryFile
	EF_ACCOLC       *ElementaryFile
	EF_TERM         *ElementaryFile
	EF_ACP          *ElementaryFile
	EF_PRL          *ElementaryFile
	EF_RUIMID       *ElementaryFile
	EF_CSIM_ST      *ElementaryFile
	EF_SPC          *ElementaryFile
	EF_OTAPASPC     *ElementaryFile
	EF_NAMLOCK      *ElementaryFile
	EF_OTA          *ElementaryFile
	EF_SP           *ElementaryFile
	EF_ESN_MEID_ME  *ElementaryFile
	EF_LI           *ElementaryFile
	EF_USGIND       *ElementaryFile
	EF_AD           *ElementaryFile
	EF_MAX_PRL      *ElementaryFile
	EF_SPCS         *ElementaryFile
	EF_MECRP        *ElementaryFile
	EF_HOME_TAG     *ElementaryFile
	EF_GROUP_TAG    *ElementaryFile
	EF_SPECIFIC_TAG *ElementaryFile
	EF_CALL_PROMPT  *ElementaryFile
	AdditionalEFs   map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// OptionalCSIM represents optional CSIM files
type OptionalCSIM struct {
	Header        *ElementHeader
	TemplateID    OID
	EF_SSCI       *ElementaryFile
	EF_FDN        *ElementaryFile
	EF_SMS        *ElementaryFile
	EF_SMSP       *ElementaryFile
	EF_SMSS       *ElementaryFile
	EF_SSFC       *ElementaryFile
	EF_SPN        *ElementaryFile
	EF_MDN        *ElementaryFile
	EF_ECC        *ElementaryFile
	EF_ME3GPDOPC  *ElementaryFile
	EF_3GPDOPM    *ElementaryFile
	EF_SIPCAP     *ElementaryFile
	EF_MIPCAP     *ElementaryFile
	EF_SIPUPP     *ElementaryFile
	EF_MIPUPP     *ElementaryFile
	EF_SIPSP      *ElementaryFile
	EF_MIPSP      *ElementaryFile
	EF_SIPPAPSS   *ElementaryFile
	EF_PUZL       *ElementaryFile
	EF_MAX_PUZL   *ElementaryFile
	EF_HRPDCAP    *ElementaryFile
	EF_HRPDUPP    *ElementaryFile
	EF_CSSPR      *ElementaryFile
	EF_ATC        *ElementaryFile
	EF_EPRL       *ElementaryFile
	EF_BCSMSP     *ElementaryFile
	EF_BCSMSConfig *ElementaryFile
	EF_BCSMSPref   *ElementaryFile
	EF_BCSMSTable  *ElementaryFile
	EF_BAKPara     *ElementaryFile
	EF_UPBAKPara   *ElementaryFile
	EF_AuthCapability *ElementaryFile
	EF_DCK         *ElementaryFile
	EF_CDMACNL     *ElementaryFile
	EF_LCSVer      *ElementaryFile
	EF_LCSCP       *ElementaryFile
	EF_AppLabels   *ElementaryFile
	EF_RC          *ElementaryFile
	EF_SMSCap      *ElementaryFile
	EF_MIPFlags    *ElementaryFile
	EF_3GPDUppeExt *ElementaryFile
	EF_IPv6Cap     *ElementaryFile
	EF_TCPConfig   *ElementaryFile
	EF_DGC         *ElementaryFile
	EF_WAPBrowserCP *ElementaryFile
	EF_WAPBrowserBM *ElementaryFile
	EF_MMSConfig   *ElementaryFile
	EF_JDL         *ElementaryFile
	EF_MMSN       *ElementaryFile
	EF_EXT8       *ElementaryFile
	EF_MMSICP     *ElementaryFile
	EF_MMSUP      *ElementaryFile
	EF_MMSUCP     *ElementaryFile
	EF_3GCIK      *ElementaryFile
	EF_GID1       *ElementaryFile
	EF_GID2       *ElementaryFile
	EF_SF_EUIMID  *ElementaryFile
	EF_EST        *ElementaryFile
	EF_HIDDEN_KEY *ElementaryFile
	EF_SDN        *ElementaryFile
	EF_EXT2       *ElementaryFile
	EF_EXT3       *ElementaryFile
	EF_ICI        *ElementaryFile
	EF_OCI        *ElementaryFile
	EF_EXT5       *ElementaryFile
	EF_CCP2       *ElementaryFile
	EF_MODEL      *ElementaryFile
	EF_MEIDME     *ElementaryFile
	AdditionalEFs map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// EAP [27]
// ============================================================================

// EAPDF represents EAP directory
type EAPDF struct {
	Header      *ElementHeader
	TemplateID  OID
	DFEAP       *FileDescriptor
	EF_EAPKeys  *ElementaryFile
	EF_EAPStatus *ElementaryFile
	EF_PUID     *ElementaryFile
	EF_PS       *ElementaryFile
	EF_CURID    *ElementaryFile
	EF_REID     *ElementaryFile
	EF_Realm    *ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// GSM Access [20]
// ============================================================================

// GSMAccessDF represents GSM Access directory
type GSMAccessDF struct {
	Header        *ElementHeader
	TemplateID    OID
	DFGSMAccess   *FileDescriptor
	EF_Kc         *ElementaryFile
	EF_KcGPRS     *ElementaryFile
	EF_CPBCCH     *ElementaryFile
	EF_INVSCAN    *ElementaryFile
	AdditionalEFs map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// DF-5GS [24]
// ============================================================================

// DF5GS represents 5G directory
type DF5GS struct {
	Header               *ElementHeader
	TemplateID           OID
	DFDF5GS              *FileDescriptor
	EF_5GS3GPPLOCI       *ElementaryFile
	EF_5GSN3GPPLOCI      *ElementaryFile
	EF_5GS3GPPNSC        *ElementaryFile
	EF_5GSN3GPPNSC       *ElementaryFile
	EF_5GAUTHKEYS        *ElementaryFile
	EF_UAC_AIC           *ElementaryFile
	EF_SUCI_CALC_INFO    *ElementaryFile
	EF_OPL5G             *ElementaryFile
	EF_SUPI_NAI          *ElementaryFile
	EF_ROUTING_INDICATOR *ElementaryFile
	EF_URSP              *ElementaryFile
	EF_TN3GPPSNN         *ElementaryFile
	EF_CAG               *ElementaryFile
	EF_SOR_CMCI          *ElementaryFile
	EF_DRI               *ElementaryFile
	EF_5GSEDRX           *ElementaryFile
	EF_5GNSWO_CONF       *ElementaryFile
	EF_MCHPPLMN          *ElementaryFile
	EF_KAUSF_DERIVATION  *ElementaryFile
	AdditionalEFs        map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// DF-SAIP [25]
// ============================================================================

// DFSAIP represents SAIP directory
type DFSAIP struct {
	Header                 *ElementHeader
	TemplateID             OID
	DFDFSAIP               *FileDescriptor
	EF_SUCI_CALC_INFO_USIM *ElementaryFile
	AdditionalEFs          map[string]*ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// DF-SNPN [30]
// ============================================================================

// DFSNPN represents SNPN directory
type DFSNPN struct {
	Header      *ElementHeader
	TemplateID  OID
	DFDFSNPN    *FileDescriptor
	EF_PWS_SNPN *ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// DF-5GPROSE [31]
// ============================================================================

// DF5GPROSE represents 5G ProSe directory
type DF5GPROSE struct {
	Header          *ElementHeader
	TemplateID      OID
	DFDF5GProSe    *FileDescriptor
	EF_5G_ProSe_ST  *ElementaryFile
	EF_5G_ProSe_DD  *ElementaryFile
	EF_5G_ProSe_DC  *ElementaryFile
	EF_5G_ProSe_U2NRU *ElementaryFile
	EF_5G_ProSe_RU  *ElementaryFile
	EF_5G_ProSe_UIR *ElementaryFile
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// IoT [32]
// ============================================================================

// IoTPE represents IoT profile element
type IoTPE struct {
	Header       *ElementHeader
	TemplateID   OID
	MF           *File
	EF_PL        *File
	EF_ICCID     *File
	EF_DIR       *File
	EF_ARR       *File
	EF_UMPC      *File
	ADF_USIM     *File
	EF_IMSI      *File
	EF_ARR_USIM  *File
	EF_Keys      *File
	EF_KeysPS    *File
	EF_HPPLMN    *File
	EF_UST       *File
	EF_StartHFN  *File
	EF_Threshold *File
	EF_PSLOCI    *File
	EF_ACC       *File
	EF_FPLMN     *File
	EF_LOCI      *File
	EF_AD        *File
	EF_ECC       *File
	EF_NETPAR    *File
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// OptionalIoT represents optional IoT profile element
type OptionalIoT struct {
	Header               *ElementHeader
	TemplateID           OID
	EF_FDN               *File
	EF_SMS               *File
	EF_SMSP              *File
	EF_SMSS              *File
	EF_SPN               *File
	EF_EST               *File
	EF_OPLMNWACT         *File
	EF_HPLMNWACT         *File
	EF_EHPLMN            *File
	EF_EPSLOCI           *File
	EF_EPSNSC            *File
	DF_DF_5GS            *File
	EF_5GS3GPPLOCI       *File
	EF_5GSN3GPPLOCI      *File
	EF_5GS3GPPNSC        *File
	EF_5GSN3GPPNSC       *File
	EF_5GAUTHKEYS        *File
	EF_UAC_AIC           *File
	EF_SUCI_CALC_INFO    *File
	EF_OPL5G             *File
	EF_SUPI_NAI          *File
	EF_ROUTING_INDICATOR *File
	EF_URSP              *File
	EF_TN3GPPSNN         *File
	DF_DF_SAIP           *File
	EF_SUCI_CALC_INFO_USIM *File
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ============================================================================
// AKA Parameter [22]
// ============================================================================

// AKAParameter represents authentication parameters
type AKAParameter struct {
	Header           *ElementHeader
	AlgoConfig       *AlgoConfiguration
	SQNOptions       byte
	SQNDelta         []byte
	SQNAgeLimit      []byte
	SQNInit          [][]byte // 32 entries of 6 bytes each
	MappingParameter *MappingParameter
}

// AlgoConfiguration represents authentication algorithm configuration
type AlgoConfiguration struct {
	AlgorithmID       AlgorithmID
	AlgorithmOptions  byte
	Key               []byte // Ki, 16 or 32 bytes
	OPC               []byte // 16 or 32 bytes
	RotationConstants []byte // r1-r5
	XoringConstants   []byte // c1-c5
	AuthCounterMax    []byte // [3] OPTIONAL
	NumberOfKeccak    *int   // for TUAK
	MappingParameter  *MappingParameter
}

// MappingParameter represents AKA mapping parameter
type MappingParameter struct {
	MappingOptions byte
	MappingSource  []byte // ApplicationIdentifier
}

// AlgorithmID represents authentication algorithm type
type AlgorithmID int

const (
	AlgoMilenage          AlgorithmID = 1
	AlgoTUAK              AlgorithmID = 2
	AlgoUSIMTestAlgorithm AlgorithmID = 3
)

// ============================================================================
// CDMA Parameter [23]
// ============================================================================

// CDMAParameter represents CDMA authentication parameters
type CDMAParameter struct {
	Header                       *ElementHeader
	AuthenticationKey            []byte
	SSD                          []byte
	HRPDAccessAuthenticationData []byte
	SimpleIPAuthenticationData   []byte
	MobileIPAuthenticationData   []byte
}

// ============================================================================
// Generic File Management [26]
// ============================================================================

// GenericFileManagement represents file management
type GenericFileManagement struct {
	Header             *ElementHeader
	FileManagementCMDs []FileManagementCMD
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// FileManagementCMD represents single file management command
// FileManagementItem represents a single command in FileManagementCMD
// FileManagementCMD ::= SEQUENCE OF CHOICE { filePath, createFCP, fillFileContent, fillFileOffset }
type FileManagementItem struct {
	ItemType        int // 0=filePath, 1=createFCP, 2=fillFileContent, 3=fillFileOffset
	FilePath        []byte
	CreateFCP       *FileDescriptor
	FillFileContent []byte
	FillFileOffset  int
}

// FileManagementCMD represents a sequence of file management operations
type FileManagementCMD []FileManagementItem

// ============================================================================
// Security Domain [55]
// ============================================================================

// SecurityDomain represents GlobalPlatform security domain
type SecurityDomain struct {
	Header          *ElementHeader
	Instance        *ApplicationInstance
	KeyList         []SDKey
	SDPersoData     [][]byte
	OpenPersoData   *OpenPersoData
	CatTpParameters *CatTpParameters
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// OpenPersoData represents GlobalPlatform Open personalization data
type OpenPersoData struct {
	RestrictParameter             []byte // [PRIVATE 25]
	ContactlessProtocolParameters []byte
}

// CatTpParameters represents CAT_TP parameters
type CatTpParameters struct {
	CatTpMaxSduSize int
	CatTpMaxPduSize int
}

// UICCApplicationParameters represents application parameters
type UICCApplicationParameters struct {
	UiccToolkitApplicationSpecificParametersField []byte
	UiccAccessApplicationSpecificParametersField  []byte
	UiccAdministrativeAccessApplicationSpecificParametersField []byte
}

// SDKey represents Security Domain key
type SDKey struct {
	KeyUsageQualifier byte
	KeyAccess         byte
	KeyIdentifier     byte
	KeyVersionNumber  byte
	KeyCounterValue   []byte
	KeyComponents     []KeyComponent
}

// KeyComponent represents key component
type KeyComponent struct {
	KeyType   byte
	KeyData   []byte
	MACLength int
}

// ============================================================================
// RFM [56]
// ============================================================================

// RFMConfig represents Remote File Management configuration
type RFMConfig struct {
	Header                *ElementHeader
	InstanceAID           []byte
	TARList               [][]byte
	MinimumSecurityLevel  byte
	UICCAccessDomain      byte
	UICCAdminAccessDomain byte
	ADFRFMAccess          *ADFRFMAccess
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ADFRFMAccess represents RFM access to ADF
type ADFRFMAccess struct {
	ADFAID               []byte
	ADFAccessDomain      byte
	ADFAdminAccessDomain byte
}

// ============================================================================
// Application [8] - PE-Application for Java Card applets
// ============================================================================

// Application represents PE-Application (Tag 8) - Java Card applet
// This is used for loading CAP files and installing applet instances in eSIM profiles
type Application struct {
	Header       *ElementHeader
	LoadBlock    *ApplicationLoadPackage  // CAP file data (optional if only instances)
	InstanceList []*ApplicationInstance   // Applet instances
	// RawBytes preserves original encoding for lossless round-trip
	RawBytes []byte
}

// ApplicationLoadPackage represents the load block containing CAP file
// ASN.1: ApplicationLoadPackage ::= SEQUENCE { ... }
type ApplicationLoadPackage struct {
	LoadPackageAID         []byte // [APPLICATION 15] - Package AID
	SecurityDomainAID      []byte // [APPLICATION 15] OPTIONAL - Target SD AID
	NonVolatileCodeLimitC6 []byte // [PRIVATE 6] OPTIONAL - NV code limit
	VolatileDataLimitC7    []byte // [PRIVATE 7] OPTIONAL - Volatile data limit
	NonVolatileDataLimitC8 []byte // [PRIVATE 8] OPTIONAL - NV data limit
	HashValue              []byte // [PRIVATE 1] OPTIONAL - DAP hash
	LoadBlockObject        []byte // [PRIVATE 4] - CAP file content (IJC format)
}

// ApplicationInstance represents one applet instance configuration
// ASN.1: ApplicationInstance ::= SEQUENCE { ... }
type ApplicationInstance struct {
	ApplicationLoadPackageAID    []byte // [APPLICATION 15] - Package AID reference
	ClassAID                     []byte // [APPLICATION 15] - Applet class AID
	InstanceAID                  []byte // [APPLICATION 15] - Instance AID
	ExtraditeSecurityDomainAID   []byte // [APPLICATION 15] OPTIONAL - Extradition SD
	ApplicationPrivileges        []byte // [2] - Privileges byte(s)
	LifeCycleState               byte   // [3] - GP lifecycle state (default 0x07)
	ApplicationSpecificParamsC9  []byte // [PRIVATE 9] - C9 install params
	SystemSpecificParams         *ApplicationSystemParameters // [PRIVATE 15] OPTIONAL - System params
	ApplicationParameters        *UICCApplicationParameters // [PRIVATE 10] OPTIONAL - UICC app params
	ProcessData                  [][]byte // Personalization APDU commands (executed after install)
	ControlReferenceTemplate     *ControlReferenceTemplate // [16] OPTIONAL - CRT for SCP
}

// ApplicationSystemParameters represents GP system specific parameters
type ApplicationSystemParameters struct {
	VolatileMemoryQuotaC7       []byte // [PRIVATE 7]
	NonVolatileMemoryQuotaC8    []byte // [PRIVATE 8]
	GlobalServiceParameters     []byte // [PRIVATE 11]
	ImplicitSelectionParameter   []byte // [PRIVATE 15]
	VolatileReservedMemory      []byte // [PRIVATE 23]
	NonVolatileReservedMemory   []byte // [PRIVATE 24]
	TS102226SIMFileAccessToolkitParameter []byte // [PRIVATE 10]
	TS102226AdditionalContactlessParameters []byte // [0]
	ContactlessProtocolParameters []byte // [PRIVATE 25]
	UserInteractionContactlessParameters []byte // [PRIVATE 26]
	CumulativeGrantedVolatileMemory    []byte // [2]
	CumulativeGrantedNonVolatileMemory []byte // [3]
}

// ============================================================================
// End [10]
// ============================================================================

// EndElement represents profile end element
type EndElement struct {
	Header *ElementHeader
}
