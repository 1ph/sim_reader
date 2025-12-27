package esim

// OID represents ASN.1 Object Identifier
type OID []int

// Profile represents a complete eSIM profile
type Profile struct {
	Elements []ProfileElement // all elements in order

	// Convenience references (populated during decoding)
	Header          *ProfileHeader
	MF              *MasterFile
	PukCodes        *PUKCodes
	PinCodes        []*PINCodes
	Telecom         *TelecomDF
	USIM            *USIMApplication
	OptUSIM         *OptionalUSIM
	ISIM            *ISIMApplication
	OptISIM         *OptionalISIM
	CSIM            *CSIMApplication
	OptCSIM         *OptionalCSIM
	GSMAccess       *GSMAccessDF
	DF5GS           *DF5GS
	DFSAIP          *DFSAIP
	AKAParams       []*AKAParameter
	CDMAParams      *CDMAParameter
	GFM             []*GenericFileManagement
	SecurityDomains []*SecurityDomain
	RFM             []*RFMConfig
	End             *EndElement
}

// ProfileElement represents one profile element (CHOICE)
type ProfileElement struct {
	Tag   int
	Value interface{}
}

// ============================================================================
// ProfileHeader [0]
// ============================================================================

// ProfileHeader represents profile header
type ProfileHeader struct {
	MajorVersion       int
	MinorVersion       int
	ProfileType        string
	ICCID              []byte
	MandatoryServices  *MandatoryServices
	MandatoryGFSTEList []OID
}

// MandatoryServices represents mandatory eUICC services
type MandatoryServices struct {
	USIM              bool
	ISIM              bool
	CSIM              bool
	USIMTestAlgorithm bool
	BERTLV            bool
	GetIdentity       bool
	ProfileAX25519    bool
	ProfileBP256      bool
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
	FileID                       uint16
	LCSI                         byte
	SecurityAttributesReferenced []byte
	ShortEFID                    byte
	EFFileSize                   int
	DFName                       []byte // AID for ADF
	PinStatusTemplateDO          []byte
	ProprietaryEFInfo            *ProprietaryEFInfo
	LinkPath                     []byte
}

// ProprietaryEFInfo represents proprietary file information
type ProprietaryEFInfo struct {
	SpecialFileInformation byte
	FillPattern            []byte
	RepeatPattern          []byte
}

// ElementaryFile represents elementary file with content
type ElementaryFile struct {
	Descriptor   *FileDescriptor
	FillContents []FillContent
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
	Header *ElementHeader
	Codes  []PUKCode
}

// PUKCode represents single PUK code
type PUKCode struct {
	KeyReference                byte
	PUKValue                    []byte
	MaxNumOfAttempsRetryNumLeft byte // packed: high nibble = max, low nibble = left
}

// PINCodes represents PIN codes block
type PINCodes struct {
	Header  *ElementHeader
	Configs []PINConfig
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
	EF_SUME       *ElementaryFile
	EF_PSISMSC    *ElementaryFile
	DFGraphics    *FileDescriptor
	EF_IMG        *ElementaryFile
	EF_LaunchSCWS *ElementaryFile
	DFPhonebook   *FileDescriptor
	EF_PBR        *ElementaryFile
	EF_PSC        *ElementaryFile
	EF_CC         *ElementaryFile
	EF_PUID       *ElementaryFile
	DFMMSS        *FileDescriptor
	EF_MLPL       *ElementaryFile
	EF_MSPL       *ElementaryFile
	// Additional fields as needed
	AdditionalEFs map[string]*ElementaryFile
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
	// Additional EFs as needed
	AdditionalEFs map[string]*ElementaryFile
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
	EF_DCK        *ElementaryFile
	EF_CNL        *ElementaryFile
	EF_SMSR       *ElementaryFile
	EF_BDN        *ElementaryFile
	EF_EXT5       *ElementaryFile
	EF_CCP2       *ElementaryFile
	EF_ACL        *ElementaryFile
	EF_CMI        *ElementaryFile
	EF_ICI        *ElementaryFile
	EF_OCI        *ElementaryFile
	EF_ICT        *ElementaryFile
	EF_OCT        *ElementaryFile
	EF_VGCS       *ElementaryFile
	EF_VGCSS      *ElementaryFile
	EF_VBS        *ElementaryFile
	EF_VBSS       *ElementaryFile
	EF_EMLPP      *ElementaryFile
	EF_AAEM       *ElementaryFile
	EF_HIDDENKEY  *ElementaryFile
	EF_PNN        *ElementaryFile
	EF_OPL        *ElementaryFile
	EF_MMSN       *ElementaryFile
	EF_EXT8       *ElementaryFile
	EF_MMSICP     *ElementaryFile
	EF_MMSUP      *ElementaryFile
	EF_MMSUCP     *ElementaryFile
	EF_NIA        *ElementaryFile
	EF_VGCSCA     *ElementaryFile
	EF_VBSCA      *ElementaryFile
	EF_EHPLMN     *ElementaryFile
	EF_EHPLMNPI   *ElementaryFile
	EF_LRPLMNSI   *ElementaryFile
	EF_NASCONFIG  *ElementaryFile
	EF_FDNURI     *ElementaryFile
	EF_SDNURI     *ElementaryFile
	AdditionalEFs map[string]*ElementaryFile
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
}

// OptionalISIM represents optional ISIM files
type OptionalISIM struct {
	Header        *ElementHeader
	TemplateID    OID
	EF_PCSCF      *ElementaryFile
	EF_GBABP      *ElementaryFile
	EF_GBANL      *ElementaryFile
	AdditionalEFs map[string]*ElementaryFile
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
	EF_HRPDCAP    *ElementaryFile
	EF_HRPDUPP    *ElementaryFile
	EF_CSSPR      *ElementaryFile
	EF_ATC        *ElementaryFile
	EF_EPRL       *ElementaryFile
	EF_BCSMSP     *ElementaryFile
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
	AdditionalEFs map[string]*ElementaryFile
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
	EF_ROUTING_INDICATOR *ElementaryFile
	AdditionalEFs        map[string]*ElementaryFile
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
}

// ============================================================================
// AKA Parameter [22]
// ============================================================================

// AKAParameter represents authentication parameters
type AKAParameter struct {
	Header      *ElementHeader
	AlgoConfig  *AlgoConfiguration
	SQNOptions  byte
	SQNDelta    []byte
	SQNAgeLimit []byte
	SQNInit     [][]byte // 32 entries of 6 bytes each
}

// AlgoConfiguration represents authentication algorithm configuration
type AlgoConfiguration struct {
	AlgorithmID       AlgorithmID
	AlgorithmOptions  byte
	Key               []byte // Ki, 16 or 32 bytes
	OPC               []byte // 16 or 32 bytes
	RotationConstants []byte // r1-r5
	XoringConstants   []byte // c1-c5
	NumberOfKeccak    int    // for TUAK
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
}

// FileManagementCMD represents single file management command
type FileManagementCMD struct {
	FilePath        []byte
	CreateFCP       *FileDescriptor
	FillFileContent []FillContent
}

// ============================================================================
// Security Domain [55]
// ============================================================================

// SecurityDomain represents GlobalPlatform security domain
type SecurityDomain struct {
	Header      *ElementHeader
	Instance    *SDInstance
	KeyList     []SDKey
	SDPersoData []byte
}

// SDInstance represents Security Domain instance
type SDInstance struct {
	ApplicationLoadPackageAID   []byte
	ClassAID                    []byte
	InstanceAID                 []byte
	ApplicationPrivileges       []byte
	LifeCycleState              byte
	ApplicationSpecificParamsC9 []byte
	ApplicationParameters       *ApplicationParameters
}

// ApplicationParameters represents application parameters
type ApplicationParameters struct {
	UIICToolkitApplicationSpecificParametersField []byte
}

// SDKey represents Security Domain key
type SDKey struct {
	KeyUsageQualifier byte
	KeyAccess         byte
	KeyIdentifier     byte
	KeyVersionNumber  byte
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
}

// ADFRFMAccess represents RFM access to ADF
type ADFRFMAccess struct {
	ADFAID               []byte
	ADFAccessDomain      byte
	ADFAdminAccessDomain byte
}

// ============================================================================
// End [63]
// ============================================================================

// EndElement represents profile end element
type EndElement struct {
	Header *ElementHeader
}
