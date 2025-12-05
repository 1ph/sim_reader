// Package sim provides SIM/USIM/ISIM file definitions and reading functionality
package sim

import (
	"fmt"
	"sim_reader/card"
)

// FileType represents the type of EF file
type FileType int

const (
	FileTypeTransparent FileType = iota // Binary file
	FileTypeLinearFixed                 // Record-based file
	FileTypeCyclic                      // Cyclic record file
)

// Application identifiers (AIDs)
var (
	// AID for USIM application (3GPP TS 31.102)
	AID_USIM = []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}
	// AID for ISIM application (3GPP TS 31.103)
	AID_ISIM = []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}

	// Detected AIDs from EF_DIR (set by AnalyzeCard)
	DetectedUSIM_AID []byte
	DetectedISIM_AID []byte

	// Detected File ID paths from EF_DIR (for cards that don't support AID selection)
	DetectedUSIM_Path []byte // e.g., []byte{0x7F, 0xF0}
	DetectedISIM_Path []byte // e.g., []byte{0x7F, 0xF2}

	// Card type flags (set by AnalyzeCard)
	UseGSMCommands bool // Card requires GSM class commands (CLA=A0)

	// Stored ADM keys for re-authentication after SELECT AID
	StoredADMKey  []byte // ADM1 (0x0A) - ADM_A
	StoredADMKey2 []byte // ADM2 (0x0B) - ADM_B
	StoredADMKey3 []byte // ADM3 (0x0C) - ADM_C
	StoredADMKey4 []byte // ADM4 (0x0D) - ADM_D
)

// SetADMKey stores the ADM1 key for re-authentication after SELECT AID
func SetADMKey(key []byte) {
	StoredADMKey = make([]byte, len(key))
	copy(StoredADMKey, key)
}

// SetADMKey2 stores the ADM2 key for re-authentication after SELECT AID
func SetADMKey2(key []byte) {
	StoredADMKey2 = make([]byte, len(key))
	copy(StoredADMKey2, key)
}

// SetADMKey3 stores the ADM3 key for re-authentication after SELECT AID
func SetADMKey3(key []byte) {
	StoredADMKey3 = make([]byte, len(key))
	copy(StoredADMKey3, key)
}

// SetADMKey4 stores the ADM4 key for re-authentication after SELECT AID
func SetADMKey4(key []byte) {
	StoredADMKey4 = make([]byte, len(key))
	copy(StoredADMKey4, key)
}

// ClearADMKey clears all stored ADM keys
func ClearADMKey() {
	StoredADMKey = nil
	StoredADMKey2 = nil
	StoredADMKey3 = nil
	StoredADMKey4 = nil
}

// SelectUSIMWithAuth selects USIM application and re-authenticates with all ADM keys
// Returns the response from SELECT for FCP parsing if needed
func SelectUSIMWithAuth(reader *card.Reader) (*card.APDUResponse, error) {
	resp, err := reader.Select(GetUSIMAID())
	if err != nil {
		return nil, fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return nil, fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Re-authenticate with all available ADM keys
	// Different files may require different ADM levels
	if len(StoredADMKey) > 0 {
		reader.VerifyADM1(StoredADMKey) // Ignore errors - some keys may not be needed
	}
	if len(StoredADMKey2) > 0 {
		reader.VerifyADM2(StoredADMKey2)
	}
	if len(StoredADMKey3) > 0 {
		reader.VerifyADM3(StoredADMKey3)
	}
	if len(StoredADMKey4) > 0 {
		reader.VerifyADM4(StoredADMKey4)
	}

	return resp, nil
}

// SelectISIMWithAuth selects ISIM application and re-authenticates with all ADM keys
// Returns the response from SELECT for FCP parsing if needed
func SelectISIMWithAuth(reader *card.Reader) (*card.APDUResponse, error) {
	resp, err := reader.Select(GetISIMAID())
	if err != nil {
		return nil, fmt.Errorf("failed to select ISIM: %w", err)
	}
	if !resp.IsOK() {
		return nil, fmt.Errorf("ISIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Re-authenticate with all available ADM keys
	// Different files may require different ADM levels
	if len(StoredADMKey) > 0 {
		reader.VerifyADM1(StoredADMKey)
	}
	if len(StoredADMKey2) > 0 {
		reader.VerifyADM2(StoredADMKey2)
	}
	if len(StoredADMKey3) > 0 {
		reader.VerifyADM3(StoredADMKey3)
	}
	if len(StoredADMKey4) > 0 {
		reader.VerifyADM4(StoredADMKey4)
	}

	return resp, nil
}

// GetUSIMAID returns the best AID for USIM (detected or standard)
func GetUSIMAID() []byte {
	if len(DetectedUSIM_AID) > 0 {
		return DetectedUSIM_AID
	}
	return AID_USIM
}

// GetISIMAID returns the best AID for ISIM (detected or standard)
func GetISIMAID() []byte {
	if len(DetectedISIM_AID) > 0 {
		return DetectedISIM_AID
	}
	return AID_ISIM
}

// GetUSIMPath returns the File ID path for USIM (for cards that don't support AID selection)
func GetUSIMPath() []byte {
	return DetectedUSIM_Path
}

// GetISIMPath returns the File ID path for ISIM (for cards that don't support AID selection)
func GetISIMPath() []byte {
	return DetectedISIM_Path
}

// HasUSIMPath returns true if a File ID path is available for USIM
func HasUSIMPath() bool {
	return len(DetectedUSIM_Path) >= 2
}

// HasISIMPath returns true if a File ID path is available for ISIM
func HasISIMPath() bool {
	return len(DetectedISIM_Path) >= 2
}

// EFDefinition defines an Elementary File on the SIM
type EFDefinition struct {
	ID          uint16   // File ID (e.g., 0x6F07 for IMSI)
	Name        string   // Short name (e.g., "EF_IMSI")
	Description string   // Human-readable description
	Type        FileType // File type
	RecordSize  int      // Record size for linear/cyclic files (0 for transparent)
	Parent      string   // Parent directory (MF, DF_GSM, ADF_USIM, ADF_ISIM)
}

// Master File (MF) files
var MF_Files = map[uint16]EFDefinition{
	0x2FE2: {0x2FE2, "EF_ICCID", "ICC Identification", FileTypeTransparent, 0, "MF"},
	0x2F05: {0x2F05, "EF_PL", "Preferred Languages", FileTypeTransparent, 0, "MF"},
	0x2F00: {0x2F00, "EF_DIR", "Application Directory", FileTypeLinearFixed, 0, "MF"},
}

// USIM Application files (ADF_USIM) - 3GPP TS 31.102
var USIM_Files = map[uint16]EFDefinition{
	// Identity files
	0x6F07: {0x6F07, "EF_IMSI", "International Mobile Subscriber Identity", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F40: {0x6F40, "EF_MSISDN", "Mobile Station ISDN Number", FileTypeLinearFixed, 0, "ADF_USIM"},
	0x6F46: {0x6F46, "EF_SPN", "Service Provider Name", FileTypeTransparent, 0, "ADF_USIM"},

	// Administrative files
	0x6FAD: {0x6FAD, "EF_AD", "Administrative Data", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F78: {0x6F78, "EF_ACC", "Access Control Class", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F05: {0x6F05, "EF_LI", "Language Indication", FileTypeTransparent, 0, "ADF_USIM"},

	// Service tables
	0x6F38: {0x6F38, "EF_UST", "USIM Service Table", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F56: {0x6F56, "EF_EST", "Enabled Services Table", FileTypeTransparent, 0, "ADF_USIM"},

	// Network files
	0x6F61: {0x6F61, "EF_OPLMNwACT", "Operator Controlled PLMN with Access Technology", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F62: {0x6F62, "EF_HPLMNwACT", "HPLMN with Access Technology", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F7B: {0x6F7B, "EF_FPLMN", "Forbidden PLMNs", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F7E: {0x6F7E, "EF_LOCI", "Location Information", FileTypeTransparent, 0, "ADF_USIM"},
	0x6FAE: {0x6FAE, "EF_PSLOCI", "PS Location Information", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F31: {0x6F31, "EF_HPPLMN", "Higher Priority PLMN Search Period", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F60: {0x6F60, "EF_PLMNwACT", "User Controlled PLMN with Access Technology", FileTypeTransparent, 0, "ADF_USIM"},

	// EPS/LTE files
	0x6FE3: {0x6FE3, "EF_EPSLOCI", "EPS Location Information", FileTypeTransparent, 0, "ADF_USIM"},
	0x6FE4: {0x6FE4, "EF_EPSNSC", "EPS NAS Security Context", FileTypeTransparent, 0, "ADF_USIM"},

	// 5G NR files
	0x6F5C: {0x6F5C, "EF_5GS3GPPLOCI", "5GS 3GPP Location Information", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F5D: {0x6F5D, "EF_5GSN3GPPLOCI", "5GS Non-3GPP Location Information", FileTypeTransparent, 0, "ADF_USIM"},

	// Security files
	0x6F08: {0x6F08, "EF_KEYS", "Ciphering and Integrity Keys", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F09: {0x6F09, "EF_KEYSPS", "Ciphering and Integrity Keys for PS domain", FileTypeTransparent, 0, "ADF_USIM"},

	// Phonebook
	0x6F3A: {0x6F3A, "EF_ADN", "Abbreviated Dialling Numbers", FileTypeLinearFixed, 0, "ADF_USIM"},
	0x6F3B: {0x6F3B, "EF_FDN", "Fixed Dialling Numbers", FileTypeLinearFixed, 0, "ADF_USIM"},
	0x6F3C: {0x6F3C, "EF_SMS", "Short Messages", FileTypeLinearFixed, 0, "ADF_USIM"},
	0x6F42: {0x6F42, "EF_SMSP", "SMS Parameters", FileTypeLinearFixed, 0, "ADF_USIM"},
	0x6F43: {0x6F43, "EF_SMSS", "SMS Status", FileTypeTransparent, 0, "ADF_USIM"},

	// Other
	0x6FC4: {0x6FC4, "EF_NETPAR", "Network Parameters", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F17: {0x6F17, "EF_RP", "Roaming Preference", FileTypeTransparent, 0, "ADF_USIM"},
	0x6F73: {0x6F73, "EF_PSLOCI", "Packet Switched Location Information", FileTypeTransparent, 0, "ADF_USIM"},
}

// ISIM Application files (ADF_ISIM) - 3GPP TS 31.103
var ISIM_Files = map[uint16]EFDefinition{
	0x6F02: {0x6F02, "EF_IMPI", "IMS Private User Identity", FileTypeTransparent, 0, "ADF_ISIM"},
	0x6F03: {0x6F03, "EF_DOMAIN", "Home Network Domain Name", FileTypeTransparent, 0, "ADF_ISIM"},
	0x6F04: {0x6F04, "EF_IMPU", "IMS Public User Identity", FileTypeLinearFixed, 0, "ADF_ISIM"},
	0x6F06: {0x6F06, "EF_ARR", "Access Rule Reference", FileTypeLinearFixed, 0, "ADF_ISIM"},
	0x6F07: {0x6F07, "EF_IST", "ISIM Service Table", FileTypeTransparent, 0, "ADF_ISIM"},
	0x6F09: {0x6F09, "EF_PCSCF", "P-CSCF Address", FileTypeLinearFixed, 0, "ADF_ISIM"},
	0x6F3C: {0x6F3C, "EF_SMS", "Short Messages", FileTypeLinearFixed, 0, "ADF_ISIM"},
	0x6F42: {0x6F42, "EF_SMSP", "SMS Parameters", FileTypeLinearFixed, 0, "ADF_ISIM"},
	0x6F43: {0x6F43, "EF_SMSS", "SMS Status", FileTypeTransparent, 0, "ADF_ISIM"},
	0x6FAD: {0x6FAD, "EF_AD", "Administrative Data", FileTypeTransparent, 0, "ADF_ISIM"},
	0x6F22: {0x6F22, "EF_UICCIARI", "UICC IARI", FileTypeLinearFixed, 0, "ADF_ISIM"},
}

// UST Service bits - USIM Service Table (3GPP TS 31.102)
var USTServices = map[int]string{
	1:   "Local Phone Book",
	2:   "FDN (Fixed Dialling Numbers)",
	3:   "Extension 2",
	4:   "SDN (Service Dialling Numbers)",
	5:   "Extension 3",
	6:   "BDN (Barred Dialling Numbers)",
	7:   "Extension 4",
	8:   "Outgoing Call Information (OCI and OCT)",
	9:   "Incoming Call Information (ICI and ICT)",
	10:  "SMS (Short Message Storage)",
	11:  "SMSR (Short Message Status Reports)",
	12:  "SMSP (SMS Parameters)",
	13:  "AoC (Advice of Charge)",
	14:  "CCP (Capability Configuration Parameters 2)",
	15:  "CB (Cell Broadcast Message Identifier)",
	16:  "CBMIR (Cell Broadcast Message Identifier Ranges)",
	17:  "GSS (Group Identifier Level 1)",
	18:  "GSS (Group Identifier Level 2)",
	19:  "SPN (Service Provider Name)",
	20:  "PLMN selector with Access Technology",
	21:  "MSISDN",
	22:  "Image (IMG)",
	23:  "Localised Service Areas (SoLSA)",
	24:  "Enhanced Multi-Level Precedence and Pre-emption Service",
	25:  "Automatic Answer for eMLPP",
	26:  "RFU",
	27:  "GSM Access",
	28:  "Data download via SMS-PP",
	29:  "Data download via SMS-CB",
	30:  "Call Control by USIM",
	31:  "MO-SMS Control by USIM",
	32:  "RUN AT COMMAND command",
	33:  "shall be set to 1",
	34:  "Enabled Services Table",
	35:  "APN Control List (ACL)",
	36:  "Depersonalisation Control Keys",
	37:  "Co-operative Network List",
	38:  "GSM Security Context",
	39:  "CPBCCH Information",
	40:  "Investigation Scan",
	41:  "MExE",
	42:  "Operator controlled PLMN selector with Access Technology",
	43:  "HPLMN selector with Access Technology",
	44:  "Extension 5",
	45:  "PLMN Network Name",
	46:  "Operator PLMN List",
	47:  "Mailbox Dialling Numbers",
	48:  "Message Waiting Indication Status",
	49:  "Call Forwarding Indication Status",
	50:  "RFU",
	51:  "Service Provider Display Information",
	52:  "MMS Notification",
	53:  "MMS User Connectivity Parameters",
	54:  "NIA (Network Initiated USSD)",
	55:  "VGCS Group Identifier List",
	56:  "VBS Group Identifier List",
	57:  "Pseudonym",
	58:  "IWLAN User PLMN selection",
	59:  "IWLAN Operator PLMN selection",
	60:  "IWLAN Home I-WLAN Specific Identifier List",
	61:  "User controlled WSID list",
	62:  "Operator controlled WSID list",
	63:  "VGCS security",
	64:  "VBS security",
	65:  "WLAN Reauthentication Identity",
	66:  "MM Storage",
	67:  "GBA (Generic Bootstrapping Architecture)",
	68:  "MBMS security",
	69:  "USSD Data download",
	70:  "Equivalent HPLMN",
	71:  "Additional TERMINAL PROFILE after UICC activation",
	72:  "Equivalent HPLMN Presentation Indication",
	73:  "Last RPLMN Selection Indication",
	74:  "OMA BCAST Smart Card Profile",
	75:  "GBA-based Local Key Establishment Mechanism",
	76:  "Terminal Applications",
	77:  "SPN Display Information",
	78:  "Network Access Rules",
	79:  "NC-OBWS",
	80:  "PWS Configuration",
	81:  "RFU",
	82:  "URI support by UICC",
	83:  "Extended Earfcn Support",
	84:  "ProSe",
	85:  "USAT Application Pairing",
	86:  "Media Type support",
	87:  "IMS call disconnection cause",
	88:  "URI support for MO SHORT MESSAGE CONTROL",
	89:  "ePDG configuration",
	90:  "ePDG configuration by PLMN",
	91:  "ACDC",
	92:  "MCPTT",
	93:  "ePDG Emergency support",
	94:  "MCPTT UE Config",
	95:  "MCData",
	96:  "MCVideo",
	97:  "XCAP Configuration by PLMN",
	98:  "XCAP Configuration",
	99:  "SIM file access via HTTP/TLS",
	100: "NASconfig",
	101: "PWS via E-UTRAN",
	102: "EARFCN list for MTC/NB-IOT UEs",
	103: "5G Security Parameters",
	104: "5G NASconfig for 5G System",
	105: "NID configuration for 5G System",
	106: "5G SoR",
	107: "5G RP",
	108: "5G NSSAI",
	109: "5GS NSSAI Storage",
	110: "5G Operator PLMN List",
	111: "5G SUPI",
	112: "SUCI calculation by USIM",
	113: "5G UAC Access Identities",
	114: "Routing Indicator",
	115: "N3IWF Selection Information",
	116: "URSP by PLMN",
	117: "5G Location Privacy Indicator",
	118: "TNAN Connection Verification",
	119: "5G ProSe",
	120: "5G ProSe Layer-2 UE-to-Network Relay",
	121: "5G ProSe Layer-3 UE-to-Network Relay",
	122: "5G ProSe Layer-2 UE-to-UE Relay",
	123: "5G ProSe Layer-3 UE-to-UE Relay",
	124: "WLAN offloading support", // VoWiFi related!
	125: "EAB Configuration",
	126: "HPLMN Direct Access",
	127: "MCPTT Group Configuration",
	128: "MCData Group Configuration",
}

// IST Service bits - ISIM Service Table (3GPP TS 31.103)
var ISTServices = map[int]string{
	1:  "P-CSCF address",
	2:  "GBA (Generic Bootstrapping Architecture)",
	3:  "HTTP Digest",
	4:  "GBA-based Local Key Establishment Mechanism",
	5:  "XCAP Configuration",
	6:  "Support of Service Specific Non-Registrations",
	7:  "SMS over IP",
	8:  "PCSCF Discovery for IMS Local Break Out",
	9:  "MCPTT (Mission Critical PTT)",
	10: "MCVideo",
	11: "MCData",
	12: "Voice domain preference",
}

// GetAllFiles returns all file definitions
func GetAllFiles() map[uint16]EFDefinition {
	all := make(map[uint16]EFDefinition)
	for k, v := range MF_Files {
		all[k] = v
	}
	for k, v := range USIM_Files {
		all[k] = v
	}
	for k, v := range ISIM_Files {
		all[k] = v
	}
	return all
}

// GetFileByID returns file definition by ID
func GetFileByID(id uint16) (EFDefinition, bool) {
	if f, ok := MF_Files[id]; ok {
		return f, true
	}
	if f, ok := USIM_Files[id]; ok {
		return f, true
	}
	if f, ok := ISIM_Files[id]; ok {
		return f, true
	}
	return EFDefinition{}, false
}
