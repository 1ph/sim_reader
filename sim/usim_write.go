package sim

import (
	"fmt"
	"sim_reader/card"
)

// WriteIMSI writes IMSI to the card
// Note: This also affects MCC/MNC as they are part of IMSI
func WriteIMSI(reader *card.Reader, imsi string) error {
	// Select USIM application
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_IMSI
	resp, err = reader.Select([]byte{0x6F, 0x07})
	if err != nil {
		return fmt.Errorf("failed to select EF_IMSI: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_IMSI selection failed: %s", card.SWToString(resp.SW()))
	}

	// Encode IMSI
	encoded, err := EncodeIMSI(imsi)
	if err != nil {
		return fmt.Errorf("failed to encode IMSI: %w", err)
	}

	// Write IMSI
	resp, err = reader.UpdateBinary(0, encoded)
	if err != nil {
		return fmt.Errorf("failed to write IMSI: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("IMSI write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// WriteSPN writes Service Provider Name
func WriteSPN(reader *card.Reader, spn string, displayCondition byte) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_SPN
	resp, err = reader.Select([]byte{0x6F, 0x46})
	if err != nil {
		return fmt.Errorf("failed to select EF_SPN: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_SPN selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size from FCP
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 17 // Default SPN size
	}

	// Encode SPN: display condition byte + name padded with 0xFF
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = 0xFF
	}
	data[0] = displayCondition
	copy(data[1:], []byte(spn))

	// Write SPN
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to write SPN: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("SPN write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// ClearForbiddenPLMN clears the Forbidden PLMN list
func ClearForbiddenPLMN(reader *card.Reader) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_FPLMN
	resp, err = reader.Select([]byte{0x6F, 0x7B})
	if err != nil {
		return fmt.Errorf("failed to select EF_FPLMN: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_FPLMN selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 12 // Default: 4 PLMNs * 3 bytes
	}

	// Clear with 0xFF
	data := ClearFPLMN(fileSize)

	// Write
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to clear FPLMN: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("FPLMN clear failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// SetUSIMServices enables or disables services in UST
func SetUSIMServices(reader *card.Reader, services map[int]bool) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_UST
	resp, err = reader.Select([]byte{0x6F, 0x38})
	if err != nil {
		return fmt.Errorf("failed to select EF_UST: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_UST selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 16 // Default
	}

	// Read current UST
	currentUST, err := reader.ReadAllBinary(fileSize)
	if err != nil {
		return fmt.Errorf("failed to read current UST: %w", err)
	}

	// Encode new UST
	newUST := EncodeUST(currentUST, services)

	// Write UST
	resp, err = reader.UpdateBinary(0, newUST)
	if err != nil {
		return fmt.Errorf("failed to write UST: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("UST write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// EnableVoLTE enables VoLTE related services
func EnableVoLTE(reader *card.Reader) error {
	services := map[int]bool{
		UST_IMS_CALL_DISCONNECT: true, // Service 87
	}
	return SetUSIMServices(reader, services)
}

// DisableVoLTE disables VoLTE related services
func DisableVoLTE(reader *card.Reader) error {
	services := map[int]bool{
		UST_IMS_CALL_DISCONNECT: false, // Service 87
	}
	return SetUSIMServices(reader, services)
}

// EnableVoWiFi enables VoWiFi related services
func EnableVoWiFi(reader *card.Reader) error {
	services := map[int]bool{
		UST_WLAN_OFFLOADING:  true, // Service 124
		UST_EPDG_CONFIG:      true, // Service 89
		UST_EPDG_CONFIG_PLMN: true, // Service 90
	}
	return SetUSIMServices(reader, services)
}

// DisableVoWiFi disables VoWiFi related services
func DisableVoWiFi(reader *card.Reader) error {
	services := map[int]bool{
		UST_WLAN_OFFLOADING:  false, // Service 124
		UST_EPDG_CONFIG:      false, // Service 89
		UST_EPDG_CONFIG_PLMN: false, // Service 90
	}
	return SetUSIMServices(reader, services)
}

// UpdateMNCLength updates the MNC length in EF_AD
func UpdateMNCLength(reader *card.Reader, mncLength int) error {
	if mncLength != 2 && mncLength != 3 {
		return fmt.Errorf("invalid MNC length: %d (must be 2 or 3)", mncLength)
	}

	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_AD
	resp, err = reader.Select([]byte{0x6F, 0xAD})
	if err != nil {
		return fmt.Errorf("failed to select EF_AD: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_AD selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 4
	}

	// Read current AD
	currentAD, err := reader.ReadAllBinary(fileSize)
	if err != nil {
		return fmt.Errorf("failed to read current AD: %w", err)
	}

	// Update MNC length
	newAD := EncodeAD(currentAD, mncLength)

	// Write AD
	resp, err = reader.UpdateBinary(0, newAD)
	if err != nil {
		return fmt.Errorf("failed to write AD: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("AD write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// WriteHPLMN writes Home PLMN with Access Technology
func WriteHPLMN(reader *card.Reader, mcc, mnc string, act uint16) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_HPLMNwACT
	resp, err = reader.Select([]byte{0x6F, 0x62})
	if err != nil {
		return fmt.Errorf("failed to select EF_HPLMNwACT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_HPLMNwACT selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 5 // One PLMN entry
	}

	// Encode PLMN
	plmn, err := EncodePLMN(mcc, mnc)
	if err != nil {
		return fmt.Errorf("failed to encode PLMN: %w", err)
	}

	// Create data: PLMN (3 bytes) + ACT (2 bytes) + padding
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = 0xFF
	}
	copy(data[0:3], plmn)
	data[3] = byte(act >> 8)
	data[4] = byte(act & 0xFF)

	// Write
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to write HPLMNwACT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("HPLMNwACT write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// Access Technology flags
const (
	ACT_UTRAN       = 0x8000 // 3G UMTS
	ACT_E_UTRAN     = 0x4000 // 4G LTE
	ACT_GSM         = 0x0080 // 2G GSM
	ACT_GSM_COMPACT = 0x0040
	ACT_CDMA_HRPD   = 0x0020
	ACT_CDMA_1X     = 0x0010
	ACT_NR          = 0x0008 // 5G NR
	ACT_NG_RAN      = 0x0004 // 5G SA
	ACT_ALL         = ACT_UTRAN | ACT_E_UTRAN | ACT_GSM | ACT_NR | ACT_NG_RAN
)

// WriteHPLMNFromString parses string format "MCC:MNC:ACT" and writes HPLMN
// ACT can be: eutran, utran, gsm, nr, ngran, all (comma-separated)
// Example: "250:88:eutran,utran,gsm" or "250:88:all"
func WriteHPLMNFromString(reader *card.Reader, hplmnStr string) error {
	mcc, mnc, act, err := ParseHPLMNString(hplmnStr)
	if err != nil {
		return err
	}
	return WriteHPLMN(reader, mcc, mnc, act)
}

// WriteHPLMNList writes multiple HPLMN entries with Access Technology
func WriteHPLMNList(reader *card.Reader, entries []HPLMNEntry) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_HPLMNwACT
	resp, err = reader.Select([]byte{0x6F, 0x62})
	if err != nil {
		return fmt.Errorf("failed to select EF_HPLMNwACT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_HPLMNwACT selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 5 * len(entries) // 5 bytes per entry
	}

	// Build data: each entry is 5 bytes (3 PLMN + 2 ACT)
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = 0xFF
	}

	offset := 0
	for _, entry := range entries {
		if offset+5 > fileSize {
			break
		}
		plmn, err := EncodePLMN(entry.MCC, entry.MNC)
		if err != nil {
			continue
		}
		copy(data[offset:offset+3], plmn)
		data[offset+3] = byte(entry.ACT >> 8)
		data[offset+4] = byte(entry.ACT & 0xFF)
		offset += 5
	}

	// Write
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to write HPLMNwACT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("HPLMNwACT write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// HPLMNEntry represents a single HPLMN entry
type HPLMNEntry struct {
	MCC string
	MNC string
	ACT uint16
}

// ParseHPLMNString parses "MCC:MNC:ACT" format
func ParseHPLMNString(s string) (mcc, mnc string, act uint16, err error) {
	parts := splitString(s, ':')
	if len(parts) < 2 {
		return "", "", 0, fmt.Errorf("invalid HPLMN format: expected MCC:MNC[:ACT], got %s", s)
	}

	mcc = parts[0]
	mnc = parts[1]

	if len(mcc) != 3 {
		return "", "", 0, fmt.Errorf("invalid MCC: must be 3 digits")
	}
	if len(mnc) < 2 || len(mnc) > 3 {
		return "", "", 0, fmt.Errorf("invalid MNC: must be 2-3 digits")
	}

	// Default to all technologies if not specified
	if len(parts) < 3 || parts[2] == "" {
		act = ACT_ALL
	} else {
		act = ParseACTString(parts[2])
		if act == 0 {
			return "", "", 0, fmt.Errorf("invalid ACT: %s", parts[2])
		}
	}

	return mcc, mnc, act, nil
}

// ParseACTString parses comma-separated ACT names
func ParseACTString(s string) uint16 {
	var act uint16
	parts := splitString(s, ',')
	for _, p := range parts {
		p = trimSpace(p)
		switch toLower(p) {
		case "eutran", "e-utran", "lte", "4g":
			act |= ACT_E_UTRAN
		case "utran", "umts", "3g":
			act |= ACT_UTRAN
		case "gsm", "2g":
			act |= ACT_GSM
		case "nr", "5g":
			act |= ACT_NR
		case "ngran", "ng-ran", "5gsa":
			act |= ACT_NG_RAN
		case "all":
			act = ACT_ALL
		}
	}
	return act
}

// Helper functions to avoid importing strings package again
func splitString(s string, sep byte) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func toLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] = b[i] + 32
		}
	}
	return string(b)
}

// UE Operation Mode constants (3GPP TS 31.102, EF_AD byte 1)
const (
	OP_MODE_NORMAL                 = 0x00 // Normal operation
	OP_MODE_TYPE_APPROVAL          = 0x01 // Type approval operations
	OP_MODE_NORMAL_SPECIFIC        = 0x02 // Normal operation + specific facilities
	OP_MODE_TYPE_APPROVAL_SPECIFIC = 0x04 // Type approval + specific facilities
	OP_MODE_MAINTENANCE            = 0x08 // Maintenance (off-line)
	OP_MODE_CELL_TEST              = 0x80 // Cell test operation
)

// OperationModeNames maps mode codes to human-readable names
var OperationModeNames = map[byte]string{
	OP_MODE_NORMAL:                 "normal",
	OP_MODE_TYPE_APPROVAL:          "type-approval",
	OP_MODE_NORMAL_SPECIFIC:        "normal-specific",
	OP_MODE_TYPE_APPROVAL_SPECIFIC: "type-approval-specific",
	OP_MODE_MAINTENANCE:            "maintenance",
	OP_MODE_CELL_TEST:              "cell-test",
}

// SetOperationMode sets the UE operation mode in EF_AD
// Supported modes:
//   - normal (0x00): Normal operation
//   - type-approval (0x01): Type approval operations
//   - normal-specific (0x02): Normal + specific facilities
//   - type-approval-specific (0x04): Type approval + specific facilities
//   - maintenance (0x08): Maintenance/off-line mode
//   - cell-test (0x80): Cell test operation (for test PLMNs like 001-01)
func SetOperationMode(reader *card.Reader, mode byte) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_AD
	resp, err = reader.Select([]byte{0x6F, 0xAD})
	if err != nil {
		return fmt.Errorf("failed to select EF_AD: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_AD selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 4
	}

	// Read current AD
	currentAD, err := reader.ReadAllBinary(fileSize)
	if err != nil {
		return fmt.Errorf("failed to read current AD: %w", err)
	}

	// Update operation mode (byte 0)
	currentAD[0] = mode

	// Write AD
	resp, err = reader.UpdateBinary(0, currentAD)
	if err != nil {
		return fmt.Errorf("failed to write AD: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("AD write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// SetOperationModeFromString parses mode name and sets it
func SetOperationModeFromString(reader *card.Reader, modeName string) error {
	mode, err := ParseOperationMode(modeName)
	if err != nil {
		return err
	}
	return SetOperationMode(reader, mode)
}

// ParseOperationMode parses mode name to byte value
func ParseOperationMode(name string) (byte, error) {
	name = toLower(trimSpace(name))
	switch name {
	case "normal", "0", "0x00":
		return OP_MODE_NORMAL, nil
	case "type-approval", "typeapproval", "approval", "1", "0x01":
		return OP_MODE_TYPE_APPROVAL, nil
	case "normal-specific", "normalspecific", "2", "0x02":
		return OP_MODE_NORMAL_SPECIFIC, nil
	case "type-approval-specific", "typeapprovalspecific", "4", "0x04":
		return OP_MODE_TYPE_APPROVAL_SPECIFIC, nil
	case "maintenance", "offline", "8", "0x08":
		return OP_MODE_MAINTENANCE, nil
	case "cell-test", "celltest", "test", "128", "0x80":
		return OP_MODE_CELL_TEST, nil
	default:
		return 0, fmt.Errorf("unknown operation mode: %s (use: normal, type-approval, normal-specific, type-approval-specific, maintenance, cell-test)", name)
	}
}

// WriteUserPLMN writes User Controlled PLMN list (EF_PLMNwAcT)
// This is different from HPLMN - User PLMNs are preferred networks selected by user
func WriteUserPLMN(reader *card.Reader, mcc, mnc string, act uint16) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_PLMNwAcT (0x6F60) - User Controlled PLMN Selector with Access Technology
	resp, err = reader.Select([]byte{0x6F, 0x60})
	if err != nil {
		return fmt.Errorf("failed to select EF_PLMNwAcT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_PLMNwAcT selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 5 // One PLMN entry
	}

	// Encode PLMN
	plmn, err := EncodePLMN(mcc, mnc)
	if err != nil {
		return fmt.Errorf("failed to encode PLMN: %w", err)
	}

	// Create data: PLMN (3 bytes) + ACT (2 bytes) + padding
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = 0xFF
	}
	copy(data[0:3], plmn)
	data[3] = byte(act >> 8)
	data[4] = byte(act & 0xFF)

	// Write
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to write PLMNwAcT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("PLMNwAcT write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// WriteUserPLMNList writes multiple User Controlled PLMN entries
func WriteUserPLMNList(reader *card.Reader, entries []HPLMNEntry) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_PLMNwAcT (0x6F60)
	resp, err = reader.Select([]byte{0x6F, 0x60})
	if err != nil {
		return fmt.Errorf("failed to select EF_PLMNwAcT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_PLMNwAcT selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 5 * len(entries) // 5 bytes per entry
	}

	// Build data: each entry is 5 bytes (3 PLMN + 2 ACT)
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = 0xFF
	}

	offset := 0
	for _, entry := range entries {
		if offset+5 > fileSize {
			break
		}
		plmn, err := EncodePLMN(entry.MCC, entry.MNC)
		if err != nil {
			continue
		}
		copy(data[offset:offset+3], plmn)
		data[offset+3] = byte(entry.ACT >> 8)
		data[offset+4] = byte(entry.ACT & 0xFF)
		offset += 5
	}

	// Write
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to write PLMNwAcT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("PLMNwAcT write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// WriteUserPLMNFromString parses string format "MCC:MNC:ACT" and writes User PLMN
func WriteUserPLMNFromString(reader *card.Reader, plmnStr string) error {
	mcc, mnc, act, err := ParseHPLMNString(plmnStr)
	if err != nil {
		return err
	}
	return WriteUserPLMN(reader, mcc, mnc, act)
}

// WriteOPLMN writes Operator Controlled PLMN list (EF_OPLMNwACT)
// This is different from HPLMN - Operator PLMNs are roaming partners selected by operator
func WriteOPLMN(reader *card.Reader, mcc, mnc string, act uint16) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_OPLMNwACT (0x6F61) - Operator Controlled PLMN Selector with Access Technology
	resp, err = reader.Select([]byte{0x6F, 0x61})
	if err != nil {
		return fmt.Errorf("failed to select EF_OPLMNwACT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_OPLMNwACT selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 5 // One PLMN entry
	}

	// Encode PLMN
	plmn, err := EncodePLMN(mcc, mnc)
	if err != nil {
		return fmt.Errorf("failed to encode PLMN: %w", err)
	}

	// Create data: PLMN (3 bytes) + ACT (2 bytes) + padding
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = 0xFF
	}
	copy(data[0:3], plmn)
	data[3] = byte(act >> 8)
	data[4] = byte(act & 0xFF)

	// Write
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to write OPLMNwACT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("OPLMNwACT write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// WriteOPLMNList writes multiple Operator Controlled PLMN entries
func WriteOPLMNList(reader *card.Reader, entries []HPLMNEntry) error {
	// Select USIM
	resp, err := SelectUSIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_OPLMNwACT (0x6F61)
	resp, err = reader.Select([]byte{0x6F, 0x61})
	if err != nil {
		return fmt.Errorf("failed to select EF_OPLMNwACT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_OPLMNwACT selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 5 * len(entries) // 5 bytes per entry
	}

	// Build data: each entry is 5 bytes (3 PLMN + 2 ACT)
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = 0xFF
	}

	offset := 0
	for _, entry := range entries {
		if offset+5 > fileSize {
			break
		}
		plmn, err := EncodePLMN(entry.MCC, entry.MNC)
		if err != nil {
			continue
		}
		copy(data[offset:offset+3], plmn)
		data[offset+3] = byte(entry.ACT >> 8)
		data[offset+4] = byte(entry.ACT & 0xFF)
		offset += 5
	}

	// Write
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to write OPLMNwACT: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("OPLMNwACT write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// WriteOPLMNFromString parses string format "MCC:MNC:ACT" and writes Operator PLMN
func WriteOPLMNFromString(reader *card.Reader, plmnStr string) error {
	mcc, mnc, act, err := ParseHPLMNString(plmnStr)
	if err != nil {
		return err
	}
	return WriteOPLMN(reader, mcc, mnc, act)
}
