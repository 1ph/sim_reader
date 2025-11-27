package sim

import (
	"fmt"
	"sim_reader/card"
)

// WriteIMSI writes IMSI to the card
// Note: This also affects MCC/MNC as they are part of IMSI
func WriteIMSI(reader *card.Reader, imsi string) error {
	// Select USIM application
	resp, err := reader.Select(AID_USIM)
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
	resp, err := reader.Select(AID_USIM)
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
	resp, err := reader.Select(AID_USIM)
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
	resp, err := reader.Select(AID_USIM)
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
	resp, err := reader.Select(AID_USIM)
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
	resp, err := reader.Select(AID_USIM)
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
