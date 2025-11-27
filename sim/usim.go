package sim

import (
	"fmt"
	"sim_reader/card"
)

// USIMData contains all data read from USIM application
type USIMData struct {
	// Identity
	ICCID  string
	IMSI   string
	MSISDN string
	SPN    string

	// Network
	MCC      string
	MNC      string
	Country  string
	Operator string
	HPLMN    []PLMNwACT
	OPLMN    []PLMNwACT
	FPLMN    []string
	UserPLMN []PLMNwACT

	// Administrative
	AdminData AdminData
	ACC       []int // Access Control Classes

	// Services
	UST map[int]bool // USIM Service Table
	EST map[int]bool // Enabled Services Table

	// Raw data for debugging
	RawFiles map[string][]byte
}

// ReadUSIM reads all USIM application data
func ReadUSIM(reader *card.Reader) (*USIMData, error) {
	data := &USIMData{
		RawFiles: make(map[string][]byte),
	}

	// First read ICCID from MF (doesn't require USIM selection)
	iccid, err := readICCID(reader)
	if err == nil {
		data.ICCID = iccid
	}

	// Select USIM application
	resp, err := reader.Select(AID_USIM)
	if err != nil {
		return nil, fmt.Errorf("failed to select USIM: %w", err)
	}
	if !resp.IsOK() {
		return nil, fmt.Errorf("USIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Read IMSI
	if _, raw, err := readEF(reader, 0x6F07); err == nil {
		data.IMSI = DecodeIMSI(raw)
		data.RawFiles["EF_IMSI"] = raw
		// Extract MCC/MNC from IMSI
		if len(data.IMSI) >= 5 {
			data.MCC = data.IMSI[:3]
			// Try to determine MNC length from AD
			data.MNC = data.IMSI[3:5] // Default 2 digits
		}
	} else {
		fmt.Printf("Warning: could not read IMSI: %v\n", err)
	}

	// Read Administrative Data (includes MNC length)
	if _, raw, err := readEF(reader, 0x6FAD); err == nil {
		data.AdminData = DecodeAD(raw)
		data.RawFiles["EF_AD"] = raw
		// Update MNC based on AD
		if data.AdminData.MNCLength == 3 && len(data.IMSI) >= 6 {
			data.MNC = data.IMSI[3:6]
		}
	}

	// Set country and operator names
	data.Country = GetMCCCountry(data.MCC)
	data.Operator = GetOperatorName(data.MCC, data.MNC)

	// Read SPN
	if _, raw, err := readEF(reader, 0x6F46); err == nil {
		data.SPN = DecodeSPN(raw)
		data.RawFiles["EF_SPN"] = raw
	}

	// Read MSISDN (linear fixed file)
	if msisdn, raw := readMSISDN(reader); msisdn != "" {
		data.MSISDN = msisdn
		data.RawFiles["EF_MSISDN"] = raw
	}

	// Read UST (USIM Service Table)
	if _, raw, err := readEF(reader, 0x6F38); err == nil {
		data.UST = DecodeUST(raw)
		data.RawFiles["EF_UST"] = raw
	}

	// Read EST (Enabled Services Table)
	if _, raw, err := readEF(reader, 0x6F56); err == nil {
		data.EST = DecodeUST(raw)
		data.RawFiles["EF_EST"] = raw
	}

	// Read ACC
	if _, raw, err := readEF(reader, 0x6F78); err == nil {
		data.ACC = DecodeACC(raw)
		data.RawFiles["EF_ACC"] = raw
	}

	// Read HPLMN with ACT
	if _, raw, err := readEF(reader, 0x6F62); err == nil {
		data.HPLMN = DecodePLMNwACT(raw)
		data.RawFiles["EF_HPLMNwACT"] = raw
	}

	// Read Operator PLMN with ACT
	if _, raw, err := readEF(reader, 0x6F61); err == nil {
		data.OPLMN = DecodePLMNwACT(raw)
		data.RawFiles["EF_OPLMNwACT"] = raw
	}

	// Read User PLMN with ACT
	if _, raw, err := readEF(reader, 0x6F60); err == nil {
		data.UserPLMN = DecodePLMNwACT(raw)
		data.RawFiles["EF_PLMNwACT"] = raw
	}

	// Read Forbidden PLMN
	if _, raw, err := readEF(reader, 0x6F7B); err == nil {
		data.FPLMN = DecodePLMNList(raw)
		data.RawFiles["EF_FPLMN"] = raw
	}

	return data, nil
}

// readICCID reads ICCID from MF
func readICCID(reader *card.Reader) (string, error) {
	// Select MF first
	reader.Select([]byte{0x3F, 0x00})

	// Select EF_ICCID
	resp, err := reader.Select([]byte{0x2F, 0xE2})
	if err != nil {
		return "", err
	}
	if !resp.IsOK() {
		return "", fmt.Errorf("select failed: %s", card.SWToString(resp.SW()))
	}

	// Read binary
	resp, err = reader.ReadBinary(0, 10)
	if err != nil {
		return "", err
	}
	if !resp.IsOK() {
		return "", fmt.Errorf("read failed: %s", card.SWToString(resp.SW()))
	}

	return DecodeICCID(resp.Data), nil
}

// readEF selects and reads a transparent EF file
func readEF(reader *card.Reader, fileID uint16) (string, []byte, error) {
	// Select file
	fid := []byte{byte(fileID >> 8), byte(fileID & 0xFF)}
	resp, err := reader.Select(fid)
	if err != nil {
		return "", nil, err
	}
	if !resp.IsOK() {
		return "", nil, fmt.Errorf("select 0x%04X failed: %s", fileID, card.SWToString(resp.SW()))
	}

	// Parse FCP to get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 256 // Default
	}

	// Read binary
	data, err := reader.ReadAllBinary(fileSize)
	if err != nil {
		return "", nil, err
	}

	return fmt.Sprintf("%X", data), data, nil
}

// readMSISDN reads MSISDN from linear fixed file
func readMSISDN(reader *card.Reader) (string, []byte) {
	// Select EF_MSISDN
	fid := []byte{0x6F, 0x40}
	resp, err := reader.Select(fid)
	if err != nil {
		return "", nil
	}
	if !resp.IsOK() {
		return "", nil
	}

	// Parse FCP to get record length
	recordLen := parseFCPRecordSize(resp.Data)
	if recordLen == 0 {
		recordLen = 34 // Default MSISDN record size
	}

	// Read first record
	resp, err = reader.ReadRecord(1, byte(recordLen))
	if err != nil {
		return "", nil
	}
	if !resp.IsOK() {
		return "", nil
	}

	return DecodeMSISDN(resp.Data), resp.Data
}

// parseFCPFileSize extracts file size from FCP template
func parseFCPFileSize(fcp []byte) int {
	// FCP Template: 62 Len [TLV...]
	// File size tag: 80
	if len(fcp) < 4 {
		return 0
	}

	idx := 0
	if fcp[0] == 0x62 {
		idx = 2 // Skip template tag and length
	}

	for idx < len(fcp)-2 {
		tag := fcp[idx]
		length := int(fcp[idx+1])
		if idx+2+length > len(fcp) {
			break
		}

		if tag == 0x80 && length >= 2 {
			// File size
			return int(fcp[idx+2])<<8 | int(fcp[idx+3])
		}

		idx += 2 + length
	}

	return 0
}

// parseFCPRecordSize extracts record size from FCP template
func parseFCPRecordSize(fcp []byte) int {
	// Record size is in tag 82 (File Descriptor)
	if len(fcp) < 4 {
		return 0
	}

	idx := 0
	if fcp[0] == 0x62 {
		idx = 2
	}

	for idx < len(fcp)-2 {
		tag := fcp[idx]
		length := int(fcp[idx+1])
		if idx+2+length > len(fcp) {
			break
		}

		if tag == 0x82 && length >= 5 {
			// File descriptor byte, data coding, record length (2 bytes), num records
			recordLen := int(fcp[idx+4])<<8 | int(fcp[idx+5])
			if recordLen > 0 {
				return recordLen
			}
		}

		idx += 2 + length
	}

	return 0
}

// HasService checks if a UST service is available
func (u *USIMData) HasService(serviceNum int) bool {
	if u.UST == nil {
		return false
	}
	return u.UST[serviceNum]
}

// HasVoLTE checks if VoLTE related services are available
func (u *USIMData) HasVoLTE() bool {
	// Service 87: IMS call disconnection cause
	// Also check if ISIM is present (service 95 in older specs)
	return u.HasService(87)
}

// HasVoWiFi checks if VoWiFi (WLAN offloading) is available
func (u *USIMData) HasVoWiFi() bool {
	// Service 124: WLAN offloading support
	return u.HasService(124)
}

// HasSMSOverIP checks if SMS over IP is available
func (u *USIMData) HasSMSOverIP() bool {
	// Service 111 relates to SMS over NAS / IMS
	return u.HasService(111)
}

// GetEnabledServices returns list of enabled service names
func (u *USIMData) GetEnabledServices() []string {
	var services []string
	for num, enabled := range u.UST {
		if enabled {
			if name, ok := USTServices[num]; ok {
				services = append(services, fmt.Sprintf("%d: %s", num, name))
			} else {
				services = append(services, fmt.Sprintf("%d: Unknown", num))
			}
		}
	}
	return services
}
