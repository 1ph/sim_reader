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
	AdminData   AdminData
	ACC         []int    // Access Control Classes
	Languages   []string // Preferred languages (EF_LI)
	HPLMNPeriod int      // HPLMN search period in minutes (EF_HPPLMN)

	// Location Information
	LOCI    *LocationInfo    // CS domain location (EF_LOCI)
	PSLOCI  *PSLocationInfo  // PS domain location (EF_PSLOCI)
	EPSLOCI *EPSLocationInfo // EPS/LTE location (EF_EPSLOCI)

	// Services
	UST map[int]bool // USIM Service Table
	EST map[int]bool // Enabled Services Table

	// File Access Conditions (populated when -adm-check is used)
	FileAccess []FileAccessInfo

	// Raw data for debugging
	RawFiles map[string][]byte
}

// LocationInfo contains CS domain location info (EF_LOCI)
type LocationInfo struct {
	TMSI     string
	LAI      string // Location Area Identity
	TMSITime int
	Status   string
}

// PSLocationInfo contains PS domain location info (EF_PSLOCI)
type PSLocationInfo struct {
	PTMSI    string
	PTMSISig string
	RAI      string // Routing Area Identity
	Status   string
}

// EPSLocationInfo contains EPS location info (EF_EPSLOCI)
type EPSLocationInfo struct {
	GUTI   string
	TAI    string // Tracking Area Identity
	Status string
}

// ReadUSIM reads all USIM application data
func ReadUSIM(reader *card.Reader) (*USIMData, error) {
	data := &USIMData{
		RawFiles: make(map[string][]byte),
	}

	// First read ICCID from MF (doesn't require USIM selection)
	iccid, rawICCID, err := readICCIDWithRaw(reader)
	if err == nil {
		data.ICCID = iccid
		if len(rawICCID) > 0 {
			data.RawFiles["EF_ICCID"] = rawICCID
		}
	}

	// Select USIM application
	// Try multiple methods:
	// 1. Select by detected AID
	// 2. Select by standard AID
	// 3. Select by File ID path (for cards that don't support AID selection)

	var resp *card.APDUResponse
	usimSelected := false

	// Method 1: Try detected AID
	usimAID := GetUSIMAID()
	resp, err = reader.Select(usimAID)
	if err == nil && resp.IsOK() {
		usimSelected = true
	}

	// Method 2: Try standard AID if detected failed
	if !usimSelected && len(DetectedUSIM_AID) > 0 {
		resp, err = reader.Select(AID_USIM)
		if err == nil && resp.IsOK() {
			usimSelected = true
		}
	}

	// Method 3: Try selecting by File ID path (for non-standard cards)
	// This is needed for cards that return 6D00 (Instruction not supported) for AID selection
	if !usimSelected && HasUSIMPath() {
		// First select MF
		if UseGSMCommands {
			reader.SelectGSM([]byte{0x3F, 0x00})
			// Then select USIM by File ID using GSM command
			resp, err = reader.SelectGSM(GetUSIMPath())
		} else {
			reader.Select([]byte{0x3F, 0x00})
			// Then select USIM by File ID
			resp, err = reader.SelectDF(GetUSIMPath())
		}
		if err == nil && resp.IsOK() {
			usimSelected = true
		}
	}

	if !usimSelected {
		swStr := "unknown error"
		if resp != nil {
			swStr = card.SWToString(resp.SW())
		}
		return nil, fmt.Errorf("USIM selection failed: %s (card may not support AID selection)", swStr)
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

	// Read Language Indication (EF_LI)
	if _, raw, err := readEF(reader, 0x6F05); err == nil {
		data.Languages = DecodeLanguages(raw)
		data.RawFiles["EF_LI"] = raw
	}

	// Read HPLMN search period (EF_HPPLMN)
	if _, raw, err := readEF(reader, 0x6F31); err == nil {
		data.HPLMNPeriod = DecodeHPLMNPeriod(raw)
		data.RawFiles["EF_HPPLMN"] = raw
	}

	// Read Location Information (EF_LOCI)
	if _, raw, err := readEF(reader, 0x6F7E); err == nil {
		data.LOCI = DecodeLOCI(raw)
		data.RawFiles["EF_LOCI"] = raw
	}

	// Read PS Location Information (EF_PSLOCI)
	if _, raw, err := readEF(reader, 0x6FAE); err == nil {
		data.PSLOCI = DecodePSLOCI(raw)
		data.RawFiles["EF_PSLOCI"] = raw
	}

	// Read EPS Location Information (EF_EPSLOCI)
	if _, raw, err := readEF(reader, 0x6FE3); err == nil {
		data.EPSLOCI = DecodeEPSLOCI(raw)
		data.RawFiles["EF_EPSLOCI"] = raw
	}

	return data, nil
}

// readICCID reads ICCID from MF
func readICCID(reader *card.Reader) (string, error) {
	iccid, _, err := readICCIDWithRaw(reader)
	return iccid, err
}

// readICCIDWithRaw reads ICCID from MF and returns raw data
func readICCIDWithRaw(reader *card.Reader) (string, []byte, error) {
	var resp *card.APDUResponse
	var err error

	// Select MF first
	if UseGSMCommands {
		reader.SelectGSM([]byte{0x3F, 0x00})
		resp, err = reader.SelectGSM([]byte{0x2F, 0xE2})
	} else {
		reader.Select([]byte{0x3F, 0x00})
		resp, err = reader.Select([]byte{0x2F, 0xE2})
	}

	if err != nil {
		return "", nil, err
	}
	if !resp.IsOK() {
		return "", nil, fmt.Errorf("select failed: %s", card.SWToString(resp.SW()))
	}

	// Read binary
	if UseGSMCommands {
		resp, err = reader.ReadBinaryGSM(0, 10)
	} else {
		resp, err = reader.ReadBinary(0, 10)
	}

	if err != nil {
		return "", nil, err
	}
	if !resp.IsOK() {
		return "", nil, fmt.Errorf("read failed: %s", card.SWToString(resp.SW()))
	}

	return DecodeICCID(resp.Data), resp.Data, nil
}

// readEF selects and reads a transparent EF file
func readEF(reader *card.Reader, fileID uint16) (string, []byte, error) {
	// Select file
	fid := []byte{byte(fileID >> 8), byte(fileID & 0xFF)}

	var resp *card.APDUResponse
	var err error

	if UseGSMCommands {
		resp, err = reader.SelectGSM(fid)
	} else {
		resp, err = reader.Select(fid)
	}

	if err != nil {
		return "", nil, err
	}
	if !resp.IsOK() {
		return "", nil, fmt.Errorf("select 0x%04X failed: %s", fileID, card.SWToString(resp.SW()))
	}

	// Parse response to get file size
	var fileSize int

	if UseGSMCommands {
		// GSM response format: file size is at bytes 2-3
		if len(resp.Data) >= 4 {
			fileSize = int(resp.Data[2])<<8 | int(resp.Data[3])
		}
	} else {
		// Parse FCP to get file size
		fileSize = parseFCPFileSize(resp.Data)
	}

	if fileSize == 0 {
		fileSize = 256 // Default
	}

	// Read binary
	var data []byte
	if UseGSMCommands {
		// Read in chunks for GSM
		offset := uint16(0)
		for int(offset) < fileSize {
			remaining := fileSize - int(offset)
			readLen := byte(0xFF)
			if remaining < 255 {
				readLen = byte(remaining)
			}

			readResp, err := reader.ReadBinaryGSM(offset, readLen)
			if err != nil || !readResp.IsOK() {
				break
			}

			data = append(data, readResp.Data...)
			offset += uint16(len(readResp.Data))

			if len(readResp.Data) == 0 {
				break
			}
		}
	} else {
		data, err = reader.ReadAllBinary(fileSize)
		if err != nil {
			return "", nil, err
		}
	}

	return fmt.Sprintf("%X", data), data, nil
}

// readMSISDN reads MSISDN from linear fixed file
func readMSISDN(reader *card.Reader) (string, []byte) {
	// Select EF_MSISDN
	fid := []byte{0x6F, 0x40}

	var resp *card.APDUResponse
	var err error

	if UseGSMCommands {
		resp, err = reader.SelectGSM(fid)
	} else {
		resp, err = reader.Select(fid)
	}

	if err != nil || !resp.IsOK() {
		return "", nil
	}

	// Parse response to get record length
	var recordLen int

	if UseGSMCommands {
		// GSM response format: record length is at byte 14
		if len(resp.Data) >= 15 {
			recordLen = int(resp.Data[14])
		}
	} else {
		recordLen = parseFCPRecordSize(resp.Data)
	}

	if recordLen == 0 {
		recordLen = 34 // Default MSISDN record size
	}

	// Read first record
	if UseGSMCommands {
		resp, err = reader.ReadRecordGSM(1, byte(recordLen))
	} else {
		resp, err = reader.ReadRecord(1, byte(recordLen))
	}

	if err != nil || !resp.IsOK() {
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

// FileAccessInfo contains access conditions for a file
type FileAccessInfo struct {
	FileName    string
	FileID      string
	ReadAccess  string // e.g., "Always", "PIN1", "ADM1"
	WriteAccess string // e.g., "ADM2", "Never"
}

// parseFCPSecurityAttributes extracts security attributes from FCP template
// Returns read and write access conditions as human-readable strings
func parseFCPSecurityAttributes(fcp []byte) (readAccess, writeAccess string) {
	readAccess = "?"
	writeAccess = "?"

	if len(fcp) < 4 {
		return
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

		// Tag 8C: Compact Security Attributes
		if tag == 0x8C && length >= 2 {
			secData := fcp[idx+2 : idx+2+length]
			readAccess, writeAccess = parseCompactSecurityAttributes(secData)
			return
		}

		// Tag 8B: Security Attributes referencing EF_ARR
		// Format: file_id (2 bytes) + record_number (1 byte)
		if tag == 0x8B && length >= 3 {
			// Security is defined in EF_ARR
			// arrFileID := uint16(fcp[idx+2])<<8 | uint16(fcp[idx+3])
			arrRecordNum := fcp[idx+4]
			// Store ARR record number for later resolution
			readAccess = fmt.Sprintf("ARR#%d", arrRecordNum)
			writeAccess = fmt.Sprintf("ARR#%d", arrRecordNum)
			return
		}

		// Tag 86: Proprietary Security Attributes
		if tag == 0x86 {
			secData := fcp[idx+2 : idx+2+length]
			readAccess, writeAccess = parseProprietarySecurityAttributes(secData)
			return
		}

		// Tag AB: Expanded Security Attributes (less common)
		if tag == 0xAB && length >= 1 {
			secData := fcp[idx+2 : idx+2+length]
			readAccess, writeAccess = parseExpandedSecurityAttributes(secData)
			return
		}

		// Tag A5: Proprietary information (some cards put security here)
		if tag == 0xA5 {
			// Parse nested TLV inside A5
			nestedRead, nestedWrite := parseFCPSecurityAttributes(fcp[idx+2 : idx+2+length])
			if nestedRead != "?" {
				readAccess = nestedRead
				writeAccess = nestedWrite
				return
			}
		}

		idx += 2 + length
	}

	return
}

// parseCompactSecurityAttributes parses tag 8C content
// Format: Access Mode byte + Security Conditions for each active bit
func parseCompactSecurityAttributes(data []byte) (readAccess, writeAccess string) {
	if len(data) < 2 {
		return "?", "?"
	}

	accessMode := data[0]
	conditions := data[1:]

	// Count bits set in accessMode to know which conditions are present
	condIdx := 0

	// Bit 4 (0x10): UPDATE BINARY / WRITE
	// Bit 5 (0x20): READ BINARY / READ RECORD
	// Bit 6 (0x40): UPDATE RECORD

	for bit := 0; bit < 8; bit++ {
		if accessMode&(1<<bit) != 0 {
			if condIdx < len(conditions) {
				cond := conditions[condIdx]
				condStr := securityConditionToString(cond)

				switch bit {
				case 4: // UPDATE BINARY / WRITE
					writeAccess = condStr
				case 5: // READ
					readAccess = condStr
				case 6: // UPDATE RECORD (also write)
					if writeAccess == "?" {
						writeAccess = condStr
					}
				}
				condIdx++
			}
		}
	}

	if readAccess == "?" {
		readAccess = "Always"
	}
	if writeAccess == "?" {
		writeAccess = "Never"
	}

	return
}

// parseExpandedSecurityAttributes parses tag AB content (simplified)
func parseExpandedSecurityAttributes(data []byte) (readAccess, writeAccess string) {
	// Simplified: just return unknown for now
	// Full parsing would require handling AM-DO (tag 80) and SC-DO (tags A0, A4, AF, etc.)
	return "?", "?"
}

// parseProprietarySecurityAttributes parses tag 86 (Proprietary Security Attributes)
// Format varies by manufacturer, common format is sequence of condition bytes
func parseProprietarySecurityAttributes(data []byte) (readAccess, writeAccess string) {
	if len(data) == 0 {
		return "?", "?"
	}

	// Pattern 1: Direct sequence of conditions (7 or more bytes)
	// Position 4: UPDATE, Position 5: READ
	if len(data) >= 6 {
		// Try interpreting as: [op0][op1][op2][op3][UPDATE][READ]...
		readCond := data[5]  // READ position (index 5)
		writeCond := data[4] // UPDATE position (index 4)

		readAccess = securityConditionToString(readCond)
		writeAccess = securityConditionToString(writeCond)

		// Validate - if both are reasonable, return
		if isValidSecurityCondition(readCond) && isValidSecurityCondition(writeCond) {
			return
		}
	}

	// Pattern 2: Some cards use first bytes for READ/UPDATE
	if len(data) >= 2 {
		// Try first two bytes as UPDATE/READ
		writeCond := data[0]
		readCond := data[1]

		if isValidSecurityCondition(readCond) && isValidSecurityCondition(writeCond) {
			readAccess = securityConditionToString(readCond)
			writeAccess = securityConditionToString(writeCond)
			return
		}
	}

	// Pattern 3: Last resort - try to find ADM patterns in the data
	for _, b := range data {
		if b >= 0x0A && b <= 0x0D {
			// Found ADM reference, assume it's for write
			writeAccess = securityConditionToString(b)
			readAccess = "PIN1" // Common default
			return
		}
	}

	return "?", "?"
}

// isValidSecurityCondition checks if byte looks like a valid security condition
func isValidSecurityCondition(b byte) bool {
	// Always (00), Never (FF), PIN1-PIN8 (01-08), ADM1-ADM5 (0A-0E), Universal PIN (11)
	if b == 0x00 || b == 0xFF {
		return true
	}
	if b >= 0x01 && b <= 0x1F {
		return true
	}
	// OR/AND conditions
	if b >= 0x80 && b <= 0xAF {
		return true
	}
	return false
}

// securityConditionToString converts security condition byte to human-readable string
func securityConditionToString(cond byte) string {
	switch cond {
	case 0x00:
		return "Always"
	case 0xFF:
		return "Never"
	case 0x01:
		return "PIN1"
	case 0x02:
		return "PIN2"
	case 0x0A:
		return "ADM1"
	case 0x0B:
		return "ADM2"
	case 0x0C:
		return "ADM3"
	case 0x0D:
		return "ADM4"
	case 0x0E:
		return "ADM5"
	case 0x11:
		return "Universal PIN"
	default:
		if cond >= 0x01 && cond <= 0x1F {
			return fmt.Sprintf("PIN%d", cond)
		}
		if cond >= 0x80 && cond <= 0x8F {
			return fmt.Sprintf("OR(0x%02X)", cond)
		}
		if cond >= 0xA0 && cond <= 0xAF {
			return fmt.Sprintf("AND(0x%02X)", cond)
		}
		return fmt.Sprintf("0x%02X", cond)
	}
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

// DebugFCP controls whether to print raw FCP data
var DebugFCP = false

// ARRCache stores parsed ARR records for quick lookup
var ARRCache = make(map[int]ARRRecord)

// ARRRecord contains parsed access rules from EF_ARR
type ARRRecord struct {
	RecordNum   int
	ReadAccess  string
	WriteAccess string
	RawData     []byte
}

// ReadARR reads and parses EF_ARR (Access Rule Reference) file
func ReadARR(reader *card.Reader) {
	// Select EF_ARR (6F06)
	resp, err := reader.Select([]byte{0x6F, 0x06})
	if err != nil || !resp.IsOK() {
		return
	}

	// Get record size
	recordSize := parseFCPRecordSize(resp.Data)
	if recordSize == 0 {
		recordSize = 48 // Default
	}

	// Read all records
	for recNum := byte(1); recNum <= 30; recNum++ {
		recResp, err := reader.ReadRecord(recNum, byte(recordSize))
		if err != nil || !recResp.IsOK() {
			break
		}

		// Skip empty records
		if len(recResp.Data) == 0 || recResp.Data[0] == 0xFF {
			continue
		}

		readAcc, writeAcc := parseARRRecord(recResp.Data)
		ARRCache[int(recNum)] = ARRRecord{
			RecordNum:   int(recNum),
			ReadAccess:  readAcc,
			WriteAccess: writeAcc,
			RawData:     recResp.Data,
		}

		if DebugFCP {
			fmt.Printf("DEBUG ARR#%d: %X -> Read=%s, Write=%s\n", recNum, recResp.Data, readAcc, writeAcc)
		}
	}
}

// parseARRRecord parses a single ARR record
// ARR records contain pairs of [AM-DO (80)][SC-DO] for each access type
func parseARRRecord(data []byte) (readAccess, writeAccess string) {
	readAccess = "?"
	writeAccess = "?"

	if len(data) == 0 || data[0] == 0xFF {
		return
	}

	idx := 0
	for idx < len(data)-2 {
		if data[idx] == 0xFF {
			break
		}

		tag := data[idx]
		length := int(data[idx+1])
		if length == 0 || idx+2+length > len(data) {
			break
		}

		// Tag 80: Access Mode (AM-DO) - followed by Security Condition
		if tag == 0x80 && length > 0 {
			accessMode := data[idx+2]
			// Move to the security condition after AM-DO
			scIdx := idx + 2 + length
			if scIdx < len(data)-1 {
				scTag := data[scIdx]
				scLen := 0
				if scIdx+1 < len(data) {
					scLen = int(data[scIdx+1])
				}

				var cond string
				if scIdx+2+scLen <= len(data) {
					scValue := data[scIdx+2 : scIdx+2+scLen]
					cond = parseSecurityConditionDO(scTag, scValue)
				} else {
					cond = parseSecurityConditionDO(scTag, nil)
				}

				// Access mode bits (ETSI TS 102 221)
				// Bit 0 (0x01): READ/SEARCH
				// Bit 1 (0x02): UPDATE
				// Bit 2 (0x04): WRITE
				// Bit 3 (0x08): INCREASE
				// Bit 4 (0x10): REHABILITATE
				// Bit 5 (0x20): INVALIDATE
				// Bit 6 (0x40): Reserved
				// Bit 7 (0x80): Reserved
				// Alternative interpretation (common):
				// 0x01: READ, 0x02: UPDATE BINARY, 0x10: UPDATE RECORD, 0x40: UPDATE

				if accessMode == 0x01 { // READ
					if readAccess == "?" {
						readAccess = cond
					}
				}
				if accessMode&0x02 != 0 || accessMode&0x10 != 0 || accessMode&0x40 != 0 ||
					accessMode == 0x1A || accessMode == 0x18 { // UPDATE variants
					if writeAccess == "?" || writeAccess == "Never" {
						writeAccess = cond
					}
				}

				// Skip the SC-DO
				idx = scIdx + 2 + scLen
				continue
			}
		}

		// Tag 90: Always (no length byte follows)
		if tag == 0x90 {
			idx += 2 + length
			continue
		}

		// Tag 97: Never (00 length)
		if tag == 0x97 {
			idx += 2 + length
			continue
		}

		idx += 2 + length
	}

	// Default values if not found
	if readAccess == "?" {
		readAccess = "PIN1" // Default for most files
	}
	if writeAccess == "?" {
		writeAccess = "ADM" // Default write requires ADM
	}

	return
}

// parseSecurityConditionDO parses Security Condition DO
func parseSecurityConditionDO(tag byte, value []byte) string {
	switch tag {
	case 0x90: // Always (no data)
		return "Always"
	case 0x97: // Never (00 length)
		return "Never"
	case 0x9E: // User authentication (PIN/ADM reference)
		if len(value) > 0 {
			return securityConditionToString(value[0])
		}
	case 0xA0: // OR template
		return parseORTemplate(value)
	case 0xA4: // User authentication template
		// Format: A4 06 83 01 XX 95 01 08
		// Where XX is the PIN/ADM reference
		return parseA4Template(value)
	case 0xA7: // AND template
		return parseANDTemplate(value)
	case 0xAF: // Never
		return "Never"
	}
	return fmt.Sprintf("0x%02X", tag)
}

// parseA4Template parses A4 (User Authentication) template
// Common format: 83 01 XX 95 01 08 (where XX is PIN/ADM reference)
func parseA4Template(data []byte) string {
	idx := 0
	for idx < len(data)-2 {
		tag := data[idx]
		length := int(data[idx+1])
		if idx+2+length > len(data) {
			break
		}

		// Tag 83: Reference data qualifier (contains PIN/ADM number)
		if tag == 0x83 && length >= 1 {
			ref := data[idx+2]
			return securityConditionToString(ref)
		}

		idx += 2 + length
	}
	return "?"
}

// parseORTemplate parses OR condition template (A0)
// Contains multiple security conditions - any one can be satisfied
func parseORTemplate(data []byte) string {
	var conditions []string
	idx := 0
	for idx < len(data)-1 {
		tag := data[idx]
		length := int(data[idx+1])
		if idx+2+length > len(data) {
			break
		}
		value := data[idx+2 : idx+2+length]

		switch tag {
		case 0x9E: // Direct PIN reference
			if len(value) > 0 {
				conditions = append(conditions, securityConditionToString(value[0]))
			}
		case 0xA4: // User authentication template
			cond := parseA4Template(value)
			if cond != "?" {
				conditions = append(conditions, cond)
			}
		case 0x90: // Always
			conditions = append(conditions, "Always")
		}

		idx += 2 + length
	}

	if len(conditions) == 1 {
		return conditions[0]
	}
	if len(conditions) > 1 {
		// Return first meaningful condition (prefer PIN1 or ADM over others)
		for _, c := range conditions {
			if c == "PIN1" {
				return "PIN1"
			}
		}
		return conditions[0] + "/" + conditions[1]
	}
	return "?"
}

// parseANDTemplate parses AND condition template
func parseANDTemplate(data []byte) string {
	var conditions []string
	idx := 0
	for idx < len(data)-1 {
		tag := data[idx]
		length := int(data[idx+1])
		if idx+2+length > len(data) {
			break
		}
		value := data[idx+2 : idx+2+length]

		if tag == 0x9E && len(value) > 0 {
			conditions = append(conditions, securityConditionToString(value[0]))
		}
		idx += 2 + length
	}

	if len(conditions) == 1 {
		return conditions[0]
	}
	if len(conditions) > 1 {
		return conditions[0] + "&" + conditions[1]
	}
	return "?"
}

// ResolveARRReference resolves ARR#N to actual access conditions
func ResolveARRReference(access string) string {
	if len(access) > 4 && access[:4] == "ARR#" {
		var recNum int
		fmt.Sscanf(access, "ARR#%d", &recNum)
		if rec, ok := ARRCache[recNum]; ok {
			return rec.ReadAccess // or WriteAccess depending on context
		}
	}
	return access
}

// ReadFileAccessConditions reads access conditions for key USIM files
func ReadFileAccessConditions(reader *card.Reader) []FileAccessInfo {
	var access []FileAccessInfo

	// Select USIM first
	resp, err := reader.Select(GetUSIMAID())
	if err != nil || !resp.IsOK() {
		return access
	}

	// Read EF_ARR first to resolve ARR references
	ARRCache = make(map[int]ARRRecord) // Reset cache
	ReadARR(reader)

	// Re-select USIM after reading ARR
	reader.Select(GetUSIMAID())

	// Key files to check
	filesToCheck := []struct {
		id   []byte
		name string
	}{
		{[]byte{0x6F, 0x07}, "EF_IMSI"},
		{[]byte{0x6F, 0x46}, "EF_SPN"},
		{[]byte{0x6F, 0xAD}, "EF_AD"},
		{[]byte{0x6F, 0x38}, "EF_UST"},
		{[]byte{0x6F, 0x62}, "EF_HPLMNwACT"},
		{[]byte{0x6F, 0x61}, "EF_OPLMNwACT"},
		{[]byte{0x6F, 0x60}, "EF_PLMNwAcT"},
		{[]byte{0x6F, 0x7B}, "EF_FPLMN"},
		{[]byte{0x6F, 0x7E}, "EF_LOCI"},
		{[]byte{0x6F, 0xE3}, "EF_EPSLOCI"},
	}

	for _, f := range filesToCheck {
		resp, err := reader.Select(f.id)
		if err != nil || !resp.IsOK() {
			continue
		}

		if DebugFCP {
			fmt.Printf("DEBUG FCP %s: %X\n", f.name, resp.Data)
		}

		readAcc, writeAcc := parseFCPSecurityAttributes(resp.Data)

		// Resolve ARR references
		if len(readAcc) > 4 && readAcc[:4] == "ARR#" {
			var recNum int
			fmt.Sscanf(readAcc, "ARR#%d", &recNum)
			if rec, ok := ARRCache[recNum]; ok {
				readAcc = rec.ReadAccess
				writeAcc = rec.WriteAccess
			}
		}

		access = append(access, FileAccessInfo{
			FileName:    f.name,
			FileID:      fmt.Sprintf("%02X%02X", f.id[0], f.id[1]),
			ReadAccess:  readAcc,
			WriteAccess: writeAcc,
		})
	}

	return access
}

// ReadISIMFileAccessConditions reads access conditions for key ISIM files
func ReadISIMFileAccessConditions(reader *card.Reader) []FileAccessInfo {
	var access []FileAccessInfo

	// Select ISIM first
	resp, err := reader.Select(GetISIMAID())
	if err != nil || !resp.IsOK() {
		return access
	}

	// Read EF_ARR for ISIM
	isimARRCache := make(map[int]ARRRecord)
	// Try to read ISIM's ARR (might be at 6F06 too)
	arrResp, arrErr := reader.Select([]byte{0x6F, 0x06})
	if arrErr == nil && arrResp.IsOK() {
		recordSize := parseFCPRecordSize(arrResp.Data)
		if recordSize == 0 {
			recordSize = 48
		}
		for recNum := byte(1); recNum <= 20; recNum++ {
			recResp, err := reader.ReadRecord(recNum, byte(recordSize))
			if err != nil || !recResp.IsOK() {
				break
			}
			if len(recResp.Data) == 0 || recResp.Data[0] == 0xFF {
				continue
			}
			readAcc, writeAcc := parseARRRecord(recResp.Data)
			isimARRCache[int(recNum)] = ARRRecord{
				RecordNum:   int(recNum),
				ReadAccess:  readAcc,
				WriteAccess: writeAcc,
			}
			if DebugFCP {
				fmt.Printf("DEBUG ISIM ARR#%d: %X -> Read=%s, Write=%s\n", recNum, recResp.Data, readAcc, writeAcc)
			}
		}
		// Re-select ISIM
		reader.Select(GetISIMAID())
	}

	// Key ISIM files to check
	filesToCheck := []struct {
		id   []byte
		name string
	}{
		{[]byte{0x6F, 0x02}, "EF_IMPI"},
		{[]byte{0x6F, 0x03}, "EF_DOMAIN"},
		{[]byte{0x6F, 0x04}, "EF_IMPU"},
		{[]byte{0x6F, 0x07}, "EF_IST"},
		{[]byte{0x6F, 0x09}, "EF_PCSCF"},
	}

	for _, f := range filesToCheck {
		resp, err := reader.Select(f.id)
		if err != nil || !resp.IsOK() {
			continue
		}

		if DebugFCP {
			fmt.Printf("DEBUG FCP ISIM %s: %X\n", f.name, resp.Data)
		}

		readAcc, writeAcc := parseFCPSecurityAttributes(resp.Data)

		// Resolve ARR references from ISIM's ARR cache
		if len(readAcc) > 4 && readAcc[:4] == "ARR#" {
			var recNum int
			fmt.Sscanf(readAcc, "ARR#%d", &recNum)
			if rec, ok := isimARRCache[recNum]; ok {
				readAcc = rec.ReadAccess
				writeAcc = rec.WriteAccess
			}
		}

		access = append(access, FileAccessInfo{
			FileName:    f.name,
			FileID:      fmt.Sprintf("%02X%02X", f.id[0], f.id[1]),
			ReadAccess:  readAcc,
			WriteAccess: writeAcc,
		})
	}

	return access
}
