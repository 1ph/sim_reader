package sim

import (
	"fmt"
	"sim_reader/card"
)

// ISIMData contains all data read from ISIM application
type ISIMData struct {
	// IMS Identity
	IMPI   string   // IMS Private User Identity
	IMPU   []string // IMS Public User Identities (can be multiple)
	Domain string   // Home Network Domain Name

	// Network
	PCSCF []string // P-CSCF addresses

	// Services
	IST map[int]bool // ISIM Service Table

	// Administrative
	AdminData AdminData

	// Raw data for debugging
	RawFiles map[string][]byte

	// Status
	Available bool
}

// ReadISIM reads all ISIM application data
func ReadISIM(reader *card.Reader) (*ISIMData, error) {
	data := &ISIMData{
		RawFiles:  make(map[string][]byte),
		IMPU:      make([]string, 0),
		PCSCF:     make([]string, 0),
		Available: false,
	}

	// Select ISIM application
	// Try multiple methods:
	// 1. Select by detected AID
	// 2. Select by standard AID
	// 3. Select by File ID path (for cards that don't support AID selection)

	var resp *card.APDUResponse
	var err error
	isimSelected := false

	// Method 1: Try detected AID
	isimAID := GetISIMAID()
	resp, err = reader.Select(isimAID)
	if err == nil && resp.IsOK() {
		isimSelected = true
	}

	// Method 2: Try standard AID if detected failed
	if !isimSelected && len(DetectedISIM_AID) > 0 {
		resp, err = reader.Select(AID_ISIM)
		if err == nil && resp.IsOK() {
			isimSelected = true
		}
	}

	// Method 3: Try selecting by File ID path (for non-standard cards)
	// This is needed for cards that return 6D00 (Instruction not supported) for AID selection
	if !isimSelected && HasISIMPath() {
		// First select MF
		if UseGSMCommands {
			reader.SelectGSM([]byte{0x3F, 0x00})
			// Then select ISIM by File ID using GSM command
			resp, err = reader.SelectGSM(GetISIMPath())
		} else {
			reader.Select([]byte{0x3F, 0x00})
			// Then select ISIM by File ID
			resp, err = reader.SelectDF(GetISIMPath())
		}
		if err == nil && resp.IsOK() {
			isimSelected = true
		}
	}

	if !isimSelected {
		swStr := "unknown error"
		if resp != nil {
			swStr = card.SWToString(resp.SW())
		}
		return data, fmt.Errorf("ISIM not available: %s", swStr)
	}

	data.Available = true

	// Read IMPI (IMS Private User Identity)
	if _, raw, err := readEF(reader, 0x6F02); err == nil {
		data.IMPI = DecodeIMPI(raw)
		data.RawFiles["EF_IMPI"] = raw
	}

	// Read Home Network Domain Name
	if _, raw, err := readEF(reader, 0x6F03); err == nil {
		data.Domain = DecodeDomain(raw)
		data.RawFiles["EF_DOMAIN"] = raw
	}

	// Read IMPU (IMS Public User Identity) - linear fixed file, can have multiple records
	if impus, raw := readAllIMPU(reader); len(impus) > 0 {
		data.IMPU = impus
		data.RawFiles["EF_IMPU"] = raw
	}

	// Read P-CSCF addresses - linear fixed file
	if pcscfs, raw := readAllPCSCF(reader); len(pcscfs) > 0 {
		data.PCSCF = pcscfs
		data.RawFiles["EF_PCSCF"] = raw
	}

	// Read IST (ISIM Service Table)
	if _, raw, err := readEF(reader, 0x6F07); err == nil {
		data.IST = DecodeIST(raw)
		data.RawFiles["EF_IST"] = raw
	}

	// Read Administrative Data
	if _, raw, err := readEF(reader, 0x6FAD); err == nil {
		data.AdminData = DecodeAD(raw)
		data.RawFiles["EF_AD"] = raw
	}

	return data, nil
}

// readAllIMPU reads all IMPU records
func readAllIMPU(reader *card.Reader) ([]string, []byte) {
	var impus []string
	var allRaw []byte

	// Select EF_IMPU
	fid := []byte{0x6F, 0x04}

	var resp *card.APDUResponse
	var err error

	if UseGSMCommands {
		resp, err = reader.SelectGSM(fid)
	} else {
		resp, err = reader.Select(fid)
	}

	if err != nil || !resp.IsOK() {
		return impus, nil
	}

	// Get record size from response
	var recordLen int
	var numRecords int

	if UseGSMCommands {
		// GSM response format
		if len(resp.Data) >= 15 {
			recordLen = int(resp.Data[14])
			// Calculate number of records from file size
			fileSize := int(resp.Data[2])<<8 | int(resp.Data[3])
			if recordLen > 0 {
				numRecords = fileSize / recordLen
			}
		}
	} else {
		recordLen = parseFCPRecordSize(resp.Data)
		numRecords = parseFCPNumRecords(resp.Data)
	}

	if recordLen == 0 {
		recordLen = 128 // Default
	}
	if numRecords == 0 {
		numRecords = 5 // Try up to 5 records
	}

	// Read all records
	for i := byte(1); i <= byte(numRecords); i++ {
		var recResp *card.APDUResponse

		if UseGSMCommands {
			recResp, err = reader.ReadRecordGSM(i, byte(recordLen))
		} else {
			recResp, err = reader.ReadRecord(i, byte(recordLen))
		}

		if err != nil || !recResp.IsOK() {
			break
		}

		allRaw = append(allRaw, recResp.Data...)

		impu := DecodeIMPU(recResp.Data)
		if impu != "" && impu != string([]byte{0xFF}) {
			impus = append(impus, impu)
		}
	}

	return impus, allRaw
}

// readAllPCSCF reads all P-CSCF records
func readAllPCSCF(reader *card.Reader) ([]string, []byte) {
	var pcscfs []string
	var allRaw []byte

	// Select EF_PCSCF
	fid := []byte{0x6F, 0x09}

	var resp *card.APDUResponse
	var err error

	if UseGSMCommands {
		resp, err = reader.SelectGSM(fid)
	} else {
		resp, err = reader.Select(fid)
	}

	if err != nil || !resp.IsOK() {
		return pcscfs, nil
	}

	// Get record size from response
	var recordLen int
	var numRecords int

	if UseGSMCommands {
		// GSM response format
		if len(resp.Data) >= 15 {
			recordLen = int(resp.Data[14])
			// Calculate number of records from file size
			fileSize := int(resp.Data[2])<<8 | int(resp.Data[3])
			if recordLen > 0 {
				numRecords = fileSize / recordLen
			}
		}
	} else {
		recordLen = parseFCPRecordSize(resp.Data)
		numRecords = parseFCPNumRecords(resp.Data)
	}

	if recordLen == 0 {
		recordLen = 64 // Default
	}
	if numRecords == 0 {
		numRecords = 5 // Try up to 5 records
	}

	// Read all records
	for i := byte(1); i <= byte(numRecords); i++ {
		var recResp *card.APDUResponse

		if UseGSMCommands {
			recResp, err = reader.ReadRecordGSM(i, byte(recordLen))
		} else {
			recResp, err = reader.ReadRecord(i, byte(recordLen))
		}

		if err != nil || !recResp.IsOK() {
			break
		}

		allRaw = append(allRaw, recResp.Data...)

		// Skip empty records
		isEmpty := true
		for _, b := range recResp.Data {
			if b != 0xFF && b != 0x00 {
				isEmpty = false
				break
			}
		}
		if isEmpty {
			continue
		}

		pcscf := DecodePCSCF(recResp.Data)
		if pcscf != "" {
			pcscfs = append(pcscfs, pcscf)
		}
	}

	return pcscfs, allRaw
}

// parseFCPNumRecords extracts number of records from FCP template
func parseFCPNumRecords(fcp []byte) int {
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
			// File descriptor: byte0, coding, recLen(2), numRecords
			if length >= 5 {
				return int(fcp[idx+6])
			}
		}

		idx += 2 + length
	}

	return 0
}

// HasService checks if an IST service is available
func (i *ISIMData) HasService(serviceNum int) bool {
	if i.IST == nil {
		return false
	}
	return i.IST[serviceNum]
}

// HasPCSCF checks if P-CSCF address service is available
func (i *ISIMData) HasPCSCF() bool {
	return i.HasService(1)
}

// HasGBA checks if GBA is available
func (i *ISIMData) HasGBA() bool {
	return i.HasService(2)
}

// HasHTTPDigest checks if HTTP Digest is available
func (i *ISIMData) HasHTTPDigest() bool {
	return i.HasService(3)
}

// HasSMSOverIP checks if SMS over IP is available
func (i *ISIMData) HasSMSOverIP() bool {
	return i.HasService(7)
}

// HasVoiceDomainPreference checks if voice domain preference is available
func (i *ISIMData) HasVoiceDomainPreference() bool {
	return i.HasService(12)
}

// GetEnabledServices returns list of enabled service names
func (i *ISIMData) GetEnabledServices() []string {
	var services []string
	for num, enabled := range i.IST {
		if enabled {
			if name, ok := ISTServices[num]; ok {
				services = append(services, fmt.Sprintf("%d: %s", num, name))
			} else {
				services = append(services, fmt.Sprintf("%d: Unknown", num))
			}
		}
	}
	return services
}
