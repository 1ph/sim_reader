package sim

import (
	"encoding/hex"
	"fmt"
	"sim_reader/card"
	"sim_reader/dictionaries"
	"strings"
)

// CardInfo contains basic card information
type CardInfo struct {
	ATR           string
	ICCID         string
	Applications  []ApplicationInfo
	GSMAvailable  bool
	GSMData       *GSMData
	RawDIR        []byte
	IsProprietary bool                    // Card uses File ID selection instead of AID
	UsesGSMClass  bool                    // Card requires GSM class commands (CLA=A0)
	ADMStatus     map[string]card.ADMInfo // Status of ADM keys
	ATRInfo       *card.ATRInfo           // Detailed ATR analysis
}

// ApplicationInfo describes an application on the card
type ApplicationInfo struct {
	AID   string
	Label string
	Type  string
	Path  string // File ID path for cards that don't support AID selection (e.g., "7FF0")
}

// GSMData contains data read from GSM (2G) SIM
type GSMData struct {
	IMSI    string
	SPN     string
	MSISDN  string
	HPLMN   string
	FPLMN   []string
	RawIMSI []byte
}

// DetectApplicationAIDs reads EF_DIR and sets detected AIDs and paths for USIM/ISIM
// This should be called before ReadUSIM/ReadISIM for non-standard cards
func DetectApplicationAIDs(reader *card.Reader) {
	apps, _ := readApplicationDirectory(reader)
	for _, app := range apps {
		aidBytes, _ := hex.DecodeString(app.AID)
		pathBytes, _ := hex.DecodeString(app.Path)

		if len(aidBytes) >= 7 {
			// Check for 3GPP RID: A0 00 00 00 87
			// This distinguishes USIM/ISIM from CSIM (A0 00 00 03 43)
			is3GPP := aidBytes[0] == 0xA0 && aidBytes[1] == 0x00 &&
				aidBytes[2] == 0x00 && aidBytes[3] == 0x00 && aidBytes[4] == 0x87

			if is3GPP {
				// Check if it's USIM (3GPP RID + app code 1002)
				if aidBytes[5] == 0x10 && aidBytes[6] == 0x02 {
					DetectedUSIM_AID = aidBytes
					if len(pathBytes) >= 2 {
						DetectedUSIM_Path = pathBytes
					}
				}
				// Check if it's ISIM (3GPP RID + app code 1004)
				if aidBytes[5] == 0x10 && aidBytes[6] == 0x04 {
					DetectedISIM_AID = aidBytes
					if len(pathBytes) >= 2 {
						DetectedISIM_Path = pathBytes
					}
				}
			}
		}
	}

	// For proprietary cards that don't expose EF_DIR properly, set default DF paths
	// so that other operations (writes, auth algo read/write) can still select ADFs.
	if IsProprietaryCard(reader.ATRHex()) && len(apps) == 0 {
		if len(DetectedUSIM_Path) == 0 {
			DetectedUSIM_Path = []byte{0x7F, 0xF0}
		}
		if len(DetectedISIM_Path) == 0 {
			DetectedISIM_Path = []byte{0x7F, 0xF2}
		}
	}
}

// AnalyzeCard performs comprehensive card analysis
// checkADM: if true, checks ADM key slots status (sends VERIFY with Lc=0)
func AnalyzeCard(reader *card.Reader, checkADM bool) (*CardInfo, error) {
	info := &CardInfo{
		ATR: reader.ATRHex(),
	}

	// Detailed ATR analysis
	info.ATRInfo, _ = card.DecodeATR(reader.ATR())

	// Detect card driver
	drv := FindDriver(reader)
	if drv != nil {
		info.UsesGSMClass = (drv.BaseCLA() == 0xA0)
		info.IsProprietary = true // Any programmable driver is considered proprietary here
	} else {
		info.UsesGSMClass = IsGSMOnlyCard(info.ATR)
		info.IsProprietary = IsProprietaryCard(info.ATR)
	}

	// Set global flag for other packages to use
	UseGSMCommands = info.UsesGSMClass

	// Try to read ICCID from MF (works on all cards)
	iccid, err := readICCIDWithGSMFallback(reader, info.UsesGSMClass)
	if err == nil {
		info.ICCID = iccid
	}

	// Detailed ATR analysis
	info.ATRInfo, _ = card.DecodeATR(reader.ATR())

	// Try to read EF_DIR to find applications
	apps, rawDir := readApplicationDirectoryWithGSMFallback(reader, info.UsesGSMClass)
	info.Applications = apps
	info.RawDIR = rawDir

	// Store detected AIDs and paths for later use
	for _, app := range apps {
		aidBytes, _ := hex.DecodeString(app.AID)
		pathBytes, _ := hex.DecodeString(app.Path)

		if len(aidBytes) >= 7 {
			// Check for 3GPP RID: A0 00 00 00 87
			// This distinguishes USIM/ISIM from CSIM (A0 00 00 03 43)
			is3GPP := aidBytes[0] == 0xA0 && aidBytes[1] == 0x00 &&
				aidBytes[2] == 0x00 && aidBytes[3] == 0x00 && aidBytes[4] == 0x87

			if is3GPP {
				// Check if it's USIM (3GPP RID + app code 1002)
				if aidBytes[5] == 0x10 && aidBytes[6] == 0x02 {
					DetectedUSIM_AID = aidBytes
					if len(pathBytes) >= 2 {
						DetectedUSIM_Path = pathBytes
					}
				}
				// Check if it's ISIM (3GPP RID + app code 1004)
				if aidBytes[5] == 0x10 && aidBytes[6] == 0x04 {
					DetectedISIM_AID = aidBytes
					if len(pathBytes) >= 2 {
						DetectedISIM_Path = pathBytes
					}
				}
			}
		}
	}

	// For cards without EF_DIR entries, set default paths
	if info.IsProprietary && len(info.Applications) == 0 {
		DetectedUSIM_Path = []byte{0x7F, 0xF0}
		DetectedISIM_Path = []byte{0x7F, 0xF2}
	}

	// Try GSM (2G) access
	gsmData, err := readGSMSIMWithFallback(reader, info.UsesGSMClass)
	if err == nil && gsmData != nil {
		info.GSMAvailable = true
		info.GSMData = gsmData
	}

	// Check available ADM levels (only if requested - sends VERIFY with Lc=0)
	if checkADM {
		info.ADMStatus = reader.GetAllADMStatus()
	}

	return info, nil
}

// readApplicationDirectory reads EF_DIR to list all applications
func readApplicationDirectory(reader *card.Reader) ([]ApplicationInfo, []byte) {
	return readApplicationDirectoryWithGSMFallback(reader, false)
}

// readApplicationDirectoryWithGSMFallback reads EF_DIR with GSM command fallback
func readApplicationDirectoryWithGSMFallback(reader *card.Reader, useGSM bool) ([]ApplicationInfo, []byte) {
	var apps []ApplicationInfo
	var rawData []byte

	// Select MF first
	if useGSM {
		reader.SelectGSM([]byte{0x3F, 0x00})
	} else {
		reader.Select([]byte{0x3F, 0x00})
	}

	// Select EF_DIR (2F00)
	var resp *card.APDUResponse
	var err error

	if useGSM {
		resp, err = reader.SelectGSM([]byte{0x2F, 0x00})
	} else {
		resp, err = reader.Select([]byte{0x2F, 0x00})
	}

	// If standard method fails, try GSM fallback
	if (err != nil || !resp.IsOK()) && !useGSM {
		resp, err = reader.SelectGSM([]byte{0x2F, 0x00})
		if err == nil && resp.IsOK() {
			useGSM = true // Switch to GSM mode for reading
		}
	}

	if err != nil || !resp.IsOK() {
		return apps, nil
	}

	// Get record length from response if available (for GSM response format)
	recordLen := byte(48) // Default for EF_DIR
	if len(resp.Data) >= 15 {
		// GSM response format: bytes 14-15 contain record length
		if resp.Data[13] > 0 && resp.Data[13] < 128 {
			recordLen = resp.Data[13]
		}
	}

	// EF_DIR is a linear fixed file, read records
	for recNum := byte(1); recNum <= 10; recNum++ {
		var recResp *card.APDUResponse

		if useGSM {
			recResp, err = reader.ReadRecordGSM(recNum, recordLen)
		} else {
			recResp, err = reader.ReadRecord(recNum, 0x00) // 0x00 = let card tell us the size
			if err != nil {
				// Try with specific size
				recResp, err = reader.ReadRecord(recNum, 64)
			}
		}

		if err != nil || !recResp.IsOK() {
			break
		}

		rawData = append(rawData, recResp.Data...)

		// Parse application template (tag 61)
		app := parseApplicationTemplate(recResp.Data)
		if app.AID != "" {
			apps = append(apps, app)
		}
	}

	return apps, rawData
}

// readICCIDWithGSMFallback reads ICCID with GSM command fallback
func readICCIDWithGSMFallback(reader *card.Reader, useGSM bool) (string, error) {
	// Select MF first
	if useGSM {
		reader.SelectGSM([]byte{0x3F, 0x00})
	} else {
		reader.Select([]byte{0x3F, 0x00})
	}

	// Select EF_ICCID (2FE2)
	var resp *card.APDUResponse
	var err error

	if useGSM {
		resp, err = reader.SelectGSM([]byte{0x2F, 0xE2})
	} else {
		resp, err = reader.Select([]byte{0x2F, 0xE2})
	}

	// If standard method fails, try GSM fallback
	if (err != nil || !resp.IsOK()) && !useGSM {
		resp, err = reader.SelectGSM([]byte{0x2F, 0xE2})
		if err == nil && resp.IsOK() {
			useGSM = true
		}
	}

	if err != nil || !resp.IsOK() {
		return "", fmt.Errorf("select failed")
	}

	// Read binary
	if useGSM {
		resp, err = reader.ReadBinaryGSM(0, 10)
	} else {
		resp, err = reader.ReadBinary(0, 10)
	}

	if err != nil || !resp.IsOK() {
		return "", fmt.Errorf("read failed")
	}

	return DecodeICCID(resp.Data), nil
}

// readGSMSIMWithFallback reads GSM SIM data with fallback
func readGSMSIMWithFallback(reader *card.Reader, useGSM bool) (*GSMData, error) {
	data := &GSMData{}

	// Select MF
	var resp *card.APDUResponse
	var err error

	if useGSM {
		resp, err = reader.SelectGSM([]byte{0x3F, 0x00})
	} else {
		resp, err = reader.Select([]byte{0x3F, 0x00})
	}
	if err != nil || !resp.IsOK() {
		return nil, fmt.Errorf("cannot select MF")
	}

	// Select DF_GSM (7F20)
	if useGSM {
		resp, err = reader.SelectGSM([]byte{0x7F, 0x20})
	} else {
		resp, err = reader.Select([]byte{0x7F, 0x20})
	}

	// Try GSM fallback if standard fails
	if (err != nil || !resp.IsOK()) && !useGSM {
		resp, err = reader.SelectGSM([]byte{0x7F, 0x20})
		if err == nil && resp.IsOK() {
			useGSM = true
		}
	}

	if err != nil || !resp.IsOK() {
		return nil, fmt.Errorf("DF_GSM not found")
	}

	// Read EF_IMSI (6F07)
	if useGSM {
		resp, err = reader.SelectGSM([]byte{0x6F, 0x07})
	} else {
		resp, err = reader.Select([]byte{0x6F, 0x07})
	}

	if err == nil && resp.IsOK() {
		var imsiData []byte
		if useGSM {
			imsiResp, _ := reader.ReadBinaryGSM(0, 9)
			if imsiResp != nil && imsiResp.IsOK() {
				imsiData = imsiResp.Data
			}
		} else {
			imsiData, _ = reader.ReadAllBinary(9)
		}

		if len(imsiData) > 0 {
			data.IMSI = DecodeIMSI(imsiData)
			data.RawIMSI = imsiData
			if len(data.IMSI) >= 5 {
				data.HPLMN = data.IMSI[:5]
			}
		}
	}

	// Read EF_SPN (6F46)
	if useGSM {
		resp, err = reader.SelectGSM([]byte{0x6F, 0x46})
	} else {
		resp, err = reader.Select([]byte{0x6F, 0x46})
	}

	if err == nil && resp.IsOK() {
		var spnData []byte
		if useGSM {
			spnResp, _ := reader.ReadBinaryGSM(0, 17)
			if spnResp != nil && spnResp.IsOK() {
				spnData = spnResp.Data
			}
		} else {
			spnData, _ = reader.ReadAllBinary(17)
		}

		if len(spnData) > 0 {
			data.SPN = DecodeSPN(spnData)
		}
	}

	if data.IMSI == "" && data.SPN == "" {
		return nil, fmt.Errorf("no GSM data found")
	}

	return data, nil
}

// parseApplicationTemplate parses a single EF_DIR record
func parseApplicationTemplate(data []byte) ApplicationInfo {
	app := ApplicationInfo{}

	idx := 0
	for idx < len(data) {
		if data[idx] == 0xFF {
			break // End of data
		}

		tag := data[idx]
		if idx+1 >= len(data) {
			break
		}
		length := int(data[idx+1])
		if idx+2+length > len(data) {
			break
		}
		value := data[idx+2 : idx+2+length]

		switch tag {
		case 0x61: // Application template
			// Parse nested TLV
			return parseApplicationTemplate(value)
		case 0x4F: // AID
			app.AID = hex.EncodeToString(value)
			app.Type = identifyAID(value)
		case 0x50: // Application label
			app.Label = strings.TrimRight(string(value), "\x00\xFF")
		case 0x51: // Path (discretionary data containing DF path)
			// Store path as hex for fallback selection
			if len(value) >= 2 {
				app.Path = hex.EncodeToString(value)
			}
		}

		idx += 2 + length
	}

	return app
}

// identifyAID identifies the application type from AID
func identifyAID(aid []byte) string {
	aidHex := strings.ToUpper(hex.EncodeToString(aid))

	// Known AIDs
	knownAIDs := map[string]string{
		"A0000000871002": "USIM (3GPP)",
		"A0000000871004": "ISIM (3GPP)",
		"A000000087":     "3GPP",
		"A0000000030000": "Visa",
		"A0000000040000": "MasterCard",
		"A00000006510":   "JCOP",
		"D276000085":     "NFC Forum",
		"D27600011800":   "TUAK (3GPP Auth)",
		"D276000118":     "TUAK JavaCard",
	}

	for prefix, name := range knownAIDs {
		if strings.HasPrefix(aidHex, prefix) {
			return name
		}
	}

	// Check for 3GPP RID
	if strings.HasPrefix(aidHex, "A000000087") {
		appCode := ""
		if len(aid) >= 6 {
			appCode = aidHex[10:14]
		}
		switch appCode {
		case "1002":
			return "USIM"
		case "1004":
			return "ISIM"
		case "1001":
			return "GSM"
		case "1003":
			return "USIM Toolkit"
		case "1005":
			return "Contactless"
		default:
			return fmt.Sprintf("3GPP App (code: %s)", appCode)
		}
	}

	return "Unknown"
}

// readGSMSIM tries to read data as 2G GSM SIM (without USIM app)
func readGSMSIM(reader *card.Reader) (*GSMData, error) {
	data := &GSMData{}

	// Select MF
	resp, err := reader.Select([]byte{0x3F, 0x00})
	if err != nil || !resp.IsOK() {
		return nil, fmt.Errorf("cannot select MF")
	}

	// Select DF_GSM (7F20)
	resp, err = reader.Select([]byte{0x7F, 0x20})
	if err != nil || !resp.IsOK() {
		return nil, fmt.Errorf("DF_GSM not found")
	}

	// Read EF_IMSI (6F07)
	resp, err = reader.Select([]byte{0x6F, 0x07})
	if err == nil && resp.IsOK() {
		imsiData, err := reader.ReadAllBinary(9)
		if err == nil {
			data.IMSI = DecodeIMSI(imsiData)
			data.RawIMSI = imsiData
			// Extract HPLMN from IMSI
			if len(data.IMSI) >= 5 {
				data.HPLMN = data.IMSI[:5]
			}
		}
	}

	// Read EF_SPN (6F46)
	resp, err = reader.Select([]byte{0x6F, 0x46})
	if err == nil && resp.IsOK() {
		spnData, err := reader.ReadAllBinary(17)
		if err == nil {
			data.SPN = DecodeSPN(spnData)
		}
	}

	// Read EF_FPLMN (6F7B)
	resp, err = reader.Select([]byte{0x6F, 0x7B})
	if err == nil && resp.IsOK() {
		fplmnData, err := reader.ReadAllBinary(12)
		if err == nil {
			data.FPLMN = DecodePLMNList(fplmnData)
		}
	}

	// Check if we got any useful data
	if data.IMSI == "" && data.SPN == "" {
		return nil, fmt.Errorf("no GSM data found")
	}

	return data, nil
}

// TrySelectApplication attempts to select an application by AID
func TrySelectApplication(reader *card.Reader, aid []byte) (*card.APDUResponse, error) {
	return reader.Select(aid)
}

// IdentifyCardByATR identifies card type based on ATR using embedded dictionary
func IdentifyCardByATR(atr string) string {
	atr = strings.ToUpper(atr)

	// Use embedded ATR dictionary for identification
	if cardType := dictionaries.LookupATRFirst(atr); cardType != "" {
		return cardType
	}

	return "Unknown card type"
}

// IsProprietaryCard checks if the card uses File ID selection instead of AID
func IsProprietaryCard(atr string) bool {
	// We'll use the driver registry to determine this
	// But since we only have ATR string here, we might need a dummy reader or change the signature
	// For now, let's keep the prefixes here or move them to a central place.
	// Actually, the goal is to MOVE them to drivers.
	
	// Let's check if any registered driver identifies this card
	// Note: AnalyzeCard is called with a real reader, so we can use it there.
	return strings.HasPrefix(strings.ToUpper(atr), "3B9596")
}

// IsGSMOnlyCard checks if the card requires GSM class commands (CLA=A0)
func IsGSMOnlyCard(atr string) bool {
	// RuSIM and GRv2 use GSM class
	atr = strings.ToUpper(atr)
	if strings.HasPrefix(atr, "3B9596") { // RuSIM
		return true
	}
	// GRv2 patterns
	grv2 := []string{
		"3B9F95801FC78031A073B6A10067CF3211B252C679",
		"3B9F94801FC38031A073B6A10067CF3210DF0EF5",
		"3B9F94801FC38031A073B6A10067CF3250DF0E72",
	}
	for _, p := range grv2 {
		if strings.HasPrefix(atr, p) {
			return true
		}
	}
	return false
}
