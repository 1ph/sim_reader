package sim

import (
	"encoding/hex"
	"fmt"
	"sim_reader/card"
	"strings"
)

// CardInfo contains basic card information
type CardInfo struct {
	ATR          string
	ICCID        string
	Applications []ApplicationInfo
	GSMAvailable bool
	GSMData      *GSMData
	RawDIR       []byte
}

// ApplicationInfo describes an application on the card
type ApplicationInfo struct {
	AID   string
	Label string
	Type  string
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

// DetectApplicationAIDs reads EF_DIR and sets detected AIDs for USIM/ISIM
// This should be called before ReadUSIM/ReadISIM for non-standard cards
func DetectApplicationAIDs(reader *card.Reader) {
	apps, _ := readApplicationDirectory(reader)
	for _, app := range apps {
		aidBytes, _ := hex.DecodeString(app.AID)
		if len(aidBytes) >= 7 {
			// Check if it's USIM (starts with A0000000871002)
			if aidBytes[0] == 0xA0 && aidBytes[5] == 0x10 && aidBytes[6] == 0x02 {
				DetectedUSIM_AID = aidBytes
			}
			// Check if it's ISIM (starts with A0000000871004)
			if aidBytes[0] == 0xA0 && aidBytes[5] == 0x10 && aidBytes[6] == 0x04 {
				DetectedISIM_AID = aidBytes
			}
		}
	}
}

// AnalyzeCard performs comprehensive card analysis
func AnalyzeCard(reader *card.Reader) (*CardInfo, error) {
	info := &CardInfo{
		ATR: reader.ATRHex(),
	}

	// Try to read ICCID from MF (works on all cards)
	iccid, err := readICCID(reader)
	if err == nil {
		info.ICCID = iccid
	}

	// Try to read EF_DIR to find applications
	apps, rawDir := readApplicationDirectory(reader)
	info.Applications = apps
	info.RawDIR = rawDir

	// Store detected AIDs for later use
	for _, app := range apps {
		aidBytes, _ := hex.DecodeString(app.AID)
		if len(aidBytes) >= 7 {
			// Check if it's USIM (starts with A0000000871002)
			if aidBytes[0] == 0xA0 && aidBytes[5] == 0x10 && aidBytes[6] == 0x02 {
				DetectedUSIM_AID = aidBytes
			}
			// Check if it's ISIM (starts with A0000000871004)
			if aidBytes[0] == 0xA0 && aidBytes[5] == 0x10 && aidBytes[6] == 0x04 {
				DetectedISIM_AID = aidBytes
			}
		}
	}

	// Try GSM (2G) access
	gsmData, err := readGSMSIM(reader)
	if err == nil && gsmData != nil {
		info.GSMAvailable = true
		info.GSMData = gsmData
	}

	return info, nil
}

// readApplicationDirectory reads EF_DIR to list all applications
func readApplicationDirectory(reader *card.Reader) ([]ApplicationInfo, []byte) {
	var apps []ApplicationInfo
	var rawData []byte

	// Select MF first
	reader.Select([]byte{0x3F, 0x00})

	// Select EF_DIR (2F00)
	resp, err := reader.Select([]byte{0x2F, 0x00})
	if err != nil || !resp.IsOK() {
		return apps, nil
	}

	// EF_DIR is a linear fixed file, read records
	for recNum := byte(1); recNum <= 10; recNum++ {
		resp, err := reader.ReadRecord(recNum, 0x00) // 0x00 = let card tell us the size
		if err != nil {
			// Try with specific size
			resp, err = reader.ReadRecord(recNum, 64)
		}
		if err != nil || !resp.IsOK() {
			break
		}

		rawData = append(rawData, resp.Data...)

		// Parse application template (tag 61)
		app := parseApplicationTemplate(resp.Data)
		if app.AID != "" {
			apps = append(apps, app)
		}
	}

	return apps, rawData
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

// ParseATR provides basic ATR analysis
func ParseATR(atr []byte) map[string]string {
	info := make(map[string]string)

	if len(atr) < 2 {
		return info
	}

	// TS byte
	switch atr[0] {
	case 0x3B:
		info["Convention"] = "Direct"
	case 0x3F:
		info["Convention"] = "Inverse"
	}

	// Historical bytes (simplified)
	if len(atr) > 2 {
		histLen := atr[1] & 0x0F
		if int(histLen) <= len(atr)-2 {
			histStart := len(atr) - int(histLen) - 1 // -1 for TCK
			if histStart > 0 && histStart < len(atr) {
				histBytes := atr[histStart : len(atr)-1]
				// Try to extract readable text
				var text strings.Builder
				for _, b := range histBytes {
					if b >= 0x20 && b < 0x7F {
						text.WriteByte(b)
					}
				}
				if text.Len() > 0 {
					info["Historical"] = text.String()
				}
			}
		}
	}

	return info
}

// Known card types based on ATR patterns
func IdentifyCardByATR(atr string) string {
	atr = strings.ToUpper(atr)

	// Check patterns in order: more specific (longer) patterns first!
	// This is important because map iteration order is not guaranteed

	// NovaCard - contains "676F" marker
	if strings.Contains(atr, "676F") || strings.Contains(atr, "676FA5") {
		return "NovaCard"
	}

	// Giesecke+Devrient (G+D) - contains "574A" (WJ) marker
	if strings.Contains(atr, "574A") {
		return "Giesecke+Devrient (G+D)"
	}

	// Sysmocom SJA5 - contains "674A35" marker (gJ5)
	if strings.Contains(atr, "674A35") {
		return "Sysmocom sysmoISIM-SJA5"
	}

	// Common ATR patterns
	patterns := []struct {
		prefix string
		name   string
	}{
		// Sysmocom (by ATR prefix)
		{"3B9F96801F878031E073FE211B674A35", "Sysmocom sysmoISIM-SJA5"},
		{"3B9F96801FC78031A073", "Sysmocom sysmoUSIM-SJS1"},
		{"3B9F96801FC7", "Sysmocom sysmoUSIM-SJS1"},
		{"3B9F97801FC7", "Sysmocom sysmoUSIM-SJS1 4FF"},

		// G+D StarSign
		{"3BBF11008131FE45455041", "G+D StarSign"},

		// Thales/Gemalto
		{"3B9F95801FC3", "Thales/Gemalto"},

		// Generic
		{"3B3F9600", "Basic SIM"},
	}

	for _, p := range patterns {
		if strings.HasPrefix(atr, p.prefix) {
			return p.name
		}
	}

	return "Unknown card type"
}
