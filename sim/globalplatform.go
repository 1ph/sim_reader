package sim

import (
	"fmt"
	"sim_reader/card"
)

// GP AID for Issuer Security Domain
var GP_ISD_AID = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}

// Applet represents a GlobalPlatform applet/package
type Applet struct {
	AID       string
	RawAID    []byte
	State     string
	Privilege string
	Type      string // "App", "Package", "ISD"
}

// GP Life Cycle states
var gpStates = map[byte]string{
	0x01: "LOADED",
	0x03: "INSTALLED",
	0x07: "SELECTABLE",
	0x0F: "PERSONALIZED",
	0x7F: "LOCKED",
	0x83: "CARD_LOCKED",
	0xFF: "TERMINATED",
}

// GP Privileges
func decodePrivileges(priv byte) string {
	var privs []string
	if priv&0x80 != 0 {
		privs = append(privs, "Security Domain")
	}
	if priv&0x40 != 0 {
		privs = append(privs, "DAP Verification")
	}
	if priv&0x20 != 0 {
		privs = append(privs, "Delegated Management")
	}
	if priv&0x10 != 0 {
		privs = append(privs, "Card Lock")
	}
	if priv&0x08 != 0 {
		privs = append(privs, "Card Terminate")
	}
	if priv&0x04 != 0 {
		privs = append(privs, "Card Reset")
	}
	if priv&0x02 != 0 {
		privs = append(privs, "CVM Management")
	}
	if priv&0x01 != 0 {
		privs = append(privs, "Mandated DAP")
	}
	if len(privs) == 0 {
		return "-"
	}
	result := ""
	for i, p := range privs {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}

// ListApplets lists all applets on the card using GlobalPlatform GET STATUS
func ListApplets(reader *card.Reader) ([]Applet, error) {
	var applets []Applet

	// Try to select ISD (Issuer Security Domain)
	resp, err := reader.Select(GP_ISD_AID)
	if err != nil {
		return nil, fmt.Errorf("failed to select ISD: %w", err)
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		// Try alternative ISD AID
		altISD := []byte{0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}
		resp, err = reader.Select(altISD)
		if err != nil || (!resp.IsOK() && !resp.HasMoreData()) {
			return nil, fmt.Errorf("ISD not found (card may not support GlobalPlatform)")
		}
	}

	// GET STATUS for ISD (P1=0x80)
	isdApps, _ := getStatus(reader, 0x80)
	for _, a := range isdApps {
		a.Type = "ISD"
		applets = append(applets, a)
	}

	// GET STATUS for Applications (P1=0x40)
	apps, _ := getStatus(reader, 0x40)
	for _, a := range apps {
		a.Type = "App"
		applets = append(applets, a)
	}

	// GET STATUS for Executable Load Files (P1=0x20)
	pkgs, _ := getStatus(reader, 0x20)
	for _, a := range pkgs {
		a.Type = "Package"
		applets = append(applets, a)
	}

	// GET STATUS for Executable Load Files and Modules (P1=0x10)
	modules, _ := getStatus(reader, 0x10)
	for _, a := range modules {
		a.Type = "Module"
		applets = append(applets, a)
	}

	return applets, nil
}

// getStatus sends GET STATUS command
func getStatus(reader *card.Reader, p1 byte) ([]Applet, error) {
	var applets []Applet

	// GET STATUS: CLA=80, INS=F2, P1=type, P2=00 (first), data=4F00 (get all)
	// P2=01 for next occurrence
	p2 := byte(0x00)

	for {
		apdu := []byte{0x80, 0xF2, p1, p2, 0x02, 0x4F, 0x00, 0x00}
		resp, err := reader.SendAPDU(apdu)
		if err != nil {
			return applets, err
		}

		// Handle GET RESPONSE if needed
		if resp.HasMoreData() {
			resp, err = reader.GetResponse(resp.SW2)
			if err != nil {
				return applets, err
			}
		}

		if !resp.IsOK() && resp.SW() != 0x6310 {
			// 6310 = more data available
			break
		}

		// Parse TLV response
		parsed := parseGetStatusResponse(resp.Data)
		applets = append(applets, parsed...)

		// Check if more data available
		if resp.SW() == 0x6310 {
			p2 = 0x01 // Get next
		} else {
			break
		}
	}

	return applets, nil
}

// parseGetStatusResponse parses GET STATUS response TLV
func parseGetStatusResponse(data []byte) []Applet {
	var applets []Applet

	idx := 0
	for idx < len(data) {
		// Each entry: E3 Len [4F Len AID] [9F70 01 State] [C5 01 Priv]
		if data[idx] != 0xE3 {
			idx++
			continue
		}
		idx++
		if idx >= len(data) {
			break
		}

		entryLen := int(data[idx])
		idx++
		if idx+entryLen > len(data) {
			break
		}

		entry := data[idx : idx+entryLen]
		idx += entryLen

		app := parseAppletEntry(entry)
		if app != nil {
			applets = append(applets, *app)
		}
	}

	return applets
}

// parseAppletEntry parses single applet entry
func parseAppletEntry(data []byte) *Applet {
	app := &Applet{}

	idx := 0
	for idx < len(data) {
		tag := data[idx]
		idx++
		if idx >= len(data) {
			break
		}

		// Handle 2-byte tags
		if tag == 0x9F {
			if idx >= len(data) {
				break
			}
			tag = data[idx]
			idx++
			if tag == 0x70 { // 9F70 = Life Cycle State
				if idx >= len(data) {
					break
				}
				length := int(data[idx])
				idx++
				if idx+length > len(data) || length < 1 {
					break
				}
				state := data[idx]
				if s, ok := gpStates[state]; ok {
					app.State = s
				} else {
					app.State = fmt.Sprintf("0x%02X", state)
				}
				idx += length
				continue
			}
		}

		if idx >= len(data) {
			break
		}
		length := int(data[idx])
		idx++
		if idx+length > len(data) {
			break
		}
		value := data[idx : idx+length]
		idx += length

		switch tag {
		case 0x4F: // AID
			app.RawAID = value
			app.AID = fmt.Sprintf("%X", value)
		case 0xC5: // Privileges
			if len(value) > 0 {
				app.Privilege = decodePrivileges(value[0])
			}
		case 0xCF: // GP Registry-related data
			// Skip
		case 0xC4: // Associated Security Domain AID
			// Skip
		}
	}

	if app.AID == "" {
		return nil
	}

	return app
}

// IdentifyAppletByAID identifies known applet types by AID
func IdentifyAppletByAID(aid string) string {
	// Common AIDs
	knownAIDs := map[string]string{
		"A0000000871002":     "USIM (3GPP)",
		"A0000000871004":     "ISIM (3GPP)",
		"A000000003000000":   "Visa",
		"A0000000041010":     "MasterCard",
		"A0000001510000":     "GlobalPlatform ISD",
		"D276000118":         "TUAK Auth",
		"A0000005591010":     "JCOP Identify",
	}

	for prefix, name := range knownAIDs {
		if len(aid) >= len(prefix) && aid[:len(prefix)] == prefix {
			return name
		}
	}

	return ""
}

