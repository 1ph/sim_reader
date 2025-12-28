package output

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"sim_reader/sim"
)

// Color styles
var (
	colorHeader  = text.Colors{text.FgCyan, text.Bold}
	colorLabel   = text.Colors{text.FgYellow}
	colorValue   = text.Colors{text.FgWhite}
	colorSuccess = text.Colors{text.FgGreen}
	colorError   = text.Colors{text.FgRed}
	colorWarn    = text.Colors{text.FgYellow}

	// Access level colors
	colorPIN1   = text.Colors{text.FgGreen}
	colorADM1   = text.Colors{text.FgCyan}
	colorADM2   = text.Colors{text.FgYellow}
	colorADM3   = text.Colors{text.FgMagenta}
	colorADM4   = text.Colors{text.FgRed}
	colorAlways = text.Colors{text.FgHiGreen}
	colorNever  = text.Colors{text.FgHiRed}
)

// getTableStyle returns the default table style
func getTableStyle() table.Style {
	style := table.StyleRounded
	style.Color.Header = colorHeader
	style.Color.Row = text.Colors{text.FgWhite}
	style.Color.RowAlternate = text.Colors{text.FgHiWhite}
	style.Options.SeparateRows = false
	return style
}

// newTable creates a new table writer with default settings
func newTable() table.Writer {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(getTableStyle())
	t.Style().Options.SeparateRows = false
	return t
}

// PrintUSIMData prints all USIM data in a nice table format
func PrintUSIMData(data *sim.USIMData) {
	// Main info table
	fmt.Println()
	t := newTable()
	t.SetTitle("SIM CARD INFORMATION (USIM)")
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 20},
		{Number: 2, Colors: colorValue, WidthMin: 50},
	})

	t.AppendRow(table.Row{"ICCID", data.ICCID})
	t.AppendRow(table.Row{"IMSI", data.IMSI})
	if data.MSISDN != "" {
		t.AppendRow(table.Row{"MSISDN", data.MSISDN})
	}
	if data.SPN != "" {
		t.AppendRow(table.Row{"Service Provider", data.SPN})
	}
	t.Render()

	// Network info table
	fmt.Println()
	t2 := newTable()
	t2.SetTitle("NETWORK INFORMATION")
	t2.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 20},
		{Number: 2, Colors: colorValue, WidthMin: 50},
	})

	t2.AppendRow(table.Row{"MCC", data.MCC})
	t2.AppendRow(table.Row{"MNC", data.MNC})
	if data.Country != "" {
		t2.AppendRow(table.Row{"Country", data.Country})
	}
	if data.Operator != "" {
		t2.AppendRow(table.Row{"Operator", data.Operator})
	}
	t2.AppendRow(table.Row{"UE Mode", data.AdminData.UEMode})
	if len(data.ACC) > 0 {
		accStr := ""
		for i, acc := range data.ACC {
			if i > 0 {
				accStr += ", "
			}
			accStr += fmt.Sprintf("%d", acc)
		}
		t2.AppendRow(table.Row{"Access Classes", accStr})
	}
	if len(data.Languages) > 0 {
		t2.AppendRow(table.Row{"Languages (EF_LI)", strings.Join(data.Languages, ", ")})
	}
	if data.HPLMNPeriod > 0 {
		t2.AppendRow(table.Row{"HPLMN Search Period", fmt.Sprintf("%d min", data.HPLMNPeriod)})
	}
	t2.Render()

	// Location Information
	hasLocation := data.LOCI != nil || data.PSLOCI != nil || data.EPSLOCI != nil
	if hasLocation {
		fmt.Println()
		tLoc := newTable()
		tLoc.SetTitle("LOCATION INFORMATION")
		tLoc.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 20},
			{Number: 2, Colors: colorValue, WidthMin: 50},
		})

		if data.LOCI != nil {
			tLoc.AppendRow(table.Row{"CS Domain (EF_LOCI)", ""})
			tLoc.AppendRow(table.Row{"  TMSI", data.LOCI.TMSI})
			tLoc.AppendRow(table.Row{"  LAI", data.LOCI.LAI})
			tLoc.AppendRow(table.Row{"  Status", data.LOCI.Status})
		} else {
			tLoc.AppendRow(table.Row{"CS Domain (EF_LOCI)", "(empty)"})
		}

		if data.PSLOCI != nil {
			tLoc.AppendRow(table.Row{"PS Domain (EF_PSLOCI)", ""})
			tLoc.AppendRow(table.Row{"  P-TMSI", data.PSLOCI.PTMSI})
			tLoc.AppendRow(table.Row{"  RAI", data.PSLOCI.RAI})
			tLoc.AppendRow(table.Row{"  Status", data.PSLOCI.Status})
		} else {
			tLoc.AppendRow(table.Row{"PS Domain (EF_PSLOCI)", "(empty)"})
		}

		if data.EPSLOCI != nil {
			tLoc.AppendRow(table.Row{"EPS/LTE (EF_EPSLOCI)", ""})
			tLoc.AppendRow(table.Row{"  GUTI", data.EPSLOCI.GUTI})
			tLoc.AppendRow(table.Row{"  TAI", data.EPSLOCI.TAI})
			tLoc.AppendRow(table.Row{"  Status", data.EPSLOCI.Status})
		} else {
			tLoc.AppendRow(table.Row{"EPS/LTE (EF_EPSLOCI)", "(empty)"})
		}

		tLoc.Render()
	}

	// PLMN tables - show only if data exists
	if len(data.HPLMN) > 0 {
		printPLMNTable("HOME PLMN (EF_HPLMNwACT, 0x6F62)", data.HPLMN)
	}
	if len(data.OPLMN) > 0 {
		printPLMNTable("OPERATOR PLMN (EF_OPLMNwACT, 0x6F61)", data.OPLMN)
	}
	if len(data.UserPLMN) > 0 {
		printPLMNTable("USER PLMN (EF_PLMNwAcT, 0x6F60)", data.UserPLMN)
	}
	if len(data.FPLMN) > 0 {
		fmt.Println()
		t3 := newTable()
		t3.SetTitle("FORBIDDEN PLMN (EF_FPLMN, 0x6F7B)")
		t3.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, WidthMin: 40},
		})
		t3.AppendRow(table.Row{strings.Join(data.FPLMN, ", ")})
		t3.Render()
	}

	// Services status
	fmt.Println()
	t4 := newTable()
	t4.SetTitle("KEY SERVICES STATUS (EF_UST, 0x6F38)")
	t4.AppendHeader(table.Row{"Service", "Status"})
	t4.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 25},
		{Number: 2, WidthMin: 15},
	})

	appendServiceRow(t4, "VoLTE Support", data.HasVoLTE())
	appendServiceRow(t4, "VoWiFi Support", data.HasVoWiFi())
	appendServiceRow(t4, "SMS over IP", data.HasSMSOverIP())
	appendServiceRow(t4, "GSM Access", data.HasService(27))
	appendServiceRow(t4, "Call Control", data.HasService(30))
	appendServiceRow(t4, "GBA", data.HasService(67))
	appendServiceRow(t4, "5G NAS Config", data.HasService(104))
	appendServiceRow(t4, "5G NSSAI", data.HasService(108))
	appendServiceRow(t4, "SUCI Calculation", data.HasService(112))
	t4.Render()
}

// PrintISIMData prints all ISIM data in a nice table format
func PrintISIMData(data *sim.ISIMData) {
	if !data.Available {
		PrintWarning("ISIM application not available on this card")
		return
	}

	// IMS Identity
	fmt.Println()
	t := newTable()
	t.SetTitle("IMS PARAMETERS (ISIM)")
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 22},
		{Number: 2, Colors: colorValue, WidthMin: 60},
	})

	if data.IMPI != "" {
		t.AppendRow(table.Row{"IMPI (Private ID)", data.IMPI})
	} else {
		t.AppendRow(table.Row{"IMPI (Private ID)", colorWarn.Sprint("(not configured)")})
	}

	if len(data.IMPU) > 0 {
		for i, impu := range data.IMPU {
			label := fmt.Sprintf("IMPU %d (Public ID)", i+1)
			t.AppendRow(table.Row{label, impu})
		}
	} else {
		t.AppendRow(table.Row{"IMPU (Public ID)", colorWarn.Sprint("(not configured)")})
	}

	if data.Domain != "" {
		t.AppendRow(table.Row{"Home Domain", data.Domain})
	} else {
		t.AppendRow(table.Row{"Home Domain", colorWarn.Sprint("(not configured)")})
	}
	t.Render()

	// P-CSCF Addresses
	fmt.Println()
	t2 := newTable()
	t2.SetTitle("P-CSCF ADDRESSES (EF_PCSCF, 0x6F09)")
	if len(data.PCSCF) > 0 {
		t2.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 15},
			{Number: 2, Colors: colorValue, WidthMin: 50},
		})
		for i, pcscf := range data.PCSCF {
			t2.AppendRow(table.Row{fmt.Sprintf("P-CSCF %d", i+1), pcscf})
		}
	} else {
		t2.AppendRow(table.Row{colorWarn.Sprint("(no P-CSCF addresses configured)")})
	}
	t2.Render()

	// ISIM Services
	fmt.Println()
	t3 := newTable()
	t3.SetTitle("ISIM SERVICES (EF_IST, 0x6F07)")
	t3.AppendHeader(table.Row{"Service", "Status"})
	t3.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 25},
		{Number: 2, WidthMin: 15},
	})

	appendServiceRow(t3, "P-CSCF Address", data.HasPCSCF())
	appendServiceRow(t3, "GBA", data.HasGBA())
	appendServiceRow(t3, "HTTP Digest", data.HasHTTPDigest())
	appendServiceRow(t3, "SMS over IP", data.HasSMSOverIP())
	appendServiceRow(t3, "Voice Domain Pref", data.HasVoiceDomainPreference())
	t3.Render()
}

// appendServiceRow adds a service status row with colored status
func appendServiceRow(t table.Writer, name string, enabled bool) {
	if enabled {
		t.AppendRow(table.Row{name, colorSuccess.Sprint("✓ Enabled")})
	} else {
		t.AppendRow(table.Row{name, colorError.Sprint("✗ Disabled")})
	}
}

func printPLMNTable(title string, plmns []sim.PLMNwACT) {
	fmt.Println()
	t := newTable()
	t.SetTitle(title)
	t.AppendHeader(table.Row{"MCC", "MNC", "Technologies"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorValue, WidthMin: 6},
		{Number: 2, Colors: colorValue, WidthMin: 6},
		{Number: 3, Colors: colorValue, WidthMin: 70},
	})

	for _, p := range plmns {
		techs := strings.Join(p.Tech, ", ")
		if techs == "" {
			techs = fmt.Sprintf("0x%04X", p.ACT)
		}
		t.AppendRow(table.Row{p.MCC, p.MNC, techs})
	}
	t.Render()
}

// PrintServiceTable prints a detailed service table
func PrintServiceTable(title string, services map[int]bool, names map[int]string) {
	fmt.Println()
	t := newTable()
	t.SetTitle(title)
	t.AppendHeader(table.Row{"#", "Service Name", "Status"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorValue, WidthMin: 5, Align: text.AlignRight},
		{Number: 2, Colors: colorLabel, WidthMin: 60},
		{Number: 3, WidthMin: 12},
	})

	// Get sorted service numbers
	var nums []int
	for num := range services {
		nums = append(nums, num)
	}
	sort.Ints(nums)

	for _, num := range nums {
		enabled := services[num]
		name := names[num]
		if name == "" {
			name = "Unknown"
		}

		status := colorError.Sprint("✗")
		if enabled {
			status = colorSuccess.Sprint("✓")
		}

		t.AppendRow(table.Row{num, name, status})
	}
	t.Render()
}

// PrintAllServices prints complete UST/IST service tables
func PrintAllServices(usimData *sim.USIMData, isimData *sim.ISIMData) {
	if usimData != nil && len(usimData.UST) > 0 {
		PrintServiceTable("USIM SERVICE TABLE (UST)", usimData.UST, sim.USTServices)
	}

	if isimData != nil && isimData.Available && len(isimData.IST) > 0 {
		PrintServiceTable("ISIM SERVICE TABLE (IST)", isimData.IST, sim.ISTServices)
	}
}

// PrintReaderInfo prints reader and card info
func PrintReaderInfo(readerName, atr string) {
	fmt.Println()
	t := newTable()
	t.SetTitle("READER & CARD INFO")
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 15},
		{Number: 2, Colors: colorValue, WidthMin: 50},
	})
	t.AppendRow(table.Row{"Reader", readerName})
	t.AppendRow(table.Row{"ATR", atr})
	t.Render()
}

// PrintReaderList prints available readers
func PrintReaderList(readers []string) {
	fmt.Println()
	t := newTable()
	t.SetTitle("AVAILABLE SMART CARD READERS")
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 8},
		{Number: 2, Colors: colorValue, WidthMin: 50},
	})

	if len(readers) == 0 {
		t.AppendRow(table.Row{"Status", colorWarn.Sprint("No readers found")})
	} else {
		for i, r := range readers {
			t.AppendRow(table.Row{fmt.Sprintf("[%d]", i), r})
		}
	}
	t.Render()
}

// PrintRawData prints raw hex data for debugging
func PrintRawData(rawFiles map[string][]byte) {
	fmt.Println()
	t := newTable()
	t.SetTitle("RAW FILE DATA (HEX)")
	t.AppendHeader(table.Row{"File", "Data (hex)"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 15},
		{Number: 2, Colors: colorValue, WidthMax: 80},
	})

	// Sort keys
	var keys []string
	for k := range rawFiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		data := rawFiles[name]
		hexStr := fmt.Sprintf("%X", data)
		t.AppendRow(table.Row{name, hexStr})
	}
	t.Render()
}

// PrintCardAnalysis prints card analysis results
func PrintCardAnalysis(info *sim.CardInfo) {
	// ATR Analysis
	fmt.Println()
	t := newTable()
	t.SetTitle("CARD ANALYSIS")
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 20},
		{Number: 2, Colors: colorValue, WidthMin: 55},
	})

	t.AppendRow(table.Row{"ATR", info.ATR})
	cardType := sim.IdentifyCardByATR(info.ATR)
	t.AppendRow(table.Row{"Card Type", cardType})

	if info.ICCID != "" {
		t.AppendRow(table.Row{"ICCID", info.ICCID})
	}
	t.Render()

	// Detailed ATR Analysis
	if info.ATRInfo != nil {
		fmt.Println()
		ta := newTable()
		ta.SetTitle("DETAILED ATR ANALYSIS")
		ta.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 20},
			{Number: 2, Colors: colorValue, WidthMin: 55},
		})

		ta.AppendRow(table.Row{"Convention", info.ATRInfo.Convention()})

		protocols := []string{}
		for _, p := range info.ATRInfo.Protocols {
			protocols = append(protocols, fmt.Sprintf("T=%d", p))
		}
		if len(protocols) == 0 {
			protocols = append(protocols, "T=0")
		}
		ta.AppendRow(table.Row{"Protocols", strings.Join(protocols, ", ")})

		if info.ATRInfo.Fi > 0 || info.ATRInfo.Di > 0 {
			ta.AppendRow(table.Row{"Fi / Di", fmt.Sprintf("Fi=%d, Di=%d", info.ATRInfo.Fi, info.ATRInfo.Di)})
			ta.AppendRow(table.Row{"Baud Rate Factor", fmt.Sprintf("%d", info.ATRInfo.Fi/info.ATRInfo.Di)})
		}

		if info.ATRInfo.Voltage != "" {
			ta.AppendRow(table.Row{"Voltage", info.ATRInfo.Voltage})
		}

		if len(info.ATRInfo.HB) > 0 {
			hbStr := fmt.Sprintf("%X", info.ATRInfo.HB)
			var text strings.Builder
			for _, b := range info.ATRInfo.HB {
				if b >= 0x20 && b < 0x7F {
					text.WriteByte(b)
				}
			}
			if text.Len() > 0 {
				hbStr += fmt.Sprintf(" (\"%s\")", text.String())
			}
			ta.AppendRow(table.Row{"Historical Bytes", hbStr})
		}

		if info.ATRInfo.TCK != nil {
			ta.AppendRow(table.Row{"Checksum (TCK)", fmt.Sprintf("%02X", *info.ATRInfo.TCK)})
		}
		ta.Render()
	}

	// Applications found
	if len(info.Applications) > 0 {
		fmt.Println()
		t2 := newTable()
		t2.SetTitle("APPLICATIONS (EF_DIR)")
		t2.AppendHeader(table.Row{"AID", "Label", "Type"})
		t2.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorValue, WidthMin: 30},
			{Number: 2, Colors: colorValue, WidthMin: 20},
			{Number: 3, Colors: colorLabel, WidthMin: 15},
		})

		for _, app := range info.Applications {
			label := app.Label
			if label == "" {
				label = "(no label)"
			}
			t2.AppendRow(table.Row{app.AID, label, app.Type})
		}
		t2.Render()
	} else {
		PrintWarning("No applications found in EF_DIR (may be 2G SIM or non-standard card)")
	}

	// GSM 2G data if available
	if info.GSMAvailable && info.GSMData != nil {
		fmt.Println()
		t3 := newTable()
		t3.SetTitle("GSM 2G SIM DATA")
		t3.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 20},
			{Number: 2, Colors: colorValue, WidthMin: 55},
		})

		if info.GSMData.IMSI != "" {
			t3.AppendRow(table.Row{"IMSI", info.GSMData.IMSI})
		}
		if info.GSMData.HPLMN != "" {
			t3.AppendRow(table.Row{"HPLMN (from IMSI)", info.GSMData.HPLMN})
		}
		if info.GSMData.SPN != "" {
			t3.AppendRow(table.Row{"Service Provider", info.GSMData.SPN})
		}
		if info.GSMData.MSISDN != "" {
			t3.AppendRow(table.Row{"MSISDN", info.GSMData.MSISDN})
		}
		if len(info.GSMData.FPLMN) > 0 {
			t3.AppendRow(table.Row{"Forbidden PLMNs", strings.Join(info.GSMData.FPLMN, ", ")})
		}
		t3.Render()

		// Show raw IMSI if available
		if len(info.GSMData.RawIMSI) > 0 {
			fmt.Println()
			PrintSuccess(fmt.Sprintf("Raw IMSI: %X", info.GSMData.RawIMSI))
		}
	}

	// Raw EF_DIR if available and raw mode
	if len(info.RawDIR) > 0 {
		fmt.Println()
		PrintSuccess(fmt.Sprintf("Raw EF_DIR: %X", info.RawDIR))
	}

	// ADM keys status
	if len(info.ADMStatus) > 0 {
		fmt.Println()
		t4 := newTable()
		t4.SetTitle("ADM KEYS STATUS")
		t4.AppendHeader(table.Row{"KEY", "EXISTS", "STATUS", "ATTEMPTS"})
		t4.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 8},
			{Number: 2, Colors: colorValue, WidthMin: 10},
			{Number: 3, Colors: colorValue, WidthMin: 15},
			{Number: 4, Colors: colorValue, WidthMin: 10},
		})

		// Show in order: ADM1, ADM2, ADM3, ADM4
		admKeys := []string{"ADM1", "ADM2", "ADM3", "ADM4"}
		for _, key := range admKeys {
			if status, ok := info.ADMStatus[key]; ok {
				existsStr := "✗ No"
				statusStr := "-"
				attemptsStr := "-"

				if status.Exists {
					existsStr = "✓ Yes"
					if status.Blocked {
						statusStr = "BLOCKED"
						attemptsStr = "0"
					} else {
						statusStr = "Available"
						if status.Attempts >= 0 {
							attemptsStr = fmt.Sprintf("%d", status.Attempts)
						} else {
							attemptsStr = "?"
						}
					}
				}

				t4.AppendRow(table.Row{key, existsStr, statusStr, attemptsStr})
			}
		}
		t4.Render()

		// Hint about multiple ADM keys
		fmt.Println()
		PrintSuccess("Use -adm, -adm2, -adm3, -adm4 to provide keys for different access levels")
	}
}

// formatAccessLevel returns colored string for access level
func formatAccessLevel(access string) string {
	switch {
	case access == "PIN1":
		return colorPIN1.Sprint("PIN1")
	case access == "ADM1":
		return colorADM1.Sprint("ADM1")
	case access == "ADM2":
		return colorADM2.Sprint("ADM2")
	case access == "ADM3":
		return colorADM3.Sprint("ADM3")
	case access == "ADM4":
		return colorADM4.Sprint("ADM4")
	case access == "Always":
		return colorAlways.Sprint("Always")
	case access == "Never":
		return colorNever.Sprint("Never")
	case strings.HasPrefix(access, "PIN"):
		return colorPIN1.Sprint(access)
	case strings.HasPrefix(access, "ADM"):
		return colorADM1.Sprint(access)
	default:
		return access
	}
}

// PrintFileAccessConditions prints file access requirements
func PrintFileAccessConditions(usimAccess, isimAccess []sim.FileAccessInfo) {
	if len(usimAccess) == 0 && len(isimAccess) == 0 {
		return
	}

	fmt.Println()
	t := newTable()
	t.SetTitle("FILE ACCESS CONDITIONS")
	t.AppendHeader(table.Row{"FILE", "FILE ID", "READ", "WRITE"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 15},
		{Number: 2, Colors: colorValue, WidthMin: 8},
		{Number: 3, WidthMin: 12},
		{Number: 4, WidthMin: 12},
	})

	// USIM files
	if len(usimAccess) > 0 {
		t.AppendRow(table.Row{"─── USIM ───", "", "", ""})
		for _, fa := range usimAccess {
			t.AppendRow(table.Row{
				fa.FileName,
				fa.FileID,
				formatAccessLevel(fa.ReadAccess),
				formatAccessLevel(fa.WriteAccess),
			})
		}
	}

	// ISIM files
	if len(isimAccess) > 0 {
		t.AppendRow(table.Row{"─── ISIM ───", "", "", ""})
		for _, fa := range isimAccess {
			t.AppendRow(table.Row{
				fa.FileName,
				fa.FileID,
				formatAccessLevel(fa.ReadAccess),
				formatAccessLevel(fa.WriteAccess),
			})
		}
	}

	t.Render()
}

// PrintError prints an error message
func PrintError(msg string) {
	fmt.Println(colorError.Sprintf("✗ Error: %s", msg))
}

// PrintSuccess prints a success message
func PrintSuccess(msg string) {
	fmt.Println(colorSuccess.Sprintf("✓ %s", msg))
}

// PrintWarning prints a warning message
func PrintWarning(msg string) {
	fmt.Println(colorWarn.Sprintf("⚠ %s", msg))
}

// PrintPhonebook prints phonebook entries
func PrintPhonebook(entries []sim.PhonebookEntry) {
	fmt.Println()
	t := newTable()
	t.SetTitle("PHONEBOOK (EF_ADN)")
	t.AppendHeader(table.Row{"#", "Name", "Number"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 5},
		{Number: 2, Colors: colorValue, WidthMin: 30},
		{Number: 3, Colors: colorValue, WidthMin: 20},
	})

	if len(entries) == 0 {
		t.AppendRow(table.Row{"-", "(empty)", "-"})
	} else {
		for _, e := range entries {
			t.AppendRow(table.Row{e.Index, e.Name, e.Number})
		}
	}
	t.Render()
	fmt.Printf("\nTotal entries: %d\n", len(entries))
}

// PrintSMS prints SMS messages
func PrintSMS(messages []sim.SMSMessage) {
	fmt.Println()
	t := newTable()
	t.SetTitle("SMS MESSAGES (EF_SMS)")
	t.AppendHeader(table.Row{"#", "Status", "Number", "Text"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 5},
		{Number: 2, Colors: colorValue, WidthMin: 10},
		{Number: 3, Colors: colorValue, WidthMin: 15},
		{Number: 4, Colors: colorValue, WidthMax: 50},
	})

	if len(messages) == 0 {
		t.AppendRow(table.Row{"-", "(empty)", "-", "-"})
	} else {
		for _, m := range messages {
			text := m.Text
			if len(text) > 50 {
				text = text[:47] + "..."
			}
			t.AppendRow(table.Row{m.Index, m.Status, m.Number, text})
		}
	}
	t.Render()
	fmt.Printf("\nTotal messages: %d\n", len(messages))
}

// PrintApplets prints GlobalPlatform applets
func PrintApplets(applets []sim.Applet) {
	fmt.Println()
	t := newTable()
	t.SetTitle("GLOBALPLATFORM APPLETS")
	t.AppendHeader(table.Row{"Type", "AID", "State", "Privileges", "Known As"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 8},
		{Number: 2, Colors: colorValue, WidthMin: 35},
		{Number: 3, Colors: colorValue, WidthMin: 12},
		{Number: 4, Colors: colorValue, WidthMin: 20},
		{Number: 5, Colors: colorLabel, WidthMin: 15},
	})

	if len(applets) == 0 {
		t.AppendRow(table.Row{"-", "(no applets found)", "-", "-", "-"})
	} else {
		for _, a := range applets {
			known := sim.IdentifyAppletByAID(a.AID)
			if known == "" {
				known = "-"
			}
			state := a.State
			if state == "" {
				state = "-"
			}
			priv := a.Privilege
			if priv == "" {
				priv = "-"
			}
			t.AppendRow(table.Row{a.Type, a.AID, state, priv, known})
		}
	}
	t.Render()
	fmt.Printf("\nTotal applets: %d\n", len(applets))
}

// PrintScriptResults prints APDU script execution results
func PrintScriptResults(results []sim.ScriptResult) {
	fmt.Println()
	t := newTable()
	t.SetTitle("SCRIPT EXECUTION RESULTS")
	t.AppendHeader(table.Row{"Line", "APDU", "Response", "SW", "Status"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 5},
		{Number: 2, Colors: colorValue, WidthMin: 40},
		{Number: 3, Colors: colorValue, WidthMin: 30},
		{Number: 4, Colors: colorValue, WidthMin: 6},
		{Number: 5, WidthMin: 10},
	})

	successCount := 0
	for _, r := range results {
		apdu := r.APDU
		if len(apdu) > 40 {
			apdu = apdu[:37] + "..."
		}
		response := r.Response
		if len(response) > 30 {
			response = response[:27] + "..."
		}

		var status string
		if r.Success {
			status = colorSuccess.Sprint("✓ OK")
			successCount++
		} else {
			if r.Error != "" {
				status = colorError.Sprintf("✗ %s", r.Error)
			} else {
				status = colorError.Sprint("✗ FAIL")
			}
		}

		t.AppendRow(table.Row{r.LineNum, apdu, response, r.SW, status})
	}
	t.Render()
	fmt.Printf("\nExecuted: %d commands, Success: %d, Failed: %d\n",
		len(results), successCount, len(results)-successCount)
}

// PrintProgrammableCardInfo prints programmable card information
func PrintProgrammableCardInfo(cardType, atr string) {
	fmt.Println()
	t := newTable()
	t.SetTitle("PROGRAMMABLE CARD INFORMATION")
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 25},
		{Number: 2, Colors: colorValue, WidthMin: 50},
	})

	t.AppendRow(table.Row{"Card Type", cardType})
	t.AppendRow(table.Row{"ATR", atr})
	
	// Add file IDs based on card type
	if cardType == "GRv2" || cardType == "Grcard v2 / open5gs (GRv2)" {
		t.AppendRow(table.Row{"", ""})
		t.AppendRow(table.Row{"Proprietary Files", ""})
		t.AppendRow(table.Row{"Ki (Subscriber Key)", "0001"})
		t.AppendRow(table.Row{"OPc (Operator Code)", "6002"})
		t.AppendRow(table.Row{"Milenage R Constants", "2FE6"})
		t.AppendRow(table.Row{"Algorithm Type", "2FD0"})
		t.AppendRow(table.Row{"ADM Key", "0B00"})
		t.AppendRow(table.Row{"PIN1/PUK1", "0100"})
		t.AppendRow(table.Row{"PIN2/PUK2", "0200"})
	} else if cardType == "GRv1" || cardType == "Grcard v1 (GRv1)" {
		t.AppendRow(table.Row{"", ""})
		t.AppendRow(table.Row{"Proprietary Files", ""})
		t.AppendRow(table.Row{"Ki (Subscriber Key)", "7FF0 FF02"})
		t.AppendRow(table.Row{"OPc (Operator Code)", "7FF0 FF01"})
		t.AppendRow(table.Row{"Milenage R Constants", "7FF0 FF03"})
		t.AppendRow(table.Row{"Milenage C Constants", "7FF0 FF04"})
	} else if cardType == "Unknown" {
		t.AppendRow(table.Row{"", ""})
		t.AppendRow(table.Row{"Status", colorWarn.Sprint("Not recognized as programmable")})
		t.AppendRow(table.Row{"Note", "Use -prog-force to override (DANGEROUS!)"})
	}
	
	t.Render()
	fmt.Println()
}

// PrintProgrammableWriteWarning prints warning before actual write operations
func PrintProgrammableWriteWarning(dryRun bool) {
	fmt.Println()
	if dryRun {
		PrintWarning("DRY RUN MODE: No data will be written")
		PrintWarning("Remove -prog-dry-run to actually program the card")
	} else {
		PrintWarning("WARNING: Programmable card operations are PERMANENT and CANNOT BE UNDONE!")
		PrintWarning("Press Ctrl+C now if you want to cancel.")
		fmt.Println()
		PrintWarning("Waiting 3 seconds...")
		time.Sleep(3 * time.Second)
	}
	fmt.Println()
}

// TestResult is imported from testing package for printing
type TestResult struct {
	Name     string
	Category string
	Passed   bool
	Expected string
	Actual   string
	APDU     string
	Response string
	SW       uint16
	Error    string
	Spec     string
}

// TestSummary for test suite results
type TestSummary struct {
	Total       int
	Passed      int
	Failed      int
	PassRate    float64
	ByCategory  map[string]int
	FailedTests []string
}

// PrintTestSummary prints test suite summary
func PrintTestSummary(results []TestResult) {
	if len(results) == 0 {
		PrintWarning("No test results")
		return
	}

	// Calculate summary
	passed := 0
	failed := 0
	byCategory := make(map[string]int)
	var failedTests []string

	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
			failedTests = append(failedTests, r.Name)
		}
		byCategory[r.Category]++
	}

	passRate := float64(passed) / float64(len(results)) * 100

	// Summary table
	fmt.Println()
	t := newTable()
	t.SetTitle("TEST SUITE SUMMARY")
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 20},
		{Number: 2, Colors: colorValue, WidthMin: 15},
	})

	t.AppendRow(table.Row{"Total Tests", len(results)})
	t.AppendRow(table.Row{"Passed", colorSuccess.Sprintf("%d", passed)})
	t.AppendRow(table.Row{"Failed", colorError.Sprintf("%d", failed)})
	t.AppendRow(table.Row{"Pass Rate", fmt.Sprintf("%.1f%%", passRate)})
	t.Render()

	// By category
	if len(byCategory) > 0 {
		fmt.Println()
		t2 := newTable()
		t2.SetTitle("TESTS BY CATEGORY")
		t2.AppendHeader(table.Row{"Category", "Tests", "Passed", "Failed"})
		t2.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 15},
			{Number: 2, Colors: colorValue, WidthMin: 8},
			{Number: 3, WidthMin: 8},
			{Number: 4, WidthMin: 8},
		})

		// Count passed/failed by category
		catPassed := make(map[string]int)
		catFailed := make(map[string]int)
		for _, r := range results {
			if r.Passed {
				catPassed[r.Category]++
			} else {
				catFailed[r.Category]++
			}
		}

		categories := []string{"usim", "isim", "auth", "apdu", "security"}
		for _, cat := range categories {
			if count, ok := byCategory[cat]; ok {
				p := catPassed[cat]
				f := catFailed[cat]
				passedStr := colorSuccess.Sprintf("%d", p)
				failedStr := fmt.Sprintf("%d", f)
				if f > 0 {
					failedStr = colorError.Sprintf("%d", f)
				}
				t2.AppendRow(table.Row{cat, count, passedStr, failedStr})
			}
		}
		t2.Render()
	}

	// Failed tests
	if len(failedTests) > 0 {
		fmt.Println()
		t3 := newTable()
		t3.SetTitle("FAILED TESTS")
		t3.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorError, WidthMin: 60},
		})
		for _, name := range failedTests {
			t3.AppendRow(table.Row{name})
		}
		t3.Render()
	}

	// Detailed results
	fmt.Println()
	t4 := newTable()
	t4.SetTitle("DETAILED TEST RESULTS")
	t4.AppendHeader(table.Row{"Status", "Category", "Test Name", "Result"})
	t4.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, WidthMin: 6},
		{Number: 2, Colors: colorLabel, WidthMin: 10},
		{Number: 3, Colors: colorValue, WidthMin: 35},
		{Number: 4, Colors: colorValue, WidthMin: 40},
	})

	for _, r := range results {
		status := colorSuccess.Sprint("✓")
		if !r.Passed {
			status = colorError.Sprint("✗")
		}
		result := r.Actual
		if !r.Passed && r.Error != "" {
			result = r.Error
		}
		if len(result) > 40 {
			result = result[:37] + "..."
		}
		t4.AppendRow(table.Row{status, r.Category, r.Name, result})
	}
	t4.Render()
}

// PrintAuthResult prints authentication test results
func PrintAuthResult(result *sim.AuthResult, algorithm string) {
	if result == nil {
		PrintError("No authentication result")
		return
	}

	// Determine mode title
	title := fmt.Sprintf("AUTHENTICATION TEST (%s)", strings.ToUpper(algorithm))
	if result.CardOnlyMode {
		title = "CARD-ONLY AUTH (No K - just send RAND+AUTN to card)"
	} else if result.AUTSFromDump {
		title = fmt.Sprintf("AUTS RESYNC (%s)", strings.ToUpper(algorithm))
	} else if result.AUTNFromDump {
		title = fmt.Sprintf("AUTH WITH PRE-COMPUTED AUTN (%s)", strings.ToUpper(algorithm))
	}

	// Input parameters
	fmt.Println()
	t := newTable()
	t.SetTitle(title)
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Colors: colorLabel, WidthMin: 20},
		{Number: 2, Colors: colorValue, WidthMin: 70},
	})

	// Card-only mode has limited input info
	if result.CardOnlyMode {
		t.AppendRow(table.Row{"─── INPUT ───", ""})
		t.AppendRow(table.Row{"RAND", result.RAND})
		t.AppendRow(table.Row{"AUTN", result.AUTN})
		t.Render()
	} else {
		t.AppendRow(table.Row{"─── INPUT ───", ""})
		t.AppendRow(table.Row{"K (Subscriber Key)", result.K})
		if result.OP != "" {
			t.AppendRow(table.Row{"OP", result.OP})
		}
		t.AppendRow(table.Row{"OPc", result.OPc})
		t.AppendRow(table.Row{"RAND", result.RAND})
		if !result.AUTSFromDump {
			t.AppendRow(table.Row{"SQN", result.SQN})
			t.AppendRow(table.Row{"AMF", result.AMF})
		}
		t.Render()
	}

	// Handle card-only mode
	if result.CardOnlyMode {
		// Card response
		fmt.Println()
		t2 := newTable()
		t2.SetTitle("SIM CARD RESPONSE")
		t2.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 20},
			{Number: 2, Colors: colorValue, WidthMin: 70},
		})

		if result.SyncFail {
			t2.AppendRow(table.Row{"Status", colorWarn.Sprint("SYNC FAILURE - SQN out of range")})
			t2.AppendRow(table.Row{"AUTS", result.AUTS})
		} else if result.RES != "" {
			t2.AppendRow(table.Row{"Status", colorSuccess.Sprint("SUCCESS")})
			t2.AppendRow(table.Row{"RES", result.RES})
			if result.CardCK != "" {
				t2.AppendRow(table.Row{"CK", result.CardCK})
			}
			if result.CardIK != "" {
				t2.AppendRow(table.Row{"IK", result.CardIK})
			}
		}
		t2.Render()

		if result.Error != "" {
			fmt.Println()
			PrintError(result.Error)
		}
		return
	}

	// Handle AUTS resync mode differently
	if result.AUTSFromDump {
		// AUTS Resync results
		fmt.Println()
		t2 := newTable()
		t2.SetTitle("AUTS RESYNC RESULTS")
		t2.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 20},
			{Number: 2, Colors: colorValue, WidthMin: 70},
		})

		t2.AppendRow(table.Row{"AUTS (from dump)", result.AUTS})
		t2.AppendRow(table.Row{"AK* (f5*)", result.AKF5})
		t2.AppendRow(table.Row{"─── EXTRACTED ───", ""})
		t2.AppendRow(table.Row{"SQNms (SIM SQN)", colorSuccess.Sprint(result.SQNms)})
		t2.AppendRow(table.Row{"MAC-S", result.MACS})
		if result.CK != "" {
			t2.AppendRow(table.Row{"CK (f3)", result.CK})
		}
		if result.IK != "" {
			t2.AppendRow(table.Row{"IK (f4)", result.IK})
		}
		t2.Render()

		fmt.Println()
		nextSQN := sim.IncrementSQNHex(result.SQNms)
		PrintSuccess(fmt.Sprintf("Use -auth-sqn %s for next authentication (SQNms+1)", nextSQN))
	} else {
		// Computed values (network side)
		fmt.Println()
		t2 := newTable()
		if result.AUTNFromDump {
			t2.SetTitle("AUTHENTICATION DATA (AUTN from dump)")
		} else {
			t2.SetTitle("COMPUTED AUTHENTICATION VECTOR (Network)")
		}
		t2.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 20},
			{Number: 2, Colors: colorValue, WidthMin: 70},
		})

		t2.AppendRow(table.Row{"MAC-A (f1)", result.MACA})
		t2.AppendRow(table.Row{"XRES (f2)", result.XRES})
		t2.AppendRow(table.Row{"CK (f3)", result.CK})
		t2.AppendRow(table.Row{"IK (f4)", result.IK})
		t2.AppendRow(table.Row{"AK (f5)", result.AK})
		if result.AUTNFromDump {
			t2.AppendRow(table.Row{"AUTN (from dump)", colorWarn.Sprint(result.AUTN)})
		} else {
			t2.AppendRow(table.Row{"AUTN", result.AUTN})
		}
		t2.Render()

		// Card response (if available)
		if result.RES != "" || result.SyncFail {
			fmt.Println()
			t3 := newTable()
			t3.SetTitle("SIM CARD RESPONSE")
			t3.SetColumnConfigs([]table.ColumnConfig{
				{Number: 1, Colors: colorLabel, WidthMin: 20},
				{Number: 2, Colors: colorValue, WidthMin: 70},
			})

			if result.SyncFail {
				t3.AppendRow(table.Row{"Status", colorWarn.Sprint("SYNC FAILURE - SQN out of range")})
				t3.AppendRow(table.Row{"AUTS", result.AUTS})
				if result.AKF5 != "" {
					t3.AppendRow(table.Row{"AK* (f5*)", result.AKF5})
				}
				if result.SQNms != "" {
					t3.AppendRow(table.Row{"SQNms (from AUTS)", result.SQNms})
				}
				if result.MACS != "" {
					t3.AppendRow(table.Row{"MAC-S (from AUTS)", result.MACS})
				}
			} else {
				t3.AppendRow(table.Row{"RES (Response)", result.RES})
				if result.CardCK != "" {
					t3.AppendRow(table.Row{"CK (Card)", result.CardCK})
				}
				if result.CardIK != "" {
					t3.AppendRow(table.Row{"IK (Card)", result.CardIK})
				}

				// Verification
				if result.RESMatch {
					t3.AppendRow(table.Row{"RES Match", colorSuccess.Sprint("✓ RES == XRES (Authentication OK)")})
				} else {
					t3.AppendRow(table.Row{"RES Match", colorError.Sprint("✗ RES != XRES (Authentication FAILED)")})
				}
			}
			t3.Render()
		}
	}

	// Error if any
	if result.Error != "" {
		fmt.Println()
		PrintError(result.Error)
	}

	// Derived keys (not shown for AUTS resync mode)
	if !result.AUTSFromDump {
		fmt.Println()
		t4 := newTable()
		t4.SetTitle("DERIVED KEYS")
		t4.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, Colors: colorLabel, WidthMin: 20},
			{Number: 2, Colors: colorValue, WidthMin: 70},
		})

		if result.KASME != "" {
			t4.AppendRow(table.Row{"KASME (LTE)", result.KASME})
		} else {
			t4.AppendRow(table.Row{"KASME (LTE)", colorWarn.Sprint("(use -auth-mcc and -auth-mnc to compute)")})
		}

		// 2G Triplets
		if result.SRES != "" {
			t4.AppendRow(table.Row{"─── 2G TRIPLET ───", ""})
			t4.AppendRow(table.Row{"SRES", result.SRES})
			t4.AppendRow(table.Row{"Kc", result.Kc})
		}
		t4.Render()
	}
}
