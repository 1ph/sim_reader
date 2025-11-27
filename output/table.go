package output

import (
	"fmt"
	"os"
	"sort"
	"strings"

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
	t2.Render()

	// PLMN tables
	if len(data.HPLMN) > 0 {
		printPLMNTable("HOME PLMN (HPLMNwACT)", data.HPLMN)
	}
	if len(data.OPLMN) > 0 {
		printPLMNTable("OPERATOR PLMN (OPLMNwACT)", data.OPLMN)
	}
	if len(data.UserPLMN) > 0 {
		printPLMNTable("USER PLMN (PLMNwACT)", data.UserPLMN)
	}
	if len(data.FPLMN) > 0 {
		fmt.Println()
		t3 := newTable()
		t3.SetTitle("FORBIDDEN PLMN")
		t3.AppendRow(table.Row{strings.Join(data.FPLMN, ", ")})
		t3.Render()
	}

	// Services status
	fmt.Println()
	t4 := newTable()
	t4.SetTitle("KEY SERVICES STATUS")
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
	t2.SetTitle("P-CSCF ADDRESSES")
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
	t3.SetTitle("ISIM SERVICES")
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

// printPLMNTable prints PLMN list as table
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
