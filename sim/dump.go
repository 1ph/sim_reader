package sim

import (
	"fmt"
	"strings"
	"time"
)

// DumpTestData generates Go code for test data from card
func DumpTestData(cardName string, atr string, usimData *USIMData, isimData *ISIMData) string {
	var sb strings.Builder

	sb.WriteString("// ============================================================================\n")
	sb.WriteString(fmt.Sprintf("// Test data dumped from: %s\n", cardName))
	sb.WriteString(fmt.Sprintf("// Date: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("// ATR: %s\n", atr))
	sb.WriteString("// ============================================================================\n")
	sb.WriteString("// Copy this to sim/decoder_test.go in testCards slice\n")
	sb.WriteString("// ============================================================================\n\n")

	// Determine card type
	cardType := IdentifyCardByATR(atr)

	sb.WriteString("{\n")
	sb.WriteString(fmt.Sprintf("\tName:     %q,\n", cardName))
	sb.WriteString(fmt.Sprintf("\tATR:      %q,\n", atr))
	sb.WriteString(fmt.Sprintf("\tCardType: %q,\n", cardType))

	if usimData != nil {
		// ICCID
		if raw, ok := usimData.RawFiles["EF_ICCID"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\tRawICCID: %s,\n", formatBytes(raw)))
			sb.WriteString(fmt.Sprintf("\tICCID:    %q,\n", usimData.ICCID))
		} else if usimData.ICCID != "" {
			sb.WriteString(fmt.Sprintf("\tICCID:    %q, // No raw data available\n", usimData.ICCID))
		}

		// IMSI
		if raw, ok := usimData.RawFiles["EF_IMSI"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\tRawIMSI:  %s,\n", formatBytes(raw)))
			sb.WriteString(fmt.Sprintf("\tIMSI:     %q,\n", usimData.IMSI))
		}

		// SPN
		if raw, ok := usimData.RawFiles["EF_SPN"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\tRawSPN:   %s,\n", formatBytes(raw)))
			sb.WriteString(fmt.Sprintf("\tSPN:      %q,\n", usimData.SPN))
		}

		// AD (Administrative Data)
		if raw, ok := usimData.RawFiles["EF_AD"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\tRawAD:    %s,\n", formatBytes(raw)))
			sb.WriteString(fmt.Sprintf("\tMNCLength: %d,\n", usimData.AdminData.MNCLength))
		}

		// UST
		if raw, ok := usimData.RawFiles["EF_UST"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\tRawUST:   %s,\n", formatBytes(raw)))
			services := getEnabledServiceNumbers(usimData.UST)
			sb.WriteString(fmt.Sprintf("\tUSTServices: %s,\n", formatIntSlice(services)))
		}

		// HPLMN
		if raw, ok := usimData.RawFiles["EF_HPLMNwACT"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\tRawHPLMN: %s,\n", formatBytes(raw)))
			sb.WriteString("\tHPLMN: []PLMNwACT{\n")
			for _, p := range usimData.HPLMN {
				techs := formatStringSlice(p.Tech)
				sb.WriteString(fmt.Sprintf("\t\t{MCC: %q, MNC: %q, ACT: 0x%04X, Tech: %s},\n",
					p.MCC, p.MNC, p.ACT, techs))
			}
			sb.WriteString("\t},\n")
		}

		// FPLMN
		if raw, ok := usimData.RawFiles["EF_FPLMN"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\tRawFPLMN: %s,\n", formatBytes(raw)))
			sb.WriteString(fmt.Sprintf("\tFPLMN:    %s,\n", formatStringSlice(usimData.FPLMN)))
		}

		// ACC
		if raw, ok := usimData.RawFiles["EF_ACC"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\t// RawACC: %s\n", formatBytes(raw)))
		}
	}

	// ISIM data
	if isimData != nil && isimData.Available {
		sb.WriteString("\t// ISIM Data:\n")
		if raw, ok := isimData.RawFiles["EF_IMPI"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\t// RawIMPI: %s\n", formatBytes(raw)))
			sb.WriteString(fmt.Sprintf("\t// IMPI: %q\n", isimData.IMPI))
		}
		if raw, ok := isimData.RawFiles["EF_DOMAIN"]; ok && len(raw) > 0 {
			sb.WriteString(fmt.Sprintf("\t// RawDomain: %s\n", formatBytes(raw)))
			sb.WriteString(fmt.Sprintf("\t// Domain: %q\n", isimData.Domain))
		}
		if len(isimData.IMPU) > 0 {
			sb.WriteString(fmt.Sprintf("\t// IMPU: %s\n", formatStringSlice(isimData.IMPU)))
		}
		if len(isimData.PCSCF) > 0 {
			sb.WriteString(fmt.Sprintf("\t// PCSCF: %s\n", formatStringSlice(isimData.PCSCF)))
		}
	}

	sb.WriteString("},\n")

	return sb.String()
}

// DumpRawFiles generates a simple dump of all raw files
func DumpRawFiles(usimData *USIMData, isimData *ISIMData) string {
	var sb strings.Builder

	sb.WriteString("// ============================================================================\n")
	sb.WriteString("// RAW FILE DUMP\n")
	sb.WriteString(fmt.Sprintf("// Date: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("// ============================================================================\n\n")

	if usimData != nil {
		sb.WriteString("// USIM Files:\n")
		for name, data := range usimData.RawFiles {
			sb.WriteString(fmt.Sprintf("// %s: %X\n", name, data))
		}
	}

	if isimData != nil && isimData.Available {
		sb.WriteString("\n// ISIM Files:\n")
		for name, data := range isimData.RawFiles {
			sb.WriteString(fmt.Sprintf("// %s: %X\n", name, data))
		}
	}

	return sb.String()
}

// Helper functions

func formatBytes(data []byte) string {
	if len(data) == 0 {
		return "nil"
	}
	var parts []string
	for _, b := range data {
		parts = append(parts, fmt.Sprintf("0x%02X", b))
	}
	return "[]byte{" + strings.Join(parts, ", ") + "}"
}

func formatIntSlice(nums []int) string {
	if len(nums) == 0 {
		return "nil"
	}
	var parts []string
	for _, n := range nums {
		parts = append(parts, fmt.Sprintf("%d", n))
	}
	return "[]int{" + strings.Join(parts, ", ") + "}"
}

func formatStringSlice(strs []string) string {
	if len(strs) == 0 {
		return "nil"
	}
	var parts []string
	for _, s := range strs {
		parts = append(parts, fmt.Sprintf("%q", s))
	}
	return "[]string{" + strings.Join(parts, ", ") + "}"
}

func getEnabledServiceNumbers(ust map[int]bool) []int {
	var nums []int
	for num, enabled := range ust {
		if enabled {
			nums = append(nums, num)
		}
	}
	// Sort for consistent output
	for i := 0; i < len(nums)-1; i++ {
		for j := i + 1; j < len(nums); j++ {
			if nums[i] > nums[j] {
				nums[i], nums[j] = nums[j], nums[i]
			}
		}
	}
	return nums
}

