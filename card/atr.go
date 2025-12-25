package card

import (
	"fmt"
	"strings"
)

// ATRInfo represents decoded Answer To Reset information
type ATRInfo struct {
	Raw          []byte
	TS           byte
	T0           byte
	TA           map[int]byte
	TB           map[int]byte
	TC           map[int]byte
	TD           map[int]byte
	HB           []byte // Historical Bytes
	TCK          *byte  // Checksum (only for T>0)
	Protocols    []int
	Fi           int    // Clock rate conversion factor
	Di           int    // Baud rate adjustment factor
	Voltage      string // Voltage info from TB
	ProgrammingP byte   // Programming voltage P
	ProgrammingI byte   // Programming current I
}

// DecodeATR parses a raw ATR byte slice
func DecodeATR(atr []byte) (*ATRInfo, error) {
	if len(atr) < 2 {
		return nil, fmt.Errorf("ATR too short")
	}

	info := &ATRInfo{
		Raw: atr,
		TS:  atr[0],
		T0:  atr[1],
		TA:  make(map[int]byte),
		TB:  make(map[int]byte),
		TC:  make(map[int]byte),
		TD:  make(map[int]byte),
	}

	hbLen := int(info.T0 & 0x0F)
	ptr := 2
	pn := 1
	td := info.T0

	for ptr < len(atr) {
		// TAi
		if td&0x10 != 0 {
			if ptr >= len(atr) {
				break
			}
			info.TA[pn] = atr[ptr]
			ptr++
		}
		// TBi
		if td&0x20 != 0 {
			if ptr >= len(atr) {
				break
			}
			info.TB[pn] = atr[ptr]
			ptr++
		}
		// TCi
		if td&0x40 != 0 {
			if ptr >= len(atr) {
				break
			}
			info.TC[pn] = atr[ptr]
			ptr++
		}
		// TDi
		if td&0x80 != 0 {
			if ptr >= len(atr) {
				break
			}
			td = atr[ptr]
			info.TD[pn] = td
			protocol := int(td & 0x0F)
			info.Protocols = append(info.Protocols, protocol)
			ptr++
			pn++
		} else {
			break
		}
	}

	// Historical bytes
	if ptr+hbLen <= len(atr) {
		info.HB = atr[ptr : ptr+hbLen]
		ptr += hbLen
	} else if ptr < len(atr) {
		info.HB = atr[ptr:]
		ptr = len(atr)
	}

	// TCK (Checksum)
	if ptr < len(atr) {
		info.TCK = &atr[ptr]
	}

	// Interpret parameters
	info.interpret()

	return info, nil
}

func (info *ATRInfo) interpret() {
	// TA1: Fi and Di
	if val, ok := info.TA[1]; ok {
		fiTable := map[byte]int{
			0: 372, 1: 372, 2: 558, 3: 744, 4: 1116, 5: 1488, 6: 1860,
			9: 512, 10: 768, 11: 1024, 12: 1536, 13: 2048,
		}
		diTable := map[byte]int{
			1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64,
			8: 12, 9: 20,
		}
		info.Fi = fiTable[val>>4]
		info.Di = diTable[val&0x0F]
	}

	// TB1, TB2: Voltage
	if val, ok := info.TB[1]; ok {
		info.ProgrammingI = val & 0x1F
		info.ProgrammingP = val >> 5
	}
	if val, ok := info.TB[2]; ok {
		// PI1 in TB2
		if val != 0 {
			voltage := float64(val) / 10.0
			info.Voltage = fmt.Sprintf("%.1fV", voltage)
		}
	} else if info.ProgrammingP != 0 {
		// Programming voltage from TB1
		info.Voltage = fmt.Sprintf("%dV", info.ProgrammingP)
	} else {
		// Default voltages for modern cards
		info.Voltage = "1.8V, 3V, 5V (Class A/B/C)"
	}
}

func (info *ATRInfo) ToString() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ATR: %X\n", info.Raw))
	sb.WriteString(fmt.Sprintf("  Convention: %s\n", info.Convention()))

	protocols := []string{}
	for _, p := range info.Protocols {
		protocols = append(protocols, fmt.Sprintf("T=%d", p))
	}
	if len(protocols) == 0 {
		protocols = append(protocols, "T=0")
	}
	sb.WriteString(fmt.Sprintf("  Protocols: %s\n", strings.Join(protocols, ", ")))

	if info.Fi > 0 || info.Di > 0 {
		sb.WriteString(fmt.Sprintf("  Transmission: Fi=%d, Di=%d (Baud rate factor: %d)\n", info.Fi, info.Di, info.Fi/info.Di))
	}

	if info.Voltage != "" {
		sb.WriteString(fmt.Sprintf("  Voltage: %s\n", info.Voltage))
	}

	if len(info.HB) > 0 {
		sb.WriteString(fmt.Sprintf("  Historical Bytes: %X", info.HB))
		// Try to extract text
		var text strings.Builder
		for _, b := range info.HB {
			if b >= 0x20 && b < 0x7F {
				text.WriteByte(b)
			}
		}
		if text.Len() > 0 {
			sb.WriteString(fmt.Sprintf(" (\"%s\")", text.String()))
		}
		sb.WriteString("\n")
	}

	if info.TCK != nil {
		sb.WriteString(fmt.Sprintf("  Checksum (TCK): %02X\n", *info.TCK))
	}

	return sb.String()
}

func (info *ATRInfo) Convention() string {
	switch info.TS {
	case 0x3B:
		return "Direct"
	case 0x3F:
		return "Inverse"
	default:
		return "Unknown"
	}
}
