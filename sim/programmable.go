package sim

import (
	"encoding/hex"
	"fmt"
	"sync"

	"sim_reader/algorithms"
	"sim_reader/card"
)

// ProgrammableDriver interface for proprietary card implementations
type ProgrammableDriver interface {
	Name() string
	Identify(reader *card.Reader) bool
	BaseCLA() byte                          // Returns 0x00 or 0xA0
	PrepareWrite(reader *card.Reader) error // Called before any write operation
	WriteKi(reader *card.Reader, ki []byte) error
	WriteOPc(reader *card.Reader, opc []byte) error
	WriteMilenageRAndC(reader *card.Reader) error
	SetAlgorithmType(reader *card.Reader, algo string) error
	GetAlgorithmType(reader *card.Reader) (string, error)
	WriteICCID(reader *card.Reader, iccid string) error
	WriteMSISDN(reader *card.Reader, msisdn string) error
	WriteACC(reader *card.Reader, acc string) error
	WritePINs(reader *card.Reader, pin1, puk1, pin2, puk2 string) error
}

var (
	registeredDrivers []ProgrammableDriver
	driversMu         sync.RWMutex
)

// RegisterDriver adds a new card driver to the registry
func RegisterDriver(driver ProgrammableDriver) {
	driversMu.Lock()
	defer driversMu.Unlock()
	registeredDrivers = append(registeredDrivers, driver)
}

// FindDriver detects the driver for the current card
func FindDriver(reader *card.Reader) ProgrammableDriver {
	driversMu.RLock()
	defer driversMu.RUnlock()
	for _, d := range registeredDrivers {
		if d.Identify(reader) {
			return d
		}
	}
	return nil
}

// ShowProgrammableCardInfo displays information about the programmable card
func ShowProgrammableCardInfo(reader *card.Reader) string {
	drv := FindDriver(reader)
	if drv != nil {
		return drv.Name()
	}
	return "Standard / Non-programmable (or unrecognized)"
}

// Standard File IDs
var (
	FileSIMMSISDN  = []byte{0x7F, 0x10, 0x6F, 0x40}
	FileUSIMMSISDN = []byte{0x7F, 0xF0, 0x6F, 0x40}
	FileSIMACC     = []byte{0x7F, 0x10, 0x6F, 0x78}
	FileUSIMACC    = []byte{0x7F, 0xF0, 0x6F, 0x78}
)

// WriteKi writes the Subscriber Key (Ki) to a programmable card
func WriteKi(reader *card.Reader, drv ProgrammableDriver, ki []byte) error {
	if len(ki) != 16 {
		return fmt.Errorf("Ki must be 16 bytes (128-bit)")
	}
	if drv == nil {
		return fmt.Errorf("no driver found for this card")
	}
	return drv.WriteKi(reader, ki)
}

// WriteOPc writes the Operator Code (OPc) to a programmable card
func WriteOPc(reader *card.Reader, drv ProgrammableDriver, opc []byte) error {
	if len(opc) != 16 {
		return fmt.Errorf("OPc must be 16 bytes (128-bit)")
	}
	if drv == nil {
		return fmt.Errorf("no driver found for this card")
	}
	return drv.WriteOPc(reader, opc)
}

// ComputeAndWriteOPc computes OPc from OP and K, then writes it to the card
func ComputeAndWriteOPc(reader *card.Reader, drv ProgrammableDriver, k, op []byte) error {
	if len(k) != 16 || len(op) != 16 {
		return fmt.Errorf("K and OP must be 16 bytes (128-bit)")
	}
	opc, err := algorithms.ComputeOPc(k, op)
	if err != nil {
		return fmt.Errorf("failed to compute OPc: %w", err)
	}
	return WriteOPc(reader, drv, opc)
}

// WriteMilenageRAndC writes Milenage R and C constants to a programmable card
func WriteMilenageRAndC(reader *card.Reader, drv ProgrammableDriver) error {
	if drv == nil {
		return fmt.Errorf("no driver found for this card")
	}
	return drv.WriteMilenageRAndC(reader)
}

// SetMilenageAlgorithmType sets the authentication algorithm type
func SetMilenageAlgorithmType(reader *card.Reader, drv ProgrammableDriver, algo string) error {
	if drv == nil {
		return fmt.Errorf("no driver found for this card")
	}
	return drv.SetAlgorithmType(reader, algo)
}

// GetMilenageAlgorithmType returns the current algorithm type
func GetMilenageAlgorithmType(reader *card.Reader, drv ProgrammableDriver) (string, error) {
	if drv == nil {
		return "", fmt.Errorf("no driver found for this card")
	}
	return drv.GetAlgorithmType(reader)
}

// WriteICCID writes ICCID to the card
func WriteICCID(reader *card.Reader, drv ProgrammableDriver, iccid string) error {
	if drv == nil {
		return fmt.Errorf("no driver found for this card")
	}
	return drv.WriteICCID(reader, iccid)
}

// WriteMSISDN writes MSISDN to the card
func WriteMSISDN(reader *card.Reader, drv ProgrammableDriver, msisdn string) error {
	if drv == nil {
		return fmt.Errorf("no driver found for this card")
	}
	return drv.WriteMSISDN(reader, msisdn)
}

// WriteACC writes Access Control Class to the card
func WriteACC(reader *card.Reader, drv ProgrammableDriver, acc string) error {
	if drv == nil {
		return fmt.Errorf("no driver found for this card")
	}
	return drv.WriteACC(reader, acc)
}

// WritePINs writes PIN/PUK codes to the card
func WritePINs(reader *card.Reader, drv ProgrammableDriver, pin1, puk1, pin2, puk2 string) error {
	if drv == nil {
		return fmt.Errorf("no driver found for this card")
	}
	return drv.WritePINs(reader, pin1, puk1, pin2, puk2)
}

// WriteMSISDNGeneric is a default implementation for writing MSISDN
func WriteMSISDNGeneric(reader *card.Reader, msisdn string) error {
	var filePath []byte
	if UseGSMCommands {
		filePath = FileSIMMSISDN
	} else {
		filePath = FileUSIMMSISDN
	}

	// Get file info to determine record length
	fileInfo, err := reader.GetFileInfo(filePath)
	if err != nil {
		return fmt.Errorf("failed to get MSISDN file info: %w", err)
	}
	recordLength := int(fileInfo.RecordLength)

	// Encode MSISDN
	encodedMSISDN := EncodeISDN(msisdn, recordLength)

	if _, err := reader.SelectByPath(filePath); err != nil {
		return fmt.Errorf("failed to select MSISDN file: %w", err)
	}
	if _, err := reader.UpdateRecord(1, encodedMSISDN); err != nil {
		return fmt.Errorf("failed to write MSISDN: %w", err)
	}
	return nil
}

// WriteACCGeneric is a default implementation for writing ACC
func WriteACCGeneric(reader *card.Reader, acc string) error {
	// Parse ACC hex string
	accBytes, err := hex.DecodeString(acc)
	if err != nil || len(accBytes) != 2 {
		return fmt.Errorf("ACC must be 2 bytes hex (4 hex chars)")
	}

	var filePath []byte
	if UseGSMCommands {
		filePath = FileSIMACC
	} else {
		filePath = FileUSIMACC
	}

	if _, err := reader.SelectByPath(filePath); err != nil {
		return fmt.Errorf("failed to select ACC file: %w", err)
	}
	if _, err := reader.UpdateBinary(0, accBytes); err != nil {
		return fmt.Errorf("failed to write ACC: %w", err)
	}
	return nil
}

// WriteICCIDGeneric is a default implementation for writing ICCID
func WriteICCIDGeneric(reader *card.Reader, iccid string) error {
	encoded, err := EncodeICCID(iccid)
	if err != nil {
		return err
	}
	if _, err := reader.SelectByPath([]byte{0x2F, 0xE2}); err != nil {
		return fmt.Errorf("failed to select ICCID file: %w", err)
	}
	if _, err := reader.UpdateBinary(0, encoded); err != nil {
		return fmt.Errorf("failed to write ICCID: %w", err)
	}
	return nil
}

// EncodeICCID encodes ICCID string to BCD format
func EncodeICCID(iccid string) ([]byte, error) {
	if len(iccid) < 18 || len(iccid) > 20 {
		return nil, fmt.Errorf("ICCID must be 18-20 digits")
	}

	result := make([]byte, 10)
	for i := 0; i < 10; i++ {
		idx := i * 2
		d1 := iccid[idx] - '0'
		d2 := byte(0x0F)
		if idx+1 < len(iccid) {
			d2 = iccid[idx+1] - '0'
		}
		result[i] = (d2 << 4) | d1
	}
	return result, nil
}

// EncodeISDN encodes ISDN number (phone number) to SIM format
func EncodeISDN(msisdn string, recordLength int) []byte {
	// MSISDN record format:
	// [Alpha ID (variable)] [Length] [TON/NPI] [Dialing Number (BCD)] [Capability/Config] [Extension]
	// We'll create a minimal record with empty alpha ID

	result := make([]byte, recordLength)
	for i := range result {
		result[i] = 0xFF // Fill with 0xFF (empty)
	}

	// Remove leading '+' if present
	if len(msisdn) > 0 && msisdn[0] == '+' {
		msisdn = msisdn[1:]
	}

	// Calculate BCD length
	bcdLen := (len(msisdn) + 1) / 2
	if bcdLen > 10 {
		bcdLen = 10 // Max 20 digits
	}

	// Start from the end of the record
	offset := recordLength - 14 // Standard MSISDN record layout
	if offset < 0 {
		offset = 0
	}

	// Length of BCD number
	result[offset] = byte(bcdLen + 1) // +1 for TON/NPI byte

	// TON/NPI: 0x91 = international, 0x81 = unknown
	ton := byte(0x91)
	if msisdn[0] == '+' || (len(msisdn) > 0 && msisdn[0] != '0') {
		ton = 0x91 // International
	} else {
		ton = 0x81 // Unknown
	}
	result[offset+1] = ton

	// Encode digits in BCD
	for i := 0; i < len(msisdn) && i < 20; i += 2 {
		d1 := msisdn[i] - '0'
		d2 := byte(0x0F) // Padding
		if i+1 < len(msisdn) {
			d2 = msisdn[i+1] - '0'
		}
		result[offset+2+i/2] = (d2 << 4) | d1
	}

	return result
}
