package sim

import (
	"encoding/hex"
	"fmt"
	"sim_reader/algorithms"
	"sim_reader/card"
)

// Standard File IDs
var (
	FileSIMMSISDN  = []byte{0x7F, 0x10, 0x6F, 0x40}
	FileUSIMMSISDN = []byte{0x7F, 0xF0, 0x6F, 0x40}
	FileSIMACC     = []byte{0x7F, 0x10, 0x6F, 0x78}
	FileUSIMACC    = []byte{0x7F, 0xF0, 0x6F, 0x78}
)

// Proprietary File IDs for GRv1 cards (from uicc project)
var (
	GRv1FileOPc = []byte{0x7F, 0xF0, 0xFF, 0x01}
	GRv1FileKi  = []byte{0x7F, 0xF0, 0xFF, 0x02}
	GRv1FileR   = []byte{0x7F, 0xF0, 0xFF, 0x03}
	GRv1FileC   = []byte{0x7F, 0xF0, 0xFF, 0x04}
)

// Proprietary File IDs for GRv2 cards (from uicc project)
var (
	GRv2FileAlgType       = []byte{0x2F, 0xD0}
	GRv2FileRC            = []byte{0x2F, 0xE6}
	GRv2FileMilenageParam = []byte{0x2F, 0xE5}
	GRv2FileOPc           = []byte{0x60, 0x02}
	GRv2FileKi            = []byte{0x00, 0x01}
	GRv2FileADM           = []byte{0x0B, 0x00}
	GRv2FilePin1Puk1      = []byte{0x01, 0x00}
	GRv2FilePin2Puk2      = []byte{0x02, 0x00}
)

// WriteKi writes the Subscriber Key (Ki) to a programmable card
func WriteKi(reader *card.Reader, cardType card.ProgrammableCardType, ki []byte) error {
	if len(ki) != 16 {
		return fmt.Errorf("Ki must be 16 bytes (128-bit)")
	}

	switch cardType {
	case card.CardTypeGRv1:
		// GRv1 uses standard USIM commands to proprietary files
		if _, err := reader.SelectByPath(GRv1FileKi); err != nil {
			return fmt.Errorf("failed to select GRv1 Ki file: %w", err)
		}
		if _, err := reader.UpdateBinary(0, ki); err != nil {
			return fmt.Errorf("failed to write GRv1 Ki: %w", err)
		}
		return nil
	case card.CardTypeGRv2:
		// GRv2 uses proprietary low-level APDU commands
		if err := card.GRv2SelectProprietaryFile(reader, GRv2FileKi); err != nil {
			return fmt.Errorf("failed to select GRv2 Ki file: %w", err)
		}
		if err := card.GRv2UpdateProprietaryBinary(reader, 0, ki); err != nil {
			return fmt.Errorf("failed to write GRv2 Ki: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported programmable card type for Ki write: %v", cardType)
	}
}

// WriteOPc writes the Operator Code (OPc) to a programmable card
func WriteOPc(reader *card.Reader, cardType card.ProgrammableCardType, opc []byte) error {
	if len(opc) != 16 {
		return fmt.Errorf("OPc must be 16 bytes (128-bit)")
	}

	switch cardType {
	case card.CardTypeGRv1:
		if _, err := reader.SelectByPath(GRv1FileOPc); err != nil {
			return fmt.Errorf("failed to select GRv1 OPc file: %w", err)
		}
		if _, err := reader.UpdateBinary(0, opc); err != nil {
			return fmt.Errorf("failed to write GRv1 OPc: %w", err)
		}
		return nil
	case card.CardTypeGRv2:
		if err := card.GRv2SelectProprietaryFile(reader, GRv2FileOPc); err != nil {
			return fmt.Errorf("failed to select GRv2 OPc file: %w", err)
		}
		// GRv2 OPc write command is A0 D6 00 00 11 01 [16 bytes OPc]
		apduData := append([]byte{0x01}, opc...)
		if err := card.GRv2UpdateProprietaryBinary(reader, 0, apduData); err != nil {
			return fmt.Errorf("failed to write GRv2 OPc: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported programmable card type for OPc write: %v", cardType)
	}
}

// ComputeAndWriteOPc computes OPc from OP and K, then writes it to the card
func ComputeAndWriteOPc(reader *card.Reader, cardType card.ProgrammableCardType, k, op []byte) error {
	if len(k) != 16 || len(op) != 16 {
		return fmt.Errorf("K and OP must be 16 bytes (128-bit)")
	}
	opc, err := algorithms.ComputeOPc(k, op)
	if err != nil {
		return fmt.Errorf("failed to compute OPc: %w", err)
	}
	return WriteOPc(reader, cardType, opc)
}

// WriteMilenageRAndC writes Milenage R and C constants to a programmable card
func WriteMilenageRAndC(reader *card.Reader, cardType card.ProgrammableCardType) error {
	switch cardType {
	case card.CardTypeGRv1:
		// GRv1 R constants (5 bytes)
		rConstants := []byte{0x40, 0x00, 0x20, 0x40, 0x60}
		if _, err := reader.SelectByPath(GRv1FileR); err != nil {
			return fmt.Errorf("failed to select GRv1 R file: %w", err)
		}
		if _, err := reader.UpdateBinary(0, rConstants); err != nil {
			return fmt.Errorf("failed to write GRv1 R: %w", err)
		}

		// GRv1 C constants (5 records of 16 bytes)
		cConstants := [][]byte{
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
		}
		if _, err := reader.SelectByPath(GRv1FileC); err != nil {
			return fmt.Errorf("failed to select GRv1 C file: %w", err)
		}
		for i, c := range cConstants {
			if _, err := reader.UpdateRecord(byte(i+1), c); err != nil {
				return fmt.Errorf("failed to write GRv1 C record %d: %w", i+1, err)
			}
		}
		return nil
	case card.CardTypeGRv2:
		// GRv2 R constants (5 records)
		rConstants := [][]byte{
			{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
			{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		}
		if err := card.GRv2SelectProprietaryFile(reader, GRv2FileRC); err != nil {
			return fmt.Errorf("failed to select GRv2 RC file: %w", err)
		}
		for i, rVal := range rConstants {
			if err := card.GRv2UpdateProprietaryRecord(reader, byte(i+1), 0x04, rVal); err != nil {
				return fmt.Errorf("failed to write GRv2 R record %d: %w", i+1, err)
			}
		}

		// Milenage parameters (single binary write)
		milenageParam := []byte{0x08, 0x1C, 0x2A, 0x00, 0x01}
		if err := card.GRv2SelectProprietaryFile(reader, GRv2FileMilenageParam); err != nil {
			return fmt.Errorf("failed to select GRv2 Milenage Param file: %w", err)
		}
		if err := card.GRv2UpdateProprietaryBinary(reader, 0, milenageParam); err != nil {
			return fmt.Errorf("failed to write GRv2 Milenage Param: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported programmable card type for Milenage R/C write: %v", cardType)
	}
}

// SetMilenageAlgorithmType sets the authentication algorithm type for GRv2 cards
func SetMilenageAlgorithmType(reader *card.Reader, algoType byte) error {
	// 0x10 = Milenage, 0x20 = XOR
	if err := card.GRv2SelectProprietaryFile(reader, GRv2FileAlgType); err != nil {
		return fmt.Errorf("failed to select GRv2 AlgType file: %w", err)
	}
	if err := card.GRv2UpdateProprietaryBinary(reader, 0, []byte{0x19, algoType}); err != nil {
		return fmt.Errorf("failed to write GRv2 AlgType: %w", err)
	}
	return nil
}

// WriteICCID writes ICCID to the card
func WriteICCID(reader *card.Reader, cardType card.ProgrammableCardType, iccid string) error {
	// Encode ICCID
	encodedICCID, err := EncodeICCID(iccid)
	if err != nil {
		return err
	}

	fileID := []byte{0x2F, 0xE2} // EF_ICCID

	switch cardType {
	case card.CardTypeGRv1, card.CardTypeUnknown:
		if _, err := reader.SelectByPath(fileID); err != nil {
			return fmt.Errorf("failed to select ICCID file: %w", err)
		}
		if _, err := reader.UpdateBinary(0, encodedICCID); err != nil {
			return fmt.Errorf("failed to write ICCID: %w", err)
		}
		return nil
	case card.CardTypeGRv2:
		if err := card.GRv2Handshake(reader); err != nil {
			return fmt.Errorf("GRv2 handshake failed before writing ICCID: %w", err)
		}
		if _, err := reader.SelectByPath(fileID); err != nil {
			return fmt.Errorf("failed to select ICCID file for GRv2: %w", err)
		}
		if _, err := reader.UpdateBinary(0, encodedICCID); err != nil {
			return fmt.Errorf("failed to write ICCID for GRv2: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported programmable card type for ICCID write: %v", cardType)
	}
}

// WriteMSISDN writes MSISDN to the card
func WriteMSISDN(reader *card.Reader, cardType card.ProgrammableCardType, msisdn string) error {
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

	switch cardType {
	case card.CardTypeGRv1, card.CardTypeUnknown:
		if _, err := reader.SelectByPath(filePath); err != nil {
			return fmt.Errorf("failed to select MSISDN file: %w", err)
		}
		if _, err := reader.UpdateRecord(1, encodedMSISDN); err != nil {
			return fmt.Errorf("failed to write MSISDN: %w", err)
		}
		return nil
	case card.CardTypeGRv2:
		if err := card.GRv2Handshake(reader); err != nil {
			return fmt.Errorf("GRv2 handshake failed before writing MSISDN: %w", err)
		}
		if _, err := reader.SelectByPath(filePath); err != nil {
			return fmt.Errorf("failed to select MSISDN file for GRv2: %w", err)
		}
		if _, err := reader.UpdateRecord(1, encodedMSISDN); err != nil {
			return fmt.Errorf("failed to write MSISDN for GRv2: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported programmable card type for MSISDN write: %v", cardType)
	}
}

// WriteACC writes Access Control Class to the card
func WriteACC(reader *card.Reader, cardType card.ProgrammableCardType, acc string) error {
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

	switch cardType {
	case card.CardTypeGRv1, card.CardTypeUnknown:
		if _, err := reader.SelectByPath(filePath); err != nil {
			return fmt.Errorf("failed to select ACC file: %w", err)
		}
		if _, err := reader.UpdateBinary(0, accBytes); err != nil {
			return fmt.Errorf("failed to write ACC: %w", err)
		}
		return nil
	case card.CardTypeGRv2:
		if err := card.GRv2Handshake(reader); err != nil {
			return fmt.Errorf("GRv2 handshake failed before writing ACC: %w", err)
		}
		if _, err := reader.SelectByPath(filePath); err != nil {
			return fmt.Errorf("failed to select ACC file for GRv2: %w", err)
		}
		if _, err := reader.UpdateBinary(0, accBytes); err != nil {
			return fmt.Errorf("failed to write ACC for GRv2: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported programmable card type for ACC write: %v", cardType)
	}
}

// WritePIN1Puk1 writes PIN1 and PUK1 to a GRv2 card
func WritePIN1Puk1(reader *card.Reader, pin1, puk1 []byte) error {
	if len(pin1) != 8 || len(puk1) != 8 {
		return fmt.Errorf("PIN1 and PUK1 must be 8 bytes")
	}
	if err := card.GRv2SelectProprietaryFile(reader, GRv2FilePin1Puk1); err != nil {
		return fmt.Errorf("failed to select GRv2 PIN1/PUK1 file: %w", err)
	}
	apduData := append([]byte{0x00, 0x00, 0x00}, pin1...)
	apduData = append(apduData, puk1...)
	apduData = append(apduData, 0x8A, 0x8A)
	if err := card.GRv2UpdateProprietaryBinary(reader, 0, apduData); err != nil {
		return fmt.Errorf("failed to write GRv2 PIN1/PUK1: %w", err)
	}
	return nil
}

// WritePIN2Puk2 writes PIN2 and PUK2 to a GRv2 card
func WritePIN2Puk2(reader *card.Reader, pin2, puk2 []byte) error {
	if len(pin2) != 8 || len(puk2) != 8 {
		return fmt.Errorf("PIN2 and PUK2 must be 8 bytes")
	}
	if err := card.GRv2SelectProprietaryFile(reader, GRv2FilePin2Puk2); err != nil {
		return fmt.Errorf("failed to select GRv2 PIN2/PUK2 file: %w", err)
	}
	apduData := append([]byte{0x01, 0x00, 0x00}, pin2...)
	apduData = append(apduData, puk2...)
	apduData = append(apduData, 0x8A, 0x8A)
	if err := card.GRv2UpdateProprietaryBinary(reader, 0, apduData); err != nil {
		return fmt.Errorf("failed to write GRv2 PIN2/PUK2: %w", err)
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

