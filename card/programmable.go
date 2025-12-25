package card

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ProgrammableCardType определяет тип программируемой карты
type ProgrammableCardType int

const (
	CardTypeUnknown  ProgrammableCardType = iota
	CardTypeGRv1                          // Grcard Version 1 (standard USIM commands)
	CardTypeGRv2                          // Grcard Version 2 (low-level proprietary APDU)
	CardTypeSysmocom                      // sysmocom sysmoUSIM-GR1
	CardTypeCustom                        // Custom programmable card (user-defined)
)

// ProgrammableCardInfo содержит информацию о программируемой карте
type ProgrammableCardInfo struct {
	Type        ProgrammableCardType
	Name        string
	Description string
	ATRPattern  string // ATR prefix для определения
	FileIDs     ProgrammableFileIDs
	Commands    ProgrammableCommands
}

// ProgrammableFileIDs содержит File ID проприетарных файлов
type ProgrammableFileIDs struct {
	Ki             []byte // Subscriber key K
	OPc            []byte // Operator code OPc
	OP             []byte // Operator code OP (if supported)
	MilenageR      []byte // Milenage R constants
	MilenageC      []byte // Milenage C constants
	AlgorithmType  []byte // Algorithm selector (Milenage/XOR/TUAK)
	ADMKey         []byte // ADM key file
	PIN1PUK1       []byte // PIN1/PUK1 file
	PIN2PUK2       []byte // PIN2/PUK2 file
	Secret         []byte // Additional secret file
	MilenageParams []byte // Milenage parameters file
}

// ProgrammableCommands содержит специальные команды для активации
type ProgrammableCommands struct {
	HandshakeAPDU string // Команда активации режима программирования
	RequiresGSM   bool   // Требует GSM class commands (A0)
}

// Known programmable card ATR patterns (первые 21 байт ATR)
var knownProgrammableCards = []ProgrammableCardInfo{
	// GRv2 cards - open5gs, Gialer, programmable SIM
	{
		Type:        CardTypeGRv2,
		Name:        "Grcard v2 / open5gs",
		Description: "Programmable USIM card (GRv2 protocol)",
		ATRPattern:  "3B9F95801FC78031A073B6A10067CF3211B252C679",
		FileIDs: ProgrammableFileIDs{
			Ki:             []byte{0x00, 0x01},
			OPc:            []byte{0x60, 0x02},
			AlgorithmType:  []byte{0x2F, 0xD0},
			MilenageR:      []byte{0x2F, 0xE6},
			MilenageParams: []byte{0x2F, 0xE5},
			ADMKey:         []byte{0x0B, 0x00},
			PIN1PUK1:       []byte{0x01, 0x00},
			PIN2PUK2:       []byte{0x02, 0x00},
		},
		Commands: ProgrammableCommands{
			HandshakeAPDU: "A0580000083132333431323334",
			RequiresGSM:   true,
		},
	},
	{
		Type:        CardTypeGRv2,
		Name:        "Grcard v2 variant 1",
		Description: "Programmable USIM card (GRv2 protocol)",
		ATRPattern:  "3B9F94801FC38031A073B6A10067CF3210DF0EF5",
		FileIDs: ProgrammableFileIDs{
			Ki:             []byte{0x00, 0x01},
			OPc:            []byte{0x60, 0x02},
			AlgorithmType:  []byte{0x2F, 0xD0},
			MilenageR:      []byte{0x2F, 0xE6},
			MilenageParams: []byte{0x2F, 0xE5},
			ADMKey:         []byte{0x0B, 0x00},
			PIN1PUK1:       []byte{0x01, 0x00},
			PIN2PUK2:       []byte{0x02, 0x00},
		},
		Commands: ProgrammableCommands{
			HandshakeAPDU: "A0580000083132333431323334",
			RequiresGSM:   true,
		},
	},
	{
		Type:        CardTypeGRv2,
		Name:        "Grcard v2 variant 2",
		Description: "Programmable USIM card (GRv2 protocol)",
		ATRPattern:  "3B9F95801FC78031A073B6A10067CF3211B252C679",
		FileIDs: ProgrammableFileIDs{
			Ki:             []byte{0x00, 0x01},
			OPc:            []byte{0x60, 0x02},
			AlgorithmType:  []byte{0x2F, 0xD0},
			MilenageR:      []byte{0x2F, 0xE6},
			MilenageParams: []byte{0x2F, 0xE5},
			ADMKey:         []byte{0x0B, 0x00},
			PIN1PUK1:       []byte{0x01, 0x00},
			PIN2PUK2:       []byte{0x02, 0x00},
		},
		Commands: ProgrammableCommands{
			HandshakeAPDU: "A0580000083132333431323334",
			RequiresGSM:   true,
		},
	},
	{
		Type:        CardTypeGRv2,
		Name:        "Grcard v2 variant 3",
		Description: "Programmable USIM card (GRv2 protocol)",
		ATRPattern:  "3B9F94801FC38031A073B6A10067CF3250DF0E72",
		FileIDs: ProgrammableFileIDs{
			Ki:             []byte{0x00, 0x01},
			OPc:            []byte{0x60, 0x02},
			AlgorithmType:  []byte{0x2F, 0xD0},
			MilenageR:      []byte{0x2F, 0xE6},
			MilenageParams: []byte{0x2F, 0xE5},
			ADMKey:         []byte{0x0B, 0x00},
			PIN1PUK1:       []byte{0x01, 0x00},
			PIN2PUK2:       []byte{0x02, 0x00},
		},
		Commands: ProgrammableCommands{
			HandshakeAPDU: "A0580000083132333431323334",
			RequiresGSM:   true,
		},
	},
	// GRv1 cards - использует стандартные USIM команды с проприетарными File ID
	{
		Type:        CardTypeGRv1,
		Name:        "Grcard v1 / Generic programmable",
		Description: "Generic programmable USIM (GRv1 protocol)",
		ATRPattern:  "", // No specific ATR, fallback
		FileIDs: ProgrammableFileIDs{
			Ki:        []byte{0x7F, 0xF0, 0xFF, 0x02},
			OPc:       []byte{0x7F, 0xF0, 0xFF, 0x01},
			MilenageR: []byte{0x7F, 0xF0, 0xFF, 0x03},
			MilenageC: []byte{0x7F, 0xF0, 0xFF, 0x04},
			Secret:    []byte{0x7F, 0x20, 0x00, 0x01},
		},
		Commands: ProgrammableCommands{
			HandshakeAPDU: "", // No special handshake
			RequiresGSM:   false,
		},
	},
}

// DetectProgrammableCard определяет тип программируемой карты по ATR
func DetectProgrammableCard(atrHex string) *ProgrammableCardInfo {
	atrHex = strings.ToUpper(strings.ReplaceAll(atrHex, " ", ""))

	// Проверяем известные паттерны
	for _, card := range knownProgrammableCards {
		if card.ATRPattern == "" {
			continue // Skip fallback
		}
		pattern := strings.ToUpper(strings.ReplaceAll(card.ATRPattern, " ", ""))
		if strings.HasPrefix(atrHex, pattern) {
			return &card
		}
	}

	return nil
}

// IsProgrammableCard проверяет, является ли карта программируемой
func IsProgrammableCard(atrHex string) bool {
	return DetectProgrammableCard(atrHex) != nil
}

// GetGRv1Fallback возвращает GRv1 fallback конфигурацию
func GetGRv1Fallback() *ProgrammableCardInfo {
	for _, card := range knownProgrammableCards {
		if card.Type == CardTypeGRv1 {
			return &card
		}
	}
	return nil
}

// FormatFileID форматирует File ID для вывода
func FormatFileID(fid []byte) string {
	if len(fid) == 0 {
		return "N/A"
	}
	return strings.ToUpper(hex.EncodeToString(fid))
}

// String returns string representation of card type
func (t ProgrammableCardType) String() string {
	switch t {
	case CardTypeGRv1:
		return "GRv1"
	case CardTypeGRv2:
		return "GRv2"
	case CardTypeSysmocom:
		return "Sysmocom"
	case CardTypeCustom:
		return "Custom"
	default:
		return "Unknown"
	}
}

// ActivateProgrammingMode активирует режим программирования (для GRv2)
func (r *Reader) ActivateProgrammingMode(info *ProgrammableCardInfo) error {
	if info.Commands.HandshakeAPDU == "" {
		return nil // No activation needed
	}

	handshake, err := hex.DecodeString(info.Commands.HandshakeAPDU)
	if err != nil {
		return fmt.Errorf("invalid handshake APDU: %v", err)
	}

	resp, err := r.SendAPDU(handshake)
	if err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}

	if resp.SW() != SW_OK {
		return fmt.Errorf("handshake returned error: %04X", resp.SW())
	}

	return nil
}

// SelectProgrammableFile выбирает проприетарный файл (low-level для GRv2)
func (r *Reader) SelectProgrammableFile(fileID []byte) error {
	if len(fileID) != 2 {
		return fmt.Errorf("invalid file ID length: %d (expected 2)", len(fileID))
	}

	// SELECT command: A0 A4 00 00 02 [FID]
	apdu := []byte{0xA0, 0xA4, 0x00, 0x00, 0x02}
	apdu = append(apdu, fileID...)

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return fmt.Errorf("SELECT failed: %v", err)
	}

	sw := resp.SW()
	// GRv2 cards return 9F10 or 9F16 on successful SELECT
	if sw != SW_OK && sw != 0x9F10 && sw != 0x9F16 && sw != 0x9F17 {
		return fmt.Errorf("SELECT returned error: %04X", sw)
	}

	return nil
}

// UpdateProgrammableFile записывает данные в проприетарный файл (low-level)
func (r *Reader) UpdateProgrammableFile(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("no data to write")
	}
	if len(data) > 255 {
		return fmt.Errorf("data too large: %d bytes (max 255)", len(data))
	}

	// UPDATE BINARY: A0 D6 00 00 [len] [data]
	apdu := []byte{0xA0, 0xD6, 0x00, 0x00, byte(len(data))}
	apdu = append(apdu, data...)

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return fmt.Errorf("UPDATE failed: %v", err)
	}

	if resp.SW() != SW_OK {
		return fmt.Errorf("UPDATE returned error: %04X", resp.SW())
	}

	return nil
}

// UpdateProgrammableRecord записывает запись в файл (для Milenage C constants)
func (r *Reader) UpdateProgrammableRecord(recordNum byte, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("no data to write")
	}
	if len(data) > 255 {
		return fmt.Errorf("data too large: %d bytes (max 255)", len(data))
	}

	// UPDATE RECORD: A0 DC [rec] 04 [len] [data]
	apdu := []byte{0xA0, 0xDC, recordNum, 0x04, byte(len(data))}
	apdu = append(apdu, data...)

	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return fmt.Errorf("UPDATE RECORD failed: %v", err)
	}

	if resp.SW() != SW_OK {
		return fmt.Errorf("UPDATE RECORD returned error: %04X", resp.SW())
	}

	return nil
}

// ValidateKi проверяет корректность Ki (128-bit = 16 bytes = 32 hex chars)
func ValidateKi(kiHex string) error {
	kiHex = strings.ReplaceAll(kiHex, " ", "")
	if len(kiHex) != 32 {
		return fmt.Errorf("Ki must be 32 hex characters (128-bit), got %d", len(kiHex))
	}
	_, err := hex.DecodeString(kiHex)
	if err != nil {
		return fmt.Errorf("Ki is not valid hex: %v", err)
	}
	return nil
}

// ValidateOPc проверяет корректность OPc (128-bit = 16 bytes = 32 hex chars)
func ValidateOPc(opcHex string) error {
	opcHex = strings.ReplaceAll(opcHex, " ", "")
	if len(opcHex) != 32 {
		return fmt.Errorf("OPc must be 32 hex characters (128-bit), got %d", len(opcHex))
	}
	_, err := hex.DecodeString(opcHex)
	if err != nil {
		return fmt.Errorf("OPc is not valid hex: %v", err)
	}
	return nil
}

// Wrapper functions for external use (matching expected API)

// GRv2Handshake performs handshake for GRv2 cards
func GRv2Handshake(r *Reader) error {
	handshake, err := hex.DecodeString("A0580000083132333431323334")
	if err != nil {
		return err
	}
	resp, err := r.SendAPDU(handshake)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	if resp.SW() != SW_OK {
		return fmt.Errorf("handshake returned error: %04X", resp.SW())
	}
	return nil
}

// GRv2SelectProprietaryFile selects a proprietary file
func GRv2SelectProprietaryFile(r *Reader, fileID []byte) error {
	return r.SelectProgrammableFile(fileID)
}

// GRv2UpdateProprietaryBinary updates a proprietary binary file
func GRv2UpdateProprietaryBinary(r *Reader, offset byte, data []byte) error {
	// Note: offset is ignored in GRv2 implementation (always 0)
	return r.UpdateProgrammableFile(data)
}

// GRv2UpdateProprietaryRecord updates a proprietary record
func GRv2UpdateProprietaryRecord(r *Reader, recordNum byte, p2 byte, data []byte) error {
	// Note: p2 is ignored in GRv2 implementation (always 0x04)
	return r.UpdateProgrammableRecord(recordNum, data)
}

// DetectProgrammableCardType detects the type of programmable card based on ATR
func DetectProgrammableCardType(atr []byte) ProgrammableCardType {
	atrHex := fmt.Sprintf("%X", atr)

	for _, card := range knownProgrammableCards {
		if len(atrHex) >= len(card.ATRPattern) && atrHex[:len(card.ATRPattern)] == card.ATRPattern {
			return card.Type
		}
	}

	return CardTypeUnknown
}
