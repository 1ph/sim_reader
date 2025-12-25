package card_drivers

import (
	"encoding/hex"
	"fmt"
	"sim_reader/card"
	"sim_reader/sim"
	"strings"
)

// Proprietary File IDs for GRv2 cards
var (
	V2FileAlgType       = []byte{0x2F, 0xD0}
	V2FileRC            = []byte{0x2F, 0xE6}
	V2FileMilenageParam = []byte{0x2F, 0xE5}
	V2FileOPc           = []byte{0x60, 0x02}
	V2FileKi            = []byte{0x00, 0x01}
	V2FileADM           = []byte{0x0B, 0x00}
	V2FilePin1Puk1      = []byte{0x01, 0x00}
	V2FilePin2Puk2      = []byte{0x02, 0x00}
)

type V2Driver struct{}

func init() {
	sim.RegisterDriver(&V2Driver{})
}

func (d *V2Driver) Name() string {
	return "Grcard V2"
}

func (d *V2Driver) BaseCLA() byte {
	return 0xA0
}

func (d *V2Driver) PrepareWrite(reader *card.Reader) error {
	handshake, _ := hex.DecodeString("A0580000083132333431323334")
	resp, err := reader.SendAPDU(handshake)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("handshake returned error: %04X", resp.SW())
	}
	return nil
}

func (d *V2Driver) Identify(reader *card.Reader) bool {
	atrHex := strings.ToUpper(reader.ATRHex())
	// Known GRv2 ATR patterns from card/programmable.go
	patterns := []string{
		"3B9F95801FC78031A073B6A10067CF3211B252C679",
		"3B9F94801FC38031A073B6A10067CF3210DF0EF5",
		"3B9F94801FC38031A073B6A10067CF3250DF0E72",
	}
	for _, p := range patterns {
		if len(atrHex) >= len(p) && atrHex[:len(p)] == p {
			return true
		}
	}
	return false
}

func (d *V2Driver) WriteKi(reader *card.Reader, ki []byte) error {
	if err := d.selectFile(reader, V2FileKi); err != nil {
		return fmt.Errorf("failed to select GRv2 Ki file: %w", err)
	}
	if err := d.updateBinary(reader, ki); err != nil {
		return fmt.Errorf("failed to write GRv2 Ki: %w", err)
	}
	return nil
}

func (d *V2Driver) WriteOPc(reader *card.Reader, opc []byte) error {
	if err := d.selectFile(reader, V2FileOPc); err != nil {
		return fmt.Errorf("failed to select GRv2 OPc file: %w", err)
	}
	// GRv2 OPc write command is A0 D6 00 00 11 01 [16 bytes OPc]
	apduData := append([]byte{0x01}, opc...)
	if err := d.updateBinary(reader, apduData); err != nil {
		return fmt.Errorf("failed to write GRv2 OPc: %w", err)
	}
	return nil
}

func (d *V2Driver) WriteMilenageRAndC(reader *card.Reader) error {
	// GRv2 R constants (5 records)
	rConstants := [][]byte{
		{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
		{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
		{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	if err := d.selectFile(reader, V2FileRC); err != nil {
		return fmt.Errorf("failed to select GRv2 RC file: %w", err)
	}
	for i, rVal := range rConstants {
		if err := d.updateRecord(reader, byte(i+1), rVal); err != nil {
			return fmt.Errorf("failed to write GRv2 R record %d: %w", i+1, err)
		}
	}

	// Milenage parameters (single binary write)
	milenageParam := []byte{0x08, 0x1C, 0x2A, 0x00, 0x01}
	if err := d.selectFile(reader, V2FileMilenageParam); err != nil {
		return fmt.Errorf("failed to select GRv2 Milenage Param file: %w", err)
	}
	if err := d.updateBinary(reader, milenageParam); err != nil {
		return fmt.Errorf("failed to write GRv2 Milenage Param: %w", err)
	}
	return nil
}

func (d *V2Driver) SetAlgorithmType(reader *card.Reader, algo string) error {
	var algoType byte
	switch algo {
	case "milenage":
		algoType = 0x10
	case "xor":
		algoType = 0x20
	default:
		return fmt.Errorf("unsupported algorithm: %s", algo)
	}

	// 0x10 = Milenage, 0x20 = XOR
	if err := d.selectFile(reader, V2FileAlgType); err != nil {
		return fmt.Errorf("failed to select GRv2 AlgType file: %w", err)
	}
	if err := d.updateBinary(reader, []byte{0x19, algoType}); err != nil {
		return fmt.Errorf("failed to write GRv2 AlgType: %w", err)
	}
	return nil
}

func (d *V2Driver) GetAlgorithmType(reader *card.Reader) (string, error) {
	// Not implemented for GRv2 reading in original code
	return "unknown", nil
}

func (d *V2Driver) WriteICCID(reader *card.Reader, iccid string) error {
	if err := d.PrepareWrite(reader); err != nil {
		return fmt.Errorf("GRv2 handshake failed before writing ICCID: %w", err)
	}
	encoded, err := sim.EncodeICCID(iccid)
	if err != nil {
		return err
	}
	if _, err := reader.SelectByPath([]byte{0x2F, 0xE2}); err != nil {
		return fmt.Errorf("failed to select ICCID file for GRv2: %w", err)
	}
	if _, err := reader.UpdateBinary(0, encoded); err != nil {
		return fmt.Errorf("failed to write ICCID for GRv2: %w", err)
	}
	return nil
}

func (d *V2Driver) WriteMSISDN(reader *card.Reader, msisdn string) error {
	if err := d.PrepareWrite(reader); err != nil {
		return fmt.Errorf("GRv2 handshake failed before writing MSISDN: %w", err)
	}
	return sim.WriteMSISDNGeneric(reader, msisdn)
}

func (d *V2Driver) WriteACC(reader *card.Reader, acc string) error {
	if err := d.PrepareWrite(reader); err != nil {
		return fmt.Errorf("GRv2 handshake failed before writing ACC: %w", err)
	}
	return sim.WriteACCGeneric(reader, acc)
}

func (d *V2Driver) WritePINs(reader *card.Reader, pin1, puk1, pin2, puk2 string) error {
	if pin1 != "" && puk1 != "" {
		p1 := sim.EncodePIN(pin1)
		u1 := sim.EncodePIN(puk1)
		if len(p1) != 8 || len(u1) != 8 {
			return fmt.Errorf("PIN1 and PUK1 must be 8 bytes")
		}
		if err := d.selectFile(reader, V2FilePin1Puk1); err != nil {
			return fmt.Errorf("failed to select GRv2 PIN1/PUK1 file: %w", err)
		}
		apduData := append([]byte{0x00, 0x00, 0x00}, p1...)
		apduData = append(apduData, u1...)
		apduData = append(apduData, 0x8A, 0x8A)
		if err := d.updateBinary(reader, apduData); err != nil {
			return fmt.Errorf("failed to write GRv2 PIN1/PUK1: %w", err)
		}
	}

	if pin2 != "" && puk2 != "" {
		p2 := sim.EncodePIN(pin2)
		u2 := sim.EncodePIN(puk2)
		if len(p2) != 8 || len(u2) != 8 {
			return fmt.Errorf("PIN2 and PUK2 must be 8 bytes")
		}
		if err := d.selectFile(reader, V2FilePin2Puk2); err != nil {
			return fmt.Errorf("failed to select GRv2 PIN2/PUK2 file: %w", err)
		}
		apduData := append([]byte{0x01, 0x00, 0x00}, p2...)
		apduData = append(apduData, u2...)
		apduData = append(apduData, 0x8A, 0x8A)
		if err := d.updateBinary(reader, apduData); err != nil {
			return fmt.Errorf("failed to write GRv2 PIN2/PUK2: %w", err)
		}
	}
	return nil
}

// Low-level GRv2 helpers
func (d *V2Driver) selectFile(r *card.Reader, fileID []byte) error {
	if len(fileID) != 2 {
		return fmt.Errorf("invalid file ID length: %d", len(fileID))
	}
	// SELECT command: A0 A4 00 00 02 [FID]
	apdu := []byte{0xA0, 0xA4, 0x00, 0x00, 0x02, fileID[0], fileID[1]}
	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return err
	}
	sw := resp.SW()
	if sw != 0x9000 && sw != 0x9F10 && sw != 0x9F16 && sw != 0x9F17 {
		return fmt.Errorf("SELECT failed: %04X", sw)
	}
	return nil
}

func (d *V2Driver) updateBinary(r *card.Reader, data []byte) error {
	if len(data) > 255 {
		return fmt.Errorf("data too large: %d", len(data))
	}
	// UPDATE BINARY: A0 D6 00 00 [len] [data]
	apdu := append([]byte{0xA0, 0xD6, 0x00, 0x00, byte(len(data))}, data...)
	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("UPDATE failed: %04X", resp.SW())
	}
	return nil
}

func (d *V2Driver) updateRecord(r *card.Reader, recordNum byte, data []byte) error {
	if len(data) > 255 {
		return fmt.Errorf("data too large: %d", len(data))
	}
	// UPDATE RECORD: A0 DC [rec] 04 [len] [data]
	apdu := append([]byte{0xA0, 0xDC, recordNum, 0x04, byte(len(data))}, data...)
	resp, err := r.SendAPDU(apdu)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("UPDATE RECORD failed: %04X", resp.SW())
	}
	return nil
}
