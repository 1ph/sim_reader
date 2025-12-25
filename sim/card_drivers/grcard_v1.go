package card_drivers

import (
	"fmt"
	"sim_reader/card"
	"sim_reader/sim"
)

// Proprietary File IDs for GRv1 cards
var (
	V1FileOPc = []byte{0x7F, 0xF0, 0xFF, 0x01}
	V1FileKi  = []byte{0x7F, 0xF0, 0xFF, 0x02}
	V1FileR   = []byte{0x7F, 0xF0, 0xFF, 0x03}
	V1FileC   = []byte{0x7F, 0xF0, 0xFF, 0x04}
)

type V1Driver struct{}

func init() {
	sim.RegisterDriver(&V1Driver{})
}

func (d *V1Driver) Name() string {
	return "Grcard V1"
}

func (d *V1Driver) BaseCLA() byte {
	return 0x00
}

func (d *V1Driver) PrepareWrite(reader *card.Reader) error {
	return nil
}

func (d *V1Driver) Identify(reader *card.Reader) bool {
	// GRv1 is a fallback driver, it doesn't have a specific ATR pattern
	// In the original code it was used when CardTypeGRv1 or CardTypeUnknown
	// For now, let's make it return false and we'll handle fallback in sim/programmable.go
	// Or we can check if proprietary files exist.
	return false
}

func (d *V1Driver) WriteKi(reader *card.Reader, ki []byte) error {
	if _, err := reader.SelectByPath(V1FileKi); err != nil {
		return fmt.Errorf("failed to select GRv1 Ki file: %w", err)
	}
	if _, err := reader.UpdateBinary(0, ki); err != nil {
		return fmt.Errorf("failed to write GRv1 Ki: %w", err)
	}
	return nil
}

func (d *V1Driver) WriteOPc(reader *card.Reader, opc []byte) error {
	if _, err := reader.SelectByPath(V1FileOPc); err != nil {
		return fmt.Errorf("failed to select GRv1 OPc file: %w", err)
	}
	if _, err := reader.UpdateBinary(0, opc); err != nil {
		return fmt.Errorf("failed to write GRv1 OPc: %w", err)
	}
	return nil
}

func (d *V1Driver) WriteMilenageRAndC(reader *card.Reader) error {
	// GRv1 R constants (5 bytes)
	rConstants := []byte{0x40, 0x00, 0x20, 0x40, 0x60}
	if _, err := reader.SelectByPath(V1FileR); err != nil {
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
	if _, err := reader.SelectByPath(V1FileC); err != nil {
		return fmt.Errorf("failed to select GRv1 C file: %w", err)
	}
	for i, c := range cConstants {
		if _, err := reader.UpdateRecord(byte(i+1), c); err != nil {
			return fmt.Errorf("failed to write GRv1 C record %d: %w", i+1, err)
		}
	}
	return nil
}

func (d *V1Driver) SetAlgorithmType(reader *card.Reader, algo string) error {
	// GRv1 doesn't support switching algorithm type via proprietary files in current code
	return nil
}

func (d *V1Driver) GetAlgorithmType(reader *card.Reader) (string, error) {
	return "milenage", nil
}

func (d *V1Driver) WriteICCID(reader *card.Reader, iccid string) error {
	encoded, err := sim.EncodeICCID(iccid)
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

func (d *V1Driver) WriteMSISDN(reader *card.Reader, msisdn string) error {
	// This is generic logic, but can be driver-specific if needed
	return sim.WriteMSISDNGeneric(reader, msisdn)
}

func (d *V1Driver) WriteACC(reader *card.Reader, acc string) error {
	return sim.WriteACCGeneric(reader, acc)
}

func (d *V1Driver) WritePINs(reader *card.Reader, pin1, puk1, pin2, puk2 string) error {
	// GRv1 doesn't support PIN/PUK writing in current code
	return nil
}
