package card_drivers

import (
	"fmt"
	"sim_reader/card"
	"sim_reader/sim"
	"strings"
)

// RuSIM / OX24 proprietary constants
const (
	NAA_MILENAGE byte = 0x1F
	NAA_S3G_128  byte = 0x2E
	NAA_TUAK     byte = 0x3D
	NAA_S3G_256  byte = 0x4C
)

type RuSIMDriver struct{}

func init() {
	sim.RegisterDriver(&RuSIMDriver{})
}

func (d *RuSIMDriver) Name() string {
	return "RuSIM / OX24"
}

func (d *RuSIMDriver) BaseCLA() byte {
	return 0xA0
}

func (d *RuSIMDriver) PrepareWrite(reader *card.Reader) error {
	return nil
}

func (d *RuSIMDriver) Identify(reader *card.Reader) bool {
	atr := strings.ToUpper(reader.ATRHex())
	prefixes := []string{
		"3B959640F00F050A0F0A",
		"3B9596",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(atr, p) {
			return true
		}
	}
	return false
}

func (d *RuSIMDriver) WriteKi(reader *card.Reader, ki []byte) error {
	// RuSIM usually uses .pcom scripts for Ki write, but we can add native support here
	return fmt.Errorf("direct Ki write not implemented for RuSIM driver yet")
}

func (d *RuSIMDriver) WriteOPc(reader *card.Reader, opc []byte) error {
	return fmt.Errorf("direct OPc write not implemented for RuSIM driver yet")
}

func (d *RuSIMDriver) WriteMilenageRAndC(reader *card.Reader) error {
	return nil
}

func (d *RuSIMDriver) SetAlgorithmType(reader *card.Reader, algo string) error {
	naaByte, err := d.parseAuthAlgo(algo)
	if err != nil {
		return err
	}

	// Select USIM
	if _, err := sim.SelectUSIMWithAuth(reader); err != nil {
		return err
	}

	// Select EF 8F90 (NAA)
	resp, err := reader.SelectGSM([]byte{0x8F, 0x90})
	if err != nil {
		return fmt.Errorf("select EF 8F90 failed: %w", err)
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		return fmt.Errorf("select EF 8F90 failed: %s", card.SWToString(resp.SW()))
	}

	// Write 1 byte
	resp, err = reader.UpdateBinaryGSM(0, []byte{naaByte})
	if err != nil {
		return fmt.Errorf("update EF 8F90 failed: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("update EF 8F90 failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

func (d *RuSIMDriver) GetAlgorithmType(reader *card.Reader) (string, error) {
	// Select USIM
	if _, err := sim.SelectUSIMWithAuth(reader); err != nil {
		return "", err
	}

	// Select EF 8F90
	resp, err := reader.SelectGSM([]byte{0x8F, 0x90})
	if err != nil {
		return "", fmt.Errorf("select EF 8F90 failed: %w", err)
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		return "", fmt.Errorf("select EF 8F90 failed: %s", card.SWToString(resp.SW()))
	}

	// Read 1 byte
	resp, err = reader.ReadBinaryGSM(0, 1)
	if err != nil {
		return "", fmt.Errorf("read EF 8F90 failed: %w", err)
	}
	if !resp.IsOK() {
		return "", fmt.Errorf("read EF 8F90 failed: %s", card.SWToString(resp.SW()))
	}
	if len(resp.Data) < 1 {
		return "", fmt.Errorf("read EF 8F90 returned empty data")
	}

	return d.algoName(resp.Data[0]), nil
}

func (d *RuSIMDriver) WriteICCID(reader *card.Reader, iccid string) error {
	return sim.WriteICCIDGeneric(reader, iccid)
}

func (d *RuSIMDriver) WriteMSISDN(reader *card.Reader, msisdn string) error {
	return sim.WriteMSISDNGeneric(reader, msisdn)
}

func (d *RuSIMDriver) WriteACC(reader *card.Reader, acc string) error {
	return sim.WriteACCGeneric(reader, acc)
}

func (d *RuSIMDriver) WritePINs(reader *card.Reader, pin1, puk1, pin2, puk2 string) error {
	return nil
}

// Internal helpers
func (d *RuSIMDriver) algoName(b byte) string {
	switch b {
	case NAA_MILENAGE:
		return "milenage"
	case NAA_S3G_128:
		return "s3g-128"
	case NAA_TUAK:
		return "tuak"
	case NAA_S3G_256:
		return "s3g-256"
	default:
		return fmt.Sprintf("unknown(0x%02X)", b)
	}
}

func (d *RuSIMDriver) parseAuthAlgo(s string) (byte, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "milenage", "naa_milenage", "1f", "0x1f":
		return NAA_MILENAGE, nil
	case "s3g-128", "s3g128", "s3g_128", "naa_s3g_128", "2e", "0x2e":
		return NAA_S3G_128, nil
	case "tuak", "naa_tuak", "3d", "0x3d":
		return NAA_TUAK, nil
	case "s3g-256", "s3g256", "s3g_256", "naa_s3g_256", "4c", "0x4c":
		return NAA_S3G_256, nil
	default:
		return 0, fmt.Errorf("unknown algorithm: %s", s)
	}
}
