package card_drivers

import (
	"fmt"
	"sim_reader/card"
	"sim_reader/sim"
	"strings"
)

type SysmocomModel int

const (
	SysmoUnknown SysmocomModel = iota
	SysmoUSIM_GR1
	SysmoSIM_GR2
	SysmoUSIM_SJS1
	SysmoISIM_SJA2
	SysmoISIM_SJA5
)

type SysmocomDriver struct {
	model SysmocomModel
}

func init() {
	sim.RegisterDriver(&SysmocomDriver{})
}

func (d *SysmocomDriver) Name() string {
	switch d.model {
	case SysmoUSIM_GR1:
		return "sysmocom sysmoUSIM-GR1"
	case SysmoSIM_GR2:
		return "sysmocom sysmoSIM-GR2"
	case SysmoUSIM_SJS1:
		return "sysmocom sysmoUSIM-SJS1"
	case SysmoISIM_SJA2:
		return "sysmocom sysmoISIM-SJA2"
	case SysmoISIM_SJA5:
		return "sysmocom sysmoISIM-SJA5"
	default:
		return "sysmocom Programmable Card"
	}
}

func (d *SysmocomDriver) BaseCLA() byte {
	switch d.model {
	case SysmoSIM_GR2:
		return 0xA0
	default:
		return 0x00
	}
}

func (d *SysmocomDriver) PrepareWrite(reader *card.Reader) error {
	switch d.model {
	case SysmoUSIM_GR1:
		// Unlock with PIN 32213232 (from pySim SysmoUSIMgr1)
		resp, err := reader.VerifyPIN(0x0A, []byte("32213232"))
		if err != nil {
			return err
		}
		if !resp.IsOK() {
			return fmt.Errorf("GR1 unlock failed: %s", card.SWToString(resp.SW()))
		}
		return nil
	case SysmoSIM_GR2:
		// Super ADM unlock 3838383838383838 (from pySim SysmoSIMgr2)
		resp, err := reader.VerifyPIN(0x0B, []byte("3838383838383838"))
		if err != nil {
			return err
		}
		if !resp.IsOK() {
			return fmt.Errorf("GR2 super-unlock failed: %s", card.SWToString(resp.SW()))
		}
		return nil
	case SysmoUSIM_SJS1, SysmoISIM_SJA2, SysmoISIM_SJA5:
		// Usually requires ADM1 (0x0A) which is handled by sim.SelectUSIMWithAuth
		return nil
	}
	return nil
}

func (d *SysmocomDriver) Identify(reader *card.Reader) bool {
	atr := strings.ToUpper(reader.ATRHex())

	// SJA2
	sja2 := []string{
		"3B9F96801F878031E073FE211B674A4C753034054BA9",
		"3B9F96801F878031E073FE211B674A4C7531330251B2",
		"3B9F96801F878031E073FE211B674A4C5275310451D5",
	}
	for _, p := range sja2 {
		if strings.HasPrefix(atr, p) {
			d.model = SysmoISIM_SJA2
			return true
		}
	}

	// SJA5
	sja5 := []string{
		"3B9F96801F878031E073FE211B674A357530350251CC",
		"3B9F96801F878031E073FE211B674A357530350265F8",
		"3B9F96801F878031E073FE211B674A357530350259C4",
	}
	for _, p := range sja5 {
		if strings.HasPrefix(atr, p) {
			d.model = SysmoISIM_SJA5
			return true
		}
	}

	// SJS1
	if strings.HasPrefix(atr, "3B9F96801FC78031A073BE21136743200718000001A5") {
		d.model = SysmoUSIM_SJS1
		return true
	}

	// GR2
	if strings.HasPrefix(atr, "3B7D9400005555530A7486930B247C4D5468") {
		d.model = SysmoSIM_GR2
		return true
	}

	// GR1 (usually starts with 3B99 or 3B9F)
	if strings.HasPrefix(atr, "3B991800118822334455667760") {
		d.model = SysmoUSIM_GR1
		return true
	}

	return false
}

func (d *SysmocomDriver) WriteKi(reader *card.Reader, ki []byte) error {
	switch d.model {
	case SysmoUSIM_GR1:
		// GR1 uses a special command 00 99 00 00 for Ki+OPc+ICCID+IMSI
		return fmt.Errorf("GR1 requires combined write (not yet supported via direct Ki write)")
	case SysmoSIM_GR2:
		// EF.0001 (from pySim)
		if _, err := reader.SelectByPath([]byte{0x00, 0x01}); err != nil {
			return err
		}
		// Ki at offset 3
		_, err := reader.UpdateBinary(3, ki)
		return err
	case SysmoUSIM_SJS1:
		// EF.00FF (from pySim)
		if _, err := reader.SelectByPath([]byte{0x00, 0xFF}); err != nil {
			return err
		}
		_, err := reader.UpdateBinary(0, ki)
		return err
	case SysmoISIM_SJA2, SysmoISIM_SJA5:
		// EF.6F20 in DF.A515
		if _, err := reader.SelectByPath([]byte{0x3F, 0x00, 0xA5, 0x15, 0x6F, 0x20}); err != nil {
			return err
		}
		// Ki at offset 1
		_, err := reader.UpdateBinary(1, ki)
		return err
	}
	return nil
}

func (d *SysmocomDriver) WriteOPc(reader *card.Reader, opc []byte) error {
	switch d.model {
	case SysmoUSIM_SJS1:
		// EF.00F7 with 01 prefix
		if _, err := reader.SelectByPath([]byte{0x00, 0xF7}); err != nil {
			return err
		}
		data := append([]byte{0x01}, opc...)
		_, err := reader.UpdateBinary(0, data)
		return err
	case SysmoISIM_SJA2, SysmoISIM_SJA5:
		// EF.6F20 in DF.A515, offset 17
		if _, err := reader.SelectByPath([]byte{0xA5, 0x15, 0x6F, 0x20}); err != nil {
			return err
		}
		_, err := reader.UpdateBinary(17, opc)
		return err
	}
	return nil
}

func (d *SysmocomDriver) WriteMilenageRAndC(reader *card.Reader) error {
	return nil
}

func (d *SysmocomDriver) SetAlgorithmType(reader *card.Reader, algo string) error {
	return nil
}

func (d *SysmocomDriver) GetAlgorithmType(reader *card.Reader) (string, error) {
	return "milenage", nil
}

func (d *SysmocomDriver) WriteICCID(reader *card.Reader, iccid string) error {
	if d.model == SysmoISIM_SJA2 || d.model == SysmoISIM_SJA5 {
		return fmt.Errorf("SJA2/SJA5 does not allow ICCID reprogramming (license protection)")
	}
	return sim.WriteICCIDGeneric(reader, iccid)
}

func (d *SysmocomDriver) WriteMSISDN(reader *card.Reader, msisdn string) error {
	return sim.WriteMSISDNGeneric(reader, msisdn)
}

func (d *SysmocomDriver) WriteACC(reader *card.Reader, acc string) error {
	return sim.WriteACCGeneric(reader, acc)
}

func (d *SysmocomDriver) WritePINs(reader *card.Reader, pin1, puk1, pin2, puk2 string) error {
	return nil
}
