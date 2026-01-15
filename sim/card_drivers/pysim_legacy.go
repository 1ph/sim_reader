package card_drivers

import (
	"encoding/hex"
	"fmt"
	"sim_reader/algorithms"
	"sim_reader/card"
	"sim_reader/sim"
	"strings"
)

const (
	magicSimNameRecord    = 2
	magicSimProgramRecord = 1
)

type magicSimDriver struct {
	driverName string
	namePath   []byte
	dataPath   []byte
	dataLen    int
	kiFile     []byte
}

func init() {
	sim.RegisterDriver(&magicSimDriver{
		driverName: "supersim",
		namePath:   []byte{0x3F, 0x00, 0x7F, 0x4D, 0x8F, 0x0C},
		dataPath:   []byte{0x3F, 0x00, 0x7F, 0x4D, 0x8F, 0x0D},
		dataLen:    74,
	})
	sim.RegisterDriver(&magicSimDriver{
		driverName: "magicsim",
		namePath:   []byte{0x3F, 0x00, 0x7F, 0x4D, 0x8F, 0x0C},
		dataPath:   []byte{0x3F, 0x00, 0x7F, 0x4D, 0x8F, 0x0D},
		dataLen:    130,
		kiFile:     []byte{0x6F, 0x1B},
	})
	sim.RegisterDriver(&fakeMagicSimDriver{})
	sim.RegisterDriver(&grcardLegacyDriver{})
	sim.RegisterDriver(&fairwavesDriver{})
	sim.RegisterDriver(&openCellsDriver{})
	sim.RegisterDriver(&wavemobileDriver{})
	sim.RegisterDriver(&gialerDriver{})
}

func (d *magicSimDriver) Name() string {
	return d.driverName
}

func (d *magicSimDriver) RequiredConfigFields() []string {
	return []string{"ki", "iccid", "imsi", "mcc", "mnc"}
}

func (d *magicSimDriver) Identify(_ *card.Reader) bool {
	return false
}

func (d *magicSimDriver) BaseCLA() byte {
	return 0x00
}

func (d *magicSimDriver) PrepareWrite(_ *card.Reader) error {
	return nil
}

func (d *magicSimDriver) ProgramConfig(reader *card.Reader, config *sim.SIMConfig) (map[string]bool, error) {
	if config.Ki == "" || config.ICCID == "" || config.IMSI == "" || config.MCC == "" || config.MNC == "" {
		return nil, fmt.Errorf("%s requires Ki, ICCID, IMSI, MCC, and MNC", d.driverName)
	}

	spn := strings.TrimSpace(config.SPN)
	if spn == "" {
		spn = "SIM"
	}
	nameBytes := []byte(spn)
	if len(nameBytes) > 16 {
		nameBytes = nameBytes[:16]
	}
	nameData := padFF(nameBytes, 16)
	nameRecord := append(append([]byte{}, nameData...), byte(len(nameBytes)), 0x01)
	if _, err := reader.SelectByPath(d.namePath); err != nil {
		return nil, fmt.Errorf("%s select name file failed: %w", d.driverName, err)
	}
	if _, err := reader.UpdateRecord(magicSimNameRecord, nameRecord); err != nil {
		return nil, fmt.Errorf("%s write name failed: %w", d.driverName, err)
	}

	ki, err := algorithms.ValidateKi(config.Ki)
	if err != nil {
		return nil, err
	}
	iccid, err := sim.EncodeICCID(config.ICCID)
	if err != nil {
		return nil, err
	}
	imsi, err := sim.EncodeIMSI(config.IMSI)
	if err != nil {
		return nil, err
	}
	plmn, err := sim.EncodePLMN(config.MCC, config.MNC)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, d.dataLen)
	if d.kiFile == nil {
		data = append(data, ki...)
	}
	data = appendTLV(data, []byte{0x3F, 0x00, 0x2F, 0xE2}, iccid)
	data = appendTLV(data, []byte{0x7F, 0x20, 0x6F, 0x07}, imsi)
	if d.kiFile != nil {
		data = appendTLV(data, d.kiFile, ki)
	}
	data = appendTLV(data, []byte{0x6F, 0x30}, padFF(plmn, 0x18))
	if config.ACCHex != "" {
		accBytes, err := hex.DecodeString(config.ACCHex)
		if err != nil || len(accBytes) != 2 {
			return nil, fmt.Errorf("ACC must be 2 bytes hex (4 hex chars)")
		}
		data = appendTLV(data, []byte{0x6F, 0x78}, accBytes)
	}

	if _, err := reader.SelectByPath(d.dataPath); err != nil {
		return nil, fmt.Errorf("%s select program file failed: %w", d.driverName, err)
	}
	if _, err := reader.UpdateRecord(magicSimProgramRecord, padFF(data, d.dataLen)); err != nil {
		return nil, fmt.Errorf("%s write program record failed: %w", d.driverName, err)
	}

	if err := writePLMNsel(reader, plmn); err != nil {
		return nil, fmt.Errorf("%s write PLMNsel failed: %w", d.driverName, err)
	}

	handled := map[string]bool{
		"ki":    true,
		"iccid": true,
		"imsi":  true,
		"hplmn": true,
		"spn":   true,
	}
	if config.ACCHex != "" {
		handled["acc"] = true
	}
	return handled, nil
}

func (d *magicSimDriver) WriteKi(_ *card.Reader, _ []byte) error {
	return fmt.Errorf("%s requires config programming", d.driverName)
}

func (d *magicSimDriver) WriteOPc(_ *card.Reader, _ []byte) error {
	return fmt.Errorf("%s does not support OPc", d.driverName)
}

func (d *magicSimDriver) WriteMilenageRAndC(_ *card.Reader) error {
	return nil
}

func (d *magicSimDriver) SetAlgorithmType(_ *card.Reader, _ string) error {
	return nil
}

func (d *magicSimDriver) GetAlgorithmType(_ *card.Reader) (string, error) {
	return "milenage", nil
}

func (d *magicSimDriver) WriteICCID(_ *card.Reader, _ string) error {
	return fmt.Errorf("%s requires config programming", d.driverName)
}

func (d *magicSimDriver) WriteMSISDN(_ *card.Reader, _ string) error {
	return fmt.Errorf("%s does not support MSISDN write", d.driverName)
}

func (d *magicSimDriver) WriteACC(_ *card.Reader, _ string) error {
	return fmt.Errorf("%s requires config programming", d.driverName)
}

func (d *magicSimDriver) WritePINs(_ *card.Reader, _, _, _, _ string) error {
	return nil
}

type fakeMagicSimDriver struct{}

func (d *fakeMagicSimDriver) Name() string {
	return "fakemagicsim"
}

func (d *fakeMagicSimDriver) RequiredConfigFields() []string {
	return []string{"ki", "iccid", "imsi", "mcc", "mnc"}
}

func (d *fakeMagicSimDriver) Identify(_ *card.Reader) bool {
	return false
}

func (d *fakeMagicSimDriver) BaseCLA() byte {
	return 0x00
}

func (d *fakeMagicSimDriver) PrepareWrite(_ *card.Reader) error {
	return nil
}

func (d *fakeMagicSimDriver) ProgramConfig(reader *card.Reader, config *sim.SIMConfig) (map[string]bool, error) {
	if config.Ki == "" || config.ICCID == "" || config.IMSI == "" || config.MCC == "" || config.MNC == "" {
		return nil, fmt.Errorf("fakemagicsim requires Ki, ICCID, IMSI, MCC, and MNC")
	}

	spn := strings.TrimSpace(config.SPN)
	if spn == "" {
		spn = "SIM"
	}

	ki, err := algorithms.ValidateKi(config.Ki)
	if err != nil {
		return nil, err
	}
	iccid, err := sim.EncodeICCID(config.ICCID)
	if err != nil {
		return nil, err
	}
	imsi, err := sim.EncodeIMSI(config.IMSI)
	if err != nil {
		return nil, err
	}
	plmn, err := sim.EncodePLMN(config.MCC, config.MNC)
	if err != nil {
		return nil, err
	}

	if err := writePLMNsel(reader, plmn); err != nil {
		return nil, err
	}

	entry := make([]byte, 0, 0x5A)
	entry = append(entry, 0x81)
	entry = append(entry, padFF([]byte(spn), 14)...)
	entry = append(entry, iccid...)
	entry = append(entry, imsi...)
	entry = append(entry, ki...)
	entry = append(entry, padFF(nil, 40)...)

	if _, err := reader.SelectByPath([]byte{0x3F, 0x00, 0x00, 0x0C}); err != nil {
		return nil, fmt.Errorf("fakemagicsim select record file failed: %w", err)
	}
	if _, err := reader.UpdateRecord(1, entry); err != nil {
		return nil, fmt.Errorf("fakemagicsim write record failed: %w", err)
	}

	return map[string]bool{
		"ki":    true,
		"iccid": true,
		"imsi":  true,
		"hplmn": true,
		"spn":   true,
	}, nil
}

func (d *fakeMagicSimDriver) WriteKi(_ *card.Reader, _ []byte) error {
	return fmt.Errorf("fakemagicsim requires config programming")
}

func (d *fakeMagicSimDriver) WriteOPc(_ *card.Reader, _ []byte) error {
	return fmt.Errorf("fakemagicsim does not support OPc")
}

func (d *fakeMagicSimDriver) WriteMilenageRAndC(_ *card.Reader) error {
	return nil
}

func (d *fakeMagicSimDriver) SetAlgorithmType(_ *card.Reader, _ string) error {
	return nil
}

func (d *fakeMagicSimDriver) GetAlgorithmType(_ *card.Reader) (string, error) {
	return "milenage", nil
}

func (d *fakeMagicSimDriver) WriteICCID(_ *card.Reader, _ string) error {
	return fmt.Errorf("fakemagicsim requires config programming")
}

func (d *fakeMagicSimDriver) WriteMSISDN(_ *card.Reader, _ string) error {
	return fmt.Errorf("fakemagicsim does not support MSISDN write")
}

func (d *fakeMagicSimDriver) WriteACC(_ *card.Reader, _ string) error {
	return fmt.Errorf("fakemagicsim requires config programming")
}

func (d *fakeMagicSimDriver) WritePINs(_ *card.Reader, _, _, _, _ string) error {
	return nil
}

type grcardLegacyDriver struct{}

func (d *grcardLegacyDriver) Name() string {
	return "grcardsim"
}

func (d *grcardLegacyDriver) Identify(_ *card.Reader) bool {
	return false
}

func (d *grcardLegacyDriver) BaseCLA() byte {
	return 0x00
}

func (d *grcardLegacyDriver) PrepareWrite(reader *card.Reader) error {
	pin := defaultAdmPin()
	if len(sim.StoredADMKey) > 0 {
		pin = sim.StoredADMKey
	}
	resp, err := reader.VerifyPIN(0x05, pin)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("grcardsim ADM5 verify failed: %s", card.SWToString(resp.SW()))
	}
	return nil
}

func (d *grcardLegacyDriver) WriteKi(reader *card.Reader, ki []byte) error {
	apdu := append([]byte{0x80, 0xD4, 0x02, 0x00, 0x10}, ki...)
	resp, err := reader.SendAPDU(apdu)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("grcardsim write Ki failed: %s", card.SWToString(resp.SW()))
	}
	return nil
}

func (d *grcardLegacyDriver) WriteOPc(_ *card.Reader, _ []byte) error {
	return fmt.Errorf("grcardsim does not support OPc")
}

func (d *grcardLegacyDriver) WriteMilenageRAndC(_ *card.Reader) error {
	return nil
}

func (d *grcardLegacyDriver) SetAlgorithmType(_ *card.Reader, _ string) error {
	return nil
}

func (d *grcardLegacyDriver) GetAlgorithmType(_ *card.Reader) (string, error) {
	return "milenage", nil
}

func (d *grcardLegacyDriver) WriteICCID(reader *card.Reader, iccid string) error {
	return sim.WriteICCIDGeneric(reader, iccid)
}

func (d *grcardLegacyDriver) WriteMSISDN(reader *card.Reader, msisdn string) error {
	return sim.WriteMSISDNGeneric(reader, msisdn)
}

func (d *grcardLegacyDriver) WriteACC(reader *card.Reader, acc string) error {
	return sim.WriteACCGeneric(reader, acc)
}

func (d *grcardLegacyDriver) WritePINs(_ *card.Reader, _, _, _, _ string) error {
	return nil
}

type fairwavesDriver struct{}

func (d *fairwavesDriver) Name() string {
	return "Fairwaves-SIM"
}

func (d *fairwavesDriver) Identify(reader *card.Reader) bool {
	return strings.EqualFold(reader.ATRHex(), "3B9F96801FC78031A073BE21136744220610000001A9")
}

func (d *fairwavesDriver) BaseCLA() byte {
	return 0xA0
}

func (d *fairwavesDriver) PrepareWrite(reader *card.Reader) error {
	if len(sim.StoredADMKey2) > 0 {
		resp, err := reader.VerifyPIN(0x12, sim.StoredADMKey2)
		if err != nil {
			return err
		}
		if !resp.IsOK() {
			return fmt.Errorf("fairwaves ADM2 verify failed: %s", card.SWToString(resp.SW()))
		}
		return nil
	}
	if len(sim.StoredADMKey) > 0 {
		resp, err := reader.VerifyPIN(0x11, sim.StoredADMKey)
		if err != nil {
			return err
		}
		if !resp.IsOK() {
			return fmt.Errorf("fairwaves ADM1 verify failed: %s", card.SWToString(resp.SW()))
		}
		return nil
	}
	return fmt.Errorf("fairwaves requires ADM key (use --adm or --adm2)")
}

func (d *fairwavesDriver) WriteKi(reader *card.Reader, ki []byte) error {
	if err := selectPathGSM(reader, []byte{0x3F, 0x00, 0x7F, 0x20, 0xFF, 0x02}); err != nil {
		return err
	}
	if _, err := reader.UpdateBinaryGSM(0, ki); err != nil {
		return err
	}
	return nil
}

func (d *fairwavesDriver) WriteOPc(reader *card.Reader, opc []byte) error {
	if err := selectPathGSM(reader, []byte{0x3F, 0x00, 0x7F, 0x20, 0xFF, 0x01}); err != nil {
		return err
	}
	data := append([]byte{0x01}, opc...)
	if _, err := reader.UpdateBinaryGSM(0, data); err != nil {
		return err
	}
	return nil
}

func (d *fairwavesDriver) WriteMilenageRAndC(_ *card.Reader) error {
	return nil
}

func (d *fairwavesDriver) SetAlgorithmType(_ *card.Reader, _ string) error {
	return nil
}

func (d *fairwavesDriver) GetAlgorithmType(_ *card.Reader) (string, error) {
	return "milenage", nil
}

func (d *fairwavesDriver) WriteICCID(_ *card.Reader, _ string) error {
	return fmt.Errorf("fairwaves SIM does not support ICCID write")
}

func (d *fairwavesDriver) WriteMSISDN(reader *card.Reader, msisdn string) error {
	return sim.WriteMSISDNGeneric(reader, msisdn)
}

func (d *fairwavesDriver) WriteACC(reader *card.Reader, acc string) error {
	return sim.WriteACCGeneric(reader, acc)
}

func (d *fairwavesDriver) WritePINs(_ *card.Reader, _, _, _, _ string) error {
	return nil
}

type openCellsDriver struct{}

func (d *openCellsDriver) Name() string {
	return "OpenCells-SIM"
}

func (d *openCellsDriver) Identify(reader *card.Reader) bool {
	return strings.EqualFold(reader.ATRHex(), "3B9F95801FC38031E073FE21135786810286984418A8")
}

func (d *openCellsDriver) BaseCLA() byte {
	return 0xA0
}

func (d *openCellsDriver) PrepareWrite(reader *card.Reader) error {
	if len(sim.StoredADMKey) == 0 {
		return fmt.Errorf("OpenCells requires ADM key (use --adm)")
	}
	resp, err := reader.VerifyPIN(0x0A, sim.StoredADMKey)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("OpenCells ADM verify failed: %s", card.SWToString(resp.SW()))
	}
	return nil
}

func (d *openCellsDriver) WriteKi(reader *card.Reader, ki []byte) error {
	if err := selectPathGSM(reader, []byte{0x3F, 0x00, 0x7F, 0xF0, 0xFF, 0x02}); err != nil {
		return err
	}
	if _, err := reader.UpdateBinaryGSM(0, ki); err != nil {
		return err
	}
	return nil
}

func (d *openCellsDriver) WriteOPc(reader *card.Reader, opc []byte) error {
	if err := selectPathGSM(reader, []byte{0x3F, 0x00, 0x7F, 0xF0, 0xFF, 0x01}); err != nil {
		return err
	}
	if _, err := reader.UpdateBinaryGSM(0, opc); err != nil {
		return err
	}
	return nil
}

func (d *openCellsDriver) WriteMilenageRAndC(_ *card.Reader) error {
	return nil
}

func (d *openCellsDriver) SetAlgorithmType(_ *card.Reader, _ string) error {
	return nil
}

func (d *openCellsDriver) GetAlgorithmType(_ *card.Reader) (string, error) {
	return "milenage", nil
}

func (d *openCellsDriver) WriteICCID(reader *card.Reader, iccid string) error {
	encoded, err := sim.EncodeICCID(iccid)
	if err != nil {
		return err
	}
	if err := selectPathGSM(reader, []byte{0x3F, 0x00, 0x2F, 0xE2}); err != nil {
		return err
	}
	if _, err := reader.UpdateBinaryGSM(0, encoded); err != nil {
		return err
	}
	return nil
}

func (d *openCellsDriver) WriteMSISDN(reader *card.Reader, msisdn string) error {
	return sim.WriteMSISDNGeneric(reader, msisdn)
}

func (d *openCellsDriver) WriteACC(reader *card.Reader, acc string) error {
	return sim.WriteACCGeneric(reader, acc)
}

func (d *openCellsDriver) WritePINs(_ *card.Reader, _, _, _, _ string) error {
	return nil
}

type wavemobileDriver struct{}

func (d *wavemobileDriver) Name() string {
	return "Wavemobile-SIM"
}

func (d *wavemobileDriver) Identify(reader *card.Reader) bool {
	return strings.EqualFold(reader.ATRHex(), "3B9F95801FC78031E073F62113674D4516004301008F")
}

func (d *wavemobileDriver) BaseCLA() byte {
	return 0x00
}

func (d *wavemobileDriver) PrepareWrite(reader *card.Reader) error {
	if len(sim.StoredADMKey) == 0 {
		return fmt.Errorf("Wavemobile requires ADM key (use --adm)")
	}
	resp, err := reader.VerifyPIN(0x0A, sim.StoredADMKey)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("Wavemobile ADM verify failed: %s", card.SWToString(resp.SW()))
	}
	return nil
}

func (d *wavemobileDriver) WriteKi(_ *card.Reader, _ []byte) error {
	return fmt.Errorf("Wavemobile SIM does not support Ki write")
}

func (d *wavemobileDriver) WriteOPc(_ *card.Reader, _ []byte) error {
	return fmt.Errorf("Wavemobile SIM does not support OPc write")
}

func (d *wavemobileDriver) WriteMilenageRAndC(_ *card.Reader) error {
	return nil
}

func (d *wavemobileDriver) SetAlgorithmType(_ *card.Reader, _ string) error {
	return nil
}

func (d *wavemobileDriver) GetAlgorithmType(_ *card.Reader) (string, error) {
	return "milenage", nil
}

func (d *wavemobileDriver) WriteICCID(_ *card.Reader, _ string) error {
	return fmt.Errorf("Wavemobile SIM does not support ICCID write")
}

func (d *wavemobileDriver) WriteMSISDN(reader *card.Reader, msisdn string) error {
	return sim.WriteMSISDNGeneric(reader, msisdn)
}

func (d *wavemobileDriver) WriteACC(reader *card.Reader, acc string) error {
	return sim.WriteACCGeneric(reader, acc)
}

func (d *wavemobileDriver) WritePINs(_ *card.Reader, _, _, _, _ string) error {
	return nil
}

type gialerDriver struct{}

func (d *gialerDriver) Name() string {
	return "gialersim"
}

func (d *gialerDriver) Identify(reader *card.Reader) bool {
	return strings.EqualFold(reader.ATRHex(), "3B9F95801FC78031A073B6A10067CF3215CA9CD70920")
}

func (d *gialerDriver) BaseCLA() byte {
	return 0x00
}

func (d *gialerDriver) PrepareWrite(reader *card.Reader) error {
	key, _ := hex.DecodeString("3834373936313533")
	resp, err := reader.VerifyPIN(0x0C, key)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("gialersim verify failed: %s", card.SWToString(resp.SW()))
	}
	return nil
}

func (d *gialerDriver) WriteKi(reader *card.Reader, ki []byte) error {
	if err := d.PrepareWrite(reader); err != nil {
		return err
	}
	if _, err := reader.SelectByPath([]byte{0x3F, 0x00, 0x00, 0x01}); err != nil {
		return err
	}
	if _, err := reader.UpdateBinary(0, ki); err != nil {
		return err
	}
	return nil
}

func (d *gialerDriver) WriteOPc(reader *card.Reader, opc []byte) error {
	if err := d.PrepareWrite(reader); err != nil {
		return err
	}
	if _, err := reader.SelectByPath([]byte{0x3F, 0x00, 0x60, 0x02}); err != nil {
		return err
	}
	data := append([]byte{0x01}, opc...)
	if _, err := reader.UpdateBinary(0, data); err != nil {
		return err
	}
	return nil
}

func (d *gialerDriver) WriteMilenageRAndC(_ *card.Reader) error {
	return nil
}

func (d *gialerDriver) SetAlgorithmType(_ *card.Reader, _ string) error {
	return nil
}

func (d *gialerDriver) GetAlgorithmType(_ *card.Reader) (string, error) {
	return "milenage", nil
}

func (d *gialerDriver) WriteICCID(reader *card.Reader, iccid string) error {
	return sim.WriteICCIDGeneric(reader, iccid)
}

func (d *gialerDriver) WriteMSISDN(reader *card.Reader, msisdn string) error {
	return sim.WriteMSISDNGeneric(reader, msisdn)
}

func (d *gialerDriver) WriteACC(reader *card.Reader, acc string) error {
	return sim.WriteACCGeneric(reader, acc)
}

func (d *gialerDriver) WritePINs(_ *card.Reader, _, _, _, _ string) error {
	return nil
}

func selectPathGSM(reader *card.Reader, path []byte) error {
	if len(path)%2 != 0 {
		return fmt.Errorf("invalid path length")
	}
	for i := 0; i < len(path); i += 2 {
		resp, err := reader.SelectGSM(path[i : i+2])
		if err != nil {
			return err
		}
		if !resp.IsOK() && !resp.HasMoreData() {
			return fmt.Errorf("select GSM failed: %s", card.SWToString(resp.SW()))
		}
	}
	return nil
}

func appendTLV(dst, tag, value []byte) []byte {
	dst = append(dst, tag...)
	dst = append(dst, byte(len(value)))
	dst = append(dst, value...)
	return dst
}

func padFF(data []byte, length int) []byte {
	if length <= 0 {
		return []byte{}
	}
	out := make([]byte, length)
	for i := range out {
		out[i] = 0xFF
	}
	if len(data) > length {
		copy(out, data[:length])
		return out
	}
	copy(out, data)
	return out
}

func writePLMNsel(reader *card.Reader, plmn []byte) error {
	info, err := reader.GetFileInfo([]byte{0x3F, 0x00, 0x7F, 0x20, 0x6F, 0x30})
	if err != nil {
		return err
	}
	if _, err := reader.SelectByPath([]byte{0x3F, 0x00, 0x7F, 0x20, 0x6F, 0x30}); err != nil {
		return err
	}
	data := padFF(plmn, int(info.FileSize))
	if _, err := reader.UpdateBinary(0, data); err != nil {
		return err
	}
	return nil
}

func defaultAdmPin() []byte {
	key, _ := hex.DecodeString("4444444444444444")
	return key
}
