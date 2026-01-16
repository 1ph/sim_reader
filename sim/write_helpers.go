package sim

import (
	"fmt"
	"strings"

	"sim_reader/card"
)

// PLMNEntry represents a PLMN without access technology flags.
type PLMNEntry struct {
	MCC string
	MNC string
}

func WriteHPLMNListDual(reader *card.Reader, entries []HPLMNEntry) error {
	return writePLMNwActDual(reader, entries, "HPLMN", FileSIMHPLMNwAcT, WriteHPLMNList)
}

func WriteOPLMNListDual(reader *card.Reader, entries []HPLMNEntry) error {
	return writePLMNwActDual(reader, entries, "OPLMN", FileSIMOPLMNwAcT, WriteOPLMNList)
}

func WriteUserPLMNListDual(reader *card.Reader, entries []HPLMNEntry) error {
	return writePLMNwActDual(reader, entries, "User PLMN", FileSIMPLMNwAcT, WriteUserPLMNList)
}

func WritePLMNselList(reader *card.Reader, entries []PLMNEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if err := writePLMNselByPath(reader, FileSIMPLMNsel, entries); err != nil {
		return fmt.Errorf("PLMNsel: %w", err)
	}
	return nil
}

func WriteSMSPRecord1SMSC(reader *card.Reader, smsc string) error {
	smsc = strings.TrimSpace(smsc)
	if smsc == "" {
		return nil
	}
	return writeSMSPRecord1DualFromSMSC(reader, smsc)
}

func writePLMNwActDual(reader *card.Reader, entries []HPLMNEntry, label string, simPath []byte, usimWrite func(*card.Reader, []HPLMNEntry) error) error {
	if len(entries) == 0 {
		return nil
	}

	var usimErr error
	if err := usimWrite(reader, entries); err != nil {
		usimErr = err
	}

	var gsmErr error
	if err := writePLMNwActByPath(reader, simPath, entries); err != nil {
		if !(usimErr == nil && isNotFoundError(err)) {
			gsmErr = err
		}
	}

	if usimErr != nil && gsmErr != nil {
		return fmt.Errorf("%s write failed (USIM: %v; GSM: %v)", label, usimErr, gsmErr)
	}
	if usimErr != nil {
		return fmt.Errorf("%s write failed (USIM: %v)", label, usimErr)
	}
	if gsmErr != nil {
		return fmt.Errorf("%s write failed (GSM: %v)", label, gsmErr)
	}
	return nil
}

func writePLMNwActByPath(reader *card.Reader, path []byte, entries []HPLMNEntry) error {
	fcp, err := selectPathWithFCP(reader, path)
	if err != nil {
		return err
	}

	fileSize := parseFCPFileSize(fcp)
	if fileSize == 0 {
		fileSize = 5 * len(entries)
	}

	data := make([]byte, fileSize)
	for i := range data {
		data[i] = 0xFF
	}

	offset := 0
	written := 0
	for _, entry := range entries {
		if offset+5 > fileSize {
			break
		}
		plmn, err := EncodePLMN(entry.MCC, entry.MNC)
		if err != nil {
			continue
		}
		copy(data[offset:offset+3], plmn)
		data[offset+3] = byte(entry.ACT >> 8)
		data[offset+4] = byte(entry.ACT & 0xFF)
		offset += 5
		written++
	}

	if written == 0 {
		return fmt.Errorf("no valid PLMN entries to write")
	}
	return updateBinary(reader, data)
}

func writePLMNselByPath(reader *card.Reader, path []byte, entries []PLMNEntry) error {
	fcp, err := selectPathWithFCP(reader, path)
	if err != nil {
		return err
	}

	fileSize := parseFCPFileSize(fcp)
	if fileSize == 0 {
		fileSize = 3 * len(entries)
	}

	data := make([]byte, fileSize)
	for i := range data {
		data[i] = 0xFF
	}

	offset := 0
	written := 0
	for _, entry := range entries {
		if offset+3 > fileSize {
			break
		}
		plmn, err := EncodePLMN(entry.MCC, entry.MNC)
		if err != nil {
			continue
		}
		copy(data[offset:offset+3], plmn)
		offset += 3
		written++
	}

	if written == 0 {
		return fmt.Errorf("no valid PLMN entries to write")
	}
	return updateBinary(reader, data)
}

func writeSMSPRecord1DualFromSMSC(reader *card.Reader, smsc string) error {
	var errs []string

	if err := writeSMSPRecordADFBySMSC(reader, SelectUSIMWithAuth, smsc); err != nil {
		errs = append(errs, fmt.Sprintf("USIM: %v", err))
	}

	if err := writeSMSPRecordByPathSMSC(reader, FileSIMSMSP, smsc); err != nil {
		if !isNotFoundError(err) {
			errs = append(errs, fmt.Sprintf("GSM: %v", err))
		}
	}

	if HasISIMPath() || len(DetectedISIM_AID) > 0 {
		if err := writeSMSPRecordADFBySMSC(reader, SelectISIMWithAuth, smsc); err != nil {
			if !isNotFoundError(err) {
				errs = append(errs, fmt.Sprintf("ISIM: %v", err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("SMSP write failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func writeSMSPRecordADFBySMSC(reader *card.Reader, selectFunc func(*card.Reader) (*card.APDUResponse, error), smsc string) error {
	resp, err := selectFunc(reader)
	if err != nil {
		return err
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		return fmt.Errorf("ADF selection failed: %s", card.SWToString(resp.SW()))
	}

	resp, err = reader.Select([]byte{0x6F, 0x42})
	if err != nil {
		return fmt.Errorf("failed to select EF_SMSP: %w", err)
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		return fmt.Errorf("EF_SMSP selection failed: %s", card.SWToString(resp.SW()))
	}

	recordSize := parseFCPRecordSize(resp.Data)
	if recordSize == 0 {
		return fmt.Errorf("failed to determine SMSP record size")
	}
	record, err := buildSMSPRecordFromSMSC(recordSize, smsc)
	if err != nil {
		return err
	}
	return updateRecord(reader, 1, record)
}

func writeSMSPRecordByPathSMSC(reader *card.Reader, path []byte, smsc string) error {
	fcp, err := selectPathWithFCP(reader, path)
	if err != nil {
		return err
	}
	recordSize := parseFCPRecordSize(fcp)
	if recordSize == 0 {
		return fmt.Errorf("failed to determine SMSP record size")
	}
	record, err := buildSMSPRecordFromSMSC(recordSize, smsc)
	if err != nil {
		return err
	}
	return updateRecord(reader, 1, record)
}

func writeMSISDNByPath(reader *card.Reader, path []byte, msisdn string) error {
	fcp, err := selectPathWithFCP(reader, path)
	if err != nil {
		return err
	}
	recordLength := parseFCPRecordSize(fcp)
	if recordLength == 0 {
		return fmt.Errorf("failed to determine MSISDN record length")
	}
	encoded := EncodeISDN(msisdn, recordLength)
	return updateRecord(reader, 1, encoded)
}

func buildSMSPRecordFromSMSC(recordLength int, smsc string) ([]byte, error) {
	const fixedFieldsLen = 17 // PI + DCS + PID + VP + SCA(12) + EXT1
	if recordLength < fixedFieldsLen {
		return nil, fmt.Errorf("SMSP record length too small: %d", recordLength)
	}

	alphaLen := recordLength - fixedFieldsLen
	record := make([]byte, recordLength)
	for i := range record {
		record[i] = 0xFF
	}

	piOffset := alphaLen
	dcsOffset := piOffset + 1
	pidOffset := piOffset + 2
	vpOffset := piOffset + 3
	scaOffset := piOffset + 4
	extOffset := piOffset + 16

	record[piOffset] = 0xFF
	record[dcsOffset] = 0xFF
	record[pidOffset] = 0xFF
	record[vpOffset] = 0xFF
	record[extOffset] = 0xFF

	sca, err := encodeSMSCAddress(smsc)
	if err != nil {
		return nil, err
	}
	copy(record[scaOffset:scaOffset+12], padFF(sca, 12))

	return record, nil
}

func encodeSMSCAddress(smsc string) ([]byte, error) {
	digits, intl := normalizePhoneDigits(smsc)
	if digits == "" {
		return nil, fmt.Errorf("SMSC number is empty")
	}
	if len(digits) > 20 {
		digits = digits[:20]
	}

	bcdLen := (len(digits) + 1) / 2
	ton := byte(0x81)
	if intl {
		ton = 0x91
	}

	length := 1 + bcdLen // TON/NPI + digits
	out := make([]byte, 1+length)
	out[0] = byte(length)
	out[1] = ton
	for i := 0; i < len(digits); i += 2 {
		d1 := digits[i] - '0'
		d2 := byte(0x0F)
		if i+1 < len(digits) {
			d2 = digits[i+1] - '0'
		}
		out[2+i/2] = (d2 << 4) | d1
	}
	return out, nil
}

func normalizePhoneDigits(s string) (string, bool) {
	var digits []byte
	intl := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '+' && len(digits) == 0 {
			intl = true
			continue
		}
		if c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	return string(digits), intl
}

func selectPathWithFCP(reader *card.Reader, path []byte) ([]byte, error) {
	if UseGSMCommands {
		return selectPathGSMWithFCP(reader, path)
	}
	resp, err := reader.SelectByPath(path)
	if err != nil {
		return nil, err
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		return nil, fmt.Errorf("select failed: %s", card.SWToString(resp.SW()))
	}
	return resp.Data, nil
}

func selectPathGSMWithFCP(reader *card.Reader, path []byte) ([]byte, error) {
	if len(path)%2 != 0 {
		return nil, fmt.Errorf("invalid path length")
	}
	var last *card.APDUResponse
	for i := 0; i < len(path); i += 2 {
		resp, err := reader.SelectGSM(path[i : i+2])
		if err != nil {
			return nil, err
		}
		if !resp.IsOK() && !resp.HasMoreData() {
			return nil, fmt.Errorf("select GSM failed: %s", card.SWToString(resp.SW()))
		}
		last = resp
	}
	if last == nil {
		return nil, fmt.Errorf("empty path")
	}
	return last.Data, nil
}

func updateBinary(reader *card.Reader, data []byte) error {
	var resp *card.APDUResponse
	var err error
	if UseGSMCommands {
		resp, err = reader.UpdateBinaryGSM(0, data)
	} else {
		resp, err = reader.UpdateBinary(0, data)
	}
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("update binary failed: %s", card.SWToString(resp.SW()))
	}
	return nil
}

func updateRecord(reader *card.Reader, recordNum byte, data []byte) error {
	var resp *card.APDUResponse
	var err error
	if UseGSMCommands {
		resp, err = reader.UpdateRecordGSM(recordNum, data)
	} else {
		resp, err = reader.UpdateRecord(recordNum, data)
	}
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("update record failed: %s", card.SWToString(resp.SW()))
	}
	return nil
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

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "6a82") || strings.Contains(msg, "file not found")
}
