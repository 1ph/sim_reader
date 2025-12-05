package sim

import (
	"fmt"
	"sim_reader/card"
)

// WriteIMPI writes IMS Private User Identity
func WriteIMPI(reader *card.Reader, impi string) error {
	// Select ISIM application
	resp, err := SelectISIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select ISIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("ISIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_IMPI
	resp, err = reader.Select([]byte{0x6F, 0x02})
	if err != nil {
		return fmt.Errorf("failed to select EF_IMPI: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_IMPI selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 128 // Default
	}

	// Encode IMPI
	data := EncodeIMPI(impi, fileSize)

	// Write IMPI
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to write IMPI: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("IMPI write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// WriteIMPU writes IMS Public User Identity (first record)
func WriteIMPU(reader *card.Reader, impu string) error {
	return WriteIMPURecord(reader, impu, 1)
}

// WriteIMPURecord writes IMS Public User Identity to a specific record
func WriteIMPURecord(reader *card.Reader, impu string, recordNum byte) error {
	// Select ISIM application
	resp, err := SelectISIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select ISIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("ISIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_IMPU
	resp, err = reader.Select([]byte{0x6F, 0x04})
	if err != nil {
		return fmt.Errorf("failed to select EF_IMPU: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_IMPU selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get record size from FCP
	recordSize := parseFCPRecordSize(resp.Data)
	if recordSize == 0 {
		recordSize = 128 // Default
	}

	// Encode IMPU
	data := EncodeIMPU(impu, recordSize)

	// Write IMPU record
	resp, err = reader.UpdateRecord(recordNum, data)
	if err != nil {
		return fmt.Errorf("failed to write IMPU: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("IMPU write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// WriteDomain writes Home Network Domain Name
func WriteDomain(reader *card.Reader, domain string) error {
	// Select ISIM application
	resp, err := SelectISIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select ISIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("ISIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_DOMAIN
	resp, err = reader.Select([]byte{0x6F, 0x03})
	if err != nil {
		return fmt.Errorf("failed to select EF_DOMAIN: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_DOMAIN selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 64 // Default
	}

	// Encode domain
	data := EncodeDomain(domain, fileSize)

	// Write domain
	resp, err = reader.UpdateBinary(0, data)
	if err != nil {
		return fmt.Errorf("failed to write domain: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("domain write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// WritePCSCF writes P-CSCF address (first record)
func WritePCSCF(reader *card.Reader, pcscf string) error {
	return WritePCSCFRecord(reader, pcscf, 1)
}

// WritePCSCFRecord writes P-CSCF address to a specific record
func WritePCSCFRecord(reader *card.Reader, pcscf string, recordNum byte) error {
	// Select ISIM application
	resp, err := SelectISIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select ISIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("ISIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_PCSCF
	resp, err = reader.Select([]byte{0x6F, 0x09})
	if err != nil {
		return fmt.Errorf("failed to select EF_PCSCF: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_PCSCF selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get record size from FCP
	recordSize := parseFCPRecordSize(resp.Data)
	if recordSize == 0 {
		recordSize = 64 // Default
	}

	// Encode P-CSCF
	data := EncodePCSCF(pcscf, recordSize)

	// Write P-CSCF record
	resp, err = reader.UpdateRecord(recordNum, data)
	if err != nil {
		return fmt.Errorf("failed to write P-CSCF: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("P-CSCF write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// SetISIMServices enables or disables services in IST
func SetISIMServices(reader *card.Reader, services map[int]bool) error {
	// Select ISIM application
	resp, err := SelectISIMWithAuth(reader)
	if err != nil {
		return fmt.Errorf("failed to select ISIM: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("ISIM selection failed: %s", card.SWToString(resp.SW()))
	}

	// Select EF_IST
	resp, err = reader.Select([]byte{0x6F, 0x07})
	if err != nil {
		return fmt.Errorf("failed to select EF_IST: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("EF_IST selection failed: %s", card.SWToString(resp.SW()))
	}

	// Get file size
	fileSize := parseFCPFileSize(resp.Data)
	if fileSize == 0 {
		fileSize = 2 // Default
	}

	// Read current IST
	currentIST, err := reader.ReadAllBinary(fileSize)
	if err != nil {
		return fmt.Errorf("failed to read current IST: %w", err)
	}

	// Encode new IST
	newIST := EncodeIST(currentIST, services)

	// Write IST
	resp, err = reader.UpdateBinary(0, newIST)
	if err != nil {
		return fmt.Errorf("failed to write IST: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("IST write failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// EnableISIMPCSCF enables P-CSCF service in IST
func EnableISIMPCSCF(reader *card.Reader) error {
	return SetISIMServices(reader, map[int]bool{
		IST_PCSCF_ADDRESS: true,
	})
}

// DisableISIMPCSCF disables P-CSCF service in IST
func DisableISIMPCSCF(reader *card.Reader) error {
	return SetISIMServices(reader, map[int]bool{
		IST_PCSCF_ADDRESS: false,
	})
}

// EnableISIMSMSOverIP enables SMS over IP in IST
func EnableISIMSMSOverIP(reader *card.Reader) error {
	return SetISIMServices(reader, map[int]bool{
		IST_SMS_OVER_IP: true,
	})
}

// DisableISIMSMSOverIP disables SMS over IP in IST
func DisableISIMSMSOverIP(reader *card.Reader) error {
	return SetISIMServices(reader, map[int]bool{
		IST_SMS_OVER_IP: false,
	})
}

// EnableISIMVoiceDomainPref enables Voice Domain Preference in IST
func EnableISIMVoiceDomainPref(reader *card.Reader) error {
	return SetISIMServices(reader, map[int]bool{
		IST_VOICE_DOMAIN_PREF: true,
	})
}

// DisableISIMVoiceDomainPref disables Voice Domain Preference in IST
func DisableISIMVoiceDomainPref(reader *card.Reader) error {
	return SetISIMServices(reader, map[int]bool{
		IST_VOICE_DOMAIN_PREF: false,
	})
}

// WriteAllISIM writes all ISIM parameters at once
func WriteAllISIM(reader *card.Reader, impi, impu, domain, pcscf string) error {
	if impi != "" {
		if err := WriteIMPI(reader, impi); err != nil {
			return fmt.Errorf("write IMPI failed: %w", err)
		}
	}

	if impu != "" {
		if err := WriteIMPU(reader, impu); err != nil {
			return fmt.Errorf("write IMPU failed: %w", err)
		}
	}

	if domain != "" {
		if err := WriteDomain(reader, domain); err != nil {
			return fmt.Errorf("write domain failed: %w", err)
		}
	}

	if pcscf != "" {
		if err := WritePCSCF(reader, pcscf); err != nil {
			return fmt.Errorf("write P-CSCF failed: %w", err)
		}
	}

	return nil
}

// GenerateIMSIdentities generates IMPI and IMPU from IMSI and domain
func GenerateIMSIdentities(imsi, domain string) (impi, impu string) {
	impi = imsi + "@" + domain
	impu = "sip:" + imsi + "@" + domain
	return
}

// GenerateDomainFromPLMN generates IMS domain from MCC and MNC
func GenerateDomainFromPLMN(mcc, mnc string) string {
	// Ensure MNC is 3 digits (pad with leading zero if needed)
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	return fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}
