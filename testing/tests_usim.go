package testing

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"sim_reader/card"
	"sim_reader/sim"
)

// runUSIMTests runs all USIM file tests per TS 31.102
func (s *TestSuite) runUSIMTests() error {
	// Select USIM application first
	usimAID := sim.GetUSIMAID()
	resp, err := s.Reader.Select(usimAID)
	if err != nil {
		s.AddResult(s.fail("usim", "USIM Application Select", "SW=9000", 
			fmt.Sprintf("error: %v", err), "Cannot select USIM application", "TS 31.102"))
		return err
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		s.AddResult(s.failAPDU("usim", "USIM Application Select", usimAID, resp, 
			"SW=9000", "USIM selection failed", "TS 31.102"))
		return fmt.Errorf("USIM selection failed: SW=%04X", resp.SW())
	}
	s.AddResult(s.pass("usim", "USIM Application Select", 
		fmt.Sprintf("SW=%04X, AID=%s", resp.SW(), strings.ToUpper(hex.EncodeToString(usimAID))), 
		"TS 31.102"))

	// Re-authenticate ADM if available
	if len(s.Options.ADMKey) > 0 {
		s.Reader.VerifyADM1(s.Options.ADMKey)
	}

	// Run individual file tests
	s.testEF_IMSI()
	s.testEF_AD()
	s.testEF_UST()
	s.testEF_EST()
	s.testEF_ACC()
	s.testEF_SPN()
	s.testEF_HPPLMN()
	s.testEF_PLMNwAcT()
	s.testEF_OPLMNwAcT()
	s.testEF_HPLMNwAcT()
	s.testEF_FPLMN()
	s.testEF_LOCI()
	s.testEF_PSLOCI()
	s.testEF_EPSLOCI()
	s.testEF_Keys()
	s.testEF_KeysPS()
	s.testEF_LI()
	s.testEF_START_HFN()
	s.testEF_THRESHOLD()
	s.testEF_SMS()
	s.testEF_SMSP()
	s.testEF_MSISDN()
	s.testEF_ECC()

	return nil
}

// testEF_IMSI tests EF.IMSI (6F07) - mandatory file
func (s *TestSuite) testEF_IMSI() {
	start := time.Now()
	name := "EF.IMSI (6F07)"
	spec := "TS 31.102 4.2.2"
	
	resp, raw, err := s.readEF(0x6F07)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false, 
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	// IMSI should be 9 bytes, first byte is length
	if len(raw) != 9 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: "9 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Error: "Invalid IMSI length", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	imsi := sim.DecodeIMSI(raw)
	if len(imsi) < 14 || len(imsi) > 15 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: "14-15 digits", Actual: fmt.Sprintf("%d digits: %s", len(imsi), imsi),
			Error: "Invalid IMSI format", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: imsi, SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_AD tests EF.AD (6FAD) - Administrative Data
func (s *TestSuite) testEF_AD() {
	start := time.Now()
	name := "EF.AD (6FAD)"
	spec := "TS 31.102 4.2.18"
	
	resp, raw, err := s.readEF(0x6FAD)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	// AD should be at least 4 bytes
	if len(raw) < 4 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: ">=4 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Error: "AD too short", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	ad := sim.DecodeAD(raw)
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("Mode=%s, MNC_len=%d", ad.UEMode, ad.MNCLength),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_UST tests EF.UST (6F38) - USIM Service Table
func (s *TestSuite) testEF_UST() {
	start := time.Now()
	name := "EF.UST (6F38)"
	spec := "TS 31.102 4.2.8"
	
	resp, raw, err := s.readEF(0x6F38)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	// UST should be at least 1 byte
	if len(raw) < 1 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: ">=1 byte", Actual: "0 bytes",
			Error: "UST empty", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	ust := sim.DecodeUST(raw)
	enabledCount := 0
	for _, enabled := range ust {
		if enabled {
			enabledCount++
		}
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("%d bytes, %d services enabled", len(raw), enabledCount),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_EST tests EF.EST (6F56) - Enabled Services Table
func (s *TestSuite) testEF_EST() {
	start := time.Now()
	name := "EF.EST (6F56)"
	spec := "TS 31.102 4.2.47"
	
	resp, raw, err := s.readEF(0x6F56)
	if err != nil {
		// EST is optional
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("%d bytes", len(raw)),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_ACC tests EF.ACC (6F78) - Access Control Class
func (s *TestSuite) testEF_ACC() {
	start := time.Now()
	name := "EF.ACC (6F78)"
	spec := "TS 31.102 4.2.15"
	
	resp, raw, err := s.readEF(0x6F78)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	if len(raw) != 2 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: "2 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Error: "Invalid ACC length", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	accValue := int(raw[0])<<8 | int(raw[1])
	var classes []string
	for i := 0; i < 16; i++ {
		if accValue&(1<<i) != 0 {
			classes = append(classes, fmt.Sprintf("%d", i))
		}
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("0x%04X (classes: %s)", accValue, strings.Join(classes, ",")),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_SPN tests EF.SPN (6F46) - Service Provider Name
func (s *TestSuite) testEF_SPN() {
	start := time.Now()
	name := "EF.SPN (6F46)"
	spec := "TS 31.102 4.2.12"
	
	resp, raw, err := s.readEF(0x6F46)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	spn := sim.DecodeSPN(raw)
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("\"%s\"", spn),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_HPPLMN tests EF.HPPLMN (6F31) - HPLMN Search Period
func (s *TestSuite) testEF_HPPLMN() {
	start := time.Now()
	name := "EF.HPPLMN (6F31)"
	spec := "TS 31.102 4.2.6"
	
	resp, raw, err := s.readEF(0x6F31)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	if len(raw) < 1 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: "Empty file", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	period := int(raw[0]) * 6 // in minutes (6 min units)
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("%d min (raw=0x%02X)", period, raw[0]),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_PLMNwAcT tests EF.PLMNwAcT (6F60) - User Controlled PLMN
func (s *TestSuite) testEF_PLMNwAcT() {
	start := time.Now()
	name := "EF.PLMNwAcT (6F60)"
	spec := "TS 31.102 4.2.5"
	
	resp, raw, err := s.readEF(0x6F60)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	// Each entry is 5 bytes (3 PLMN + 2 ACT)
	entries := len(raw) / 5
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("%d bytes, %d entries", len(raw), entries),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_OPLMNwAcT tests EF.OPLMNwAcT (6F61) - Operator Controlled PLMN
func (s *TestSuite) testEF_OPLMNwAcT() {
	start := time.Now()
	name := "EF.OPLMNwAcT (6F61)"
	spec := "TS 31.102 4.2.53"
	
	resp, raw, err := s.readEF(0x6F61)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	entries := len(raw) / 5
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("%d bytes, %d entries", len(raw), entries),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_HPLMNwAcT tests EF.HPLMNwAcT (6F62) - Home PLMN with ACT
func (s *TestSuite) testEF_HPLMNwAcT() {
	start := time.Now()
	name := "EF.HPLMNwAcT (6F62)"
	spec := "TS 31.102 4.2.51"
	
	resp, raw, err := s.readEF(0x6F62)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	entries := len(raw) / 5
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("%d bytes, %d entries", len(raw), entries),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_FPLMN tests EF.FPLMN (6F7B) - Forbidden PLMN
func (s *TestSuite) testEF_FPLMN() {
	start := time.Now()
	name := "EF.FPLMN (6F7B)"
	spec := "TS 31.102 4.2.16"
	
	resp, raw, err := s.readEF(0x6F7B)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	// Each PLMN is 3 bytes
	entries := len(raw) / 3
	nonEmpty := 0
	for i := 0; i < len(raw); i += 3 {
		if i+3 <= len(raw) && raw[i] != 0xFF {
			nonEmpty++
		}
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("%d bytes, %d/%d entries used", len(raw), nonEmpty, entries),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_LOCI tests EF.LOCI (6F7E) - Location Information
func (s *TestSuite) testEF_LOCI() {
	start := time.Now()
	name := "EF.LOCI (6F7E)"
	spec := "TS 31.102 4.2.17"
	
	resp, raw, err := s.readEF(0x6F7E)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	if len(raw) != 11 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: "11 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Error: "Invalid LOCI length", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("11 bytes, raw=%s", strings.ToUpper(hex.EncodeToString(raw[:6]))),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_PSLOCI tests EF.PSLOCI (6F73) - PS Location Information
func (s *TestSuite) testEF_PSLOCI() {
	start := time.Now()
	name := "EF.PSLOCI (6F73)"
	spec := "TS 31.102 4.2.23"
	
	resp, raw, err := s.readEF(0x6F73)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	if len(raw) != 14 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: "14 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Error: "Invalid PSLOCI length", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: "14 bytes",
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_EPSLOCI tests EF.EPSLOCI (6FE3) - EPS Location Information
func (s *TestSuite) testEF_EPSLOCI() {
	start := time.Now()
	name := "EF.EPSLOCI (6FE3)"
	spec := "TS 31.102 4.2.48"
	
	resp, raw, err := s.readEF(0x6FE3)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("%d bytes", len(raw)),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_Keys tests EF.Keys (6F08) - Ciphering and Integrity Keys
func (s *TestSuite) testEF_Keys() {
	start := time.Now()
	name := "EF.Keys (6F08)"
	spec := "TS 31.102 4.2.6"
	
	resp, raw, err := s.readEF(0x6F08)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	if len(raw) != 33 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: "33 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Error: "Invalid Keys length", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	ksi := raw[0]
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("33 bytes, KSI=0x%02X", ksi),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_KeysPS tests EF.KeysPS (6F09) - Ciphering and Integrity Keys for PS
func (s *TestSuite) testEF_KeysPS() {
	start := time.Now()
	name := "EF.KeysPS (6F09)"
	spec := "TS 31.102 4.2.6"
	
	resp, raw, err := s.readEF(0x6F09)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	
	if len(raw) != 33 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: "33 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Error: "Invalid KeysPS length", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	ksi := raw[0]
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("33 bytes, KSI=0x%02X", ksi),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_LI tests EF.LI (6F05) - Language Indication
func (s *TestSuite) testEF_LI() {
	start := time.Now()
	name := "EF.LI (6F05)"
	spec := "TS 31.102 4.2.4"
	
	resp, raw, err := s.readEF(0x6F05)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	// Each language is 2 bytes
	langs := len(raw) / 2
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: fmt.Sprintf("%d bytes, %d languages", len(raw), langs),
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_START_HFN tests EF.START-HFN (6F5B)
func (s *TestSuite) testEF_START_HFN() {
	start := time.Now()
	name := "EF.START-HFN (6F5B)"
	spec := "TS 31.102 4.2.44"
	
	resp, raw, err := s.readEF(0x6F5B)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	if len(raw) != 6 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: "6 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: "6 bytes",
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_THRESHOLD tests EF.THRESHOLD (6F5C)
func (s *TestSuite) testEF_THRESHOLD() {
	start := time.Now()
	name := "EF.THRESHOLD (6F5C)"
	spec := "TS 31.102 4.2.45"
	
	resp, raw, err := s.readEF(0x6F5C)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	if len(raw) != 3 {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: false,
			Expected: "3 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: "3 bytes",
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_SMS tests EF.SMS (6F3C) - Short Messages
func (s *TestSuite) testEF_SMS() {
	start := time.Now()
	name := "EF.SMS (6F3C)"
	spec := "TS 31.102 4.2.25"
	
	// SMS is a linear fixed file - try to get file info
	fid := []byte{0x6F, 0x3C}
	resp, err := s.Reader.Select(fid)
	if err != nil || !resp.IsOK() {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: "Present (linear fixed)",
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_SMSP tests EF.SMSP (6F42) - SMS Parameters
func (s *TestSuite) testEF_SMSP() {
	start := time.Now()
	name := "EF.SMSP (6F42)"
	spec := "TS 31.102 4.2.27"
	
	fid := []byte{0x6F, 0x42}
	resp, err := s.Reader.Select(fid)
	if err != nil || !resp.IsOK() {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: "Present (linear fixed)",
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_MSISDN tests EF.MSISDN (6F40) - Phone number
func (s *TestSuite) testEF_MSISDN() {
	start := time.Now()
	name := "EF.MSISDN (6F40)"
	spec := "TS 31.102 4.2.26"
	
	fid := []byte{0x6F, 0x40}
	resp, err := s.Reader.Select(fid)
	if err != nil || !resp.IsOK() {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: "Present (linear fixed)",
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testEF_ECC tests EF.ECC (6FB7) - Emergency Call Codes
func (s *TestSuite) testEF_ECC() {
	start := time.Now()
	name := "EF.ECC (6FB7)"
	spec := "TS 31.102 4.2.21"
	
	fid := []byte{0x6F, 0xB7}
	resp, err := s.Reader.Select(fid)
	if err != nil || !resp.IsOK() {
		s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}
	
	s.AddResult(TestResult{Name: name, Category: "usim", Passed: true,
		Actual: "Present (linear fixed)",
		SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// Helper: read transparent EF file
func (s *TestSuite) readEF(fid uint16) (*card.APDUResponse, []byte, error) {
	// Select file
	fidBytes := []byte{byte(fid >> 8), byte(fid & 0xFF)}
	resp, err := s.Reader.Select(fidBytes)
	if err != nil {
		return nil, nil, err
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		return resp, nil, fmt.Errorf("select failed: SW=%04X", resp.SW())
	}
	
	// Read binary - returns APDUResponse
	readResp, err := s.Reader.ReadBinary(0, 0)
	if err != nil {
		return nil, nil, err
	}
	if !readResp.IsOK() {
		return readResp, nil, fmt.Errorf("read failed: SW=%04X", readResp.SW())
	}
	
	return resp, readResp.Data, nil
}

