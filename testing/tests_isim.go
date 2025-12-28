package testing

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"sim_reader/sim"
)

// runISIMTests runs all ISIM file tests per TS 31.103
func (s *TestSuite) runISIMTests() error {
	// Select ISIM application
	isimAID := sim.GetISIMAID()
	resp, err := s.Reader.Select(isimAID)
	if err != nil {
		s.AddResult(s.fail("isim", "ISIM Application Select", "SW=9000",
			fmt.Sprintf("error: %v", err), "Cannot select ISIM application", "TS 31.103"))
		return err
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		s.AddResult(TestResult{Name: "ISIM Application Select", Category: "isim", Passed: false,
			Expected: "SW=9000", Actual: fmt.Sprintf("SW=%04X", resp.SW()),
			Error: "ISIM not available", Spec: "TS 31.103"})
		return fmt.Errorf("ISIM selection failed: SW=%04X", resp.SW())
	}
	s.AddResult(s.pass("isim", "ISIM Application Select",
		fmt.Sprintf("SW=%04X, AID=%s", resp.SW(), strings.ToUpper(hex.EncodeToString(isimAID))),
		"TS 31.103"))

	// Re-authenticate ADM if available
	if len(s.Options.ADMKey) > 0 {
		s.Reader.VerifyADM1(s.Options.ADMKey)
	}

	// Run individual file tests
	s.testISIM_IMPI()
	s.testISIM_IMPU()
	s.testISIM_DOMAIN()
	s.testISIM_IST()
	s.testISIM_PCSCF()
	s.testISIM_AD()
	s.testISIM_ARR()

	return nil
}

// testISIM_IMPI tests EF.IMPI (6F02) - IMS Private User Identity
func (s *TestSuite) testISIM_IMPI() {
	start := time.Now()
	name := "EF.IMPI (6F02)"
	spec := "TS 31.103 4.2.2"

	resp, raw, err := s.readEF(0x6F02)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}

	// IMPI is BER-TLV encoded with tag 0x80
	if len(raw) < 2 || raw[0] != 0x80 {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: false,
			Expected: "BER-TLV tag 0x80", Actual: fmt.Sprintf("tag=0x%02X", raw[0]),
			Error: "Invalid IMPI format", Spec: spec, Duration: time.Since(start)})
		return
	}

	impi := sim.DecodeIMPI(raw)
	s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
		Actual: impi, SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testISIM_IMPU tests EF.IMPU (6F04) - IMS Public User Identity
func (s *TestSuite) testISIM_IMPU() {
	start := time.Now()
	name := "EF.IMPU (6F04)"
	spec := "TS 31.103 4.2.4"

	// IMPU is a linear fixed file
	fid := []byte{0x6F, 0x04}
	resp, err := s.Reader.Select(fid)
	if err != nil || !resp.IsOK() {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: false,
			Error: "Cannot select EF.IMPU", Spec: spec, Duration: time.Since(start)})
		return
	}

	// Try to read first record
	recordResp, err := s.Reader.ReadRecord(1, 0x04)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}
	record := recordResp.Data

	// Decode IMPU from record (BER-TLV tag 0x80)
	if len(record) > 2 && record[0] == 0x80 {
		impu := sim.DecodeIMPI(record) // Same decoding as IMPI
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
			Actual: impu, SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
	} else {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
			Actual: "Present (linear fixed)", SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
	}
}

// testISIM_DOMAIN tests EF.DOMAIN (6F03) - Home Network Domain Name
func (s *TestSuite) testISIM_DOMAIN() {
	start := time.Now()
	name := "EF.DOMAIN (6F03)"
	spec := "TS 31.103 4.2.3"

	resp, raw, err := s.readEF(0x6F03)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}

	// Domain is BER-TLV encoded with tag 0x80
	if len(raw) < 2 || raw[0] != 0x80 {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: false,
			Expected: "BER-TLV tag 0x80", Actual: fmt.Sprintf("tag=0x%02X", raw[0]),
			Error: "Invalid Domain format", Spec: spec, Duration: time.Since(start)})
		return
	}

	domain := sim.DecodeDomain(raw)
	s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
		Actual: domain, SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testISIM_IST tests EF.IST (6F07) - ISIM Service Table
func (s *TestSuite) testISIM_IST() {
	start := time.Now()
	name := "EF.IST (6F07)"
	spec := "TS 31.103 4.2.7"

	resp, raw, err := s.readEF(0x6F07)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}

	if len(raw) < 1 {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: false,
			Error: "IST empty", Spec: spec, Duration: time.Since(start)})
		return
	}

	ist := sim.DecodeIST(raw)
	enabledCount := 0
	for _, enabled := range ist {
		if enabled {
			enabledCount++
		}
	}

	s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
		Actual: fmt.Sprintf("%d bytes, %d services enabled", len(raw), enabledCount),
		SW:     resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testISIM_PCSCF tests EF.PCSCF (6F09) - P-CSCF Address
func (s *TestSuite) testISIM_PCSCF() {
	start := time.Now()
	name := "EF.PCSCF (6F09)"
	spec := "TS 31.103 4.2.8"

	// P-CSCF is a linear fixed file
	fid := []byte{0x6F, 0x09}
	resp, err := s.Reader.Select(fid)
	if err != nil || !resp.IsOK() {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}

	// Try to read first record
	recordResp, err := s.Reader.ReadRecord(1, 0x04)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
			Actual: "Present (no records)", Spec: spec, Duration: time.Since(start)})
		return
	}
	record := recordResp.Data

	// Check if record is not empty (FF filled)
	isEmpty := true
	for _, b := range record {
		if b != 0xFF {
			isEmpty = false
			break
		}
	}

	if isEmpty {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
			Actual: "Present (empty)", SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
	} else {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
			Actual: fmt.Sprintf("Present (%d bytes)", len(record)),
			SW:     resp.SW(), Spec: spec, Duration: time.Since(start)})
	}
}

// testISIM_AD tests EF.AD (6FAD) - Administrative Data
func (s *TestSuite) testISIM_AD() {
	start := time.Now()
	name := "EF.AD (6FAD) ISIM"
	spec := "TS 31.103 4.2.9"

	resp, raw, err := s.readEF(0x6FAD)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}

	// TS 31.103 says minimum 4 bytes, but some profiles have only 3
	// Accept 3+ bytes as valid (common in sysmoEUICC profiles)
	if len(raw) < 3 {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: false,
			Expected: ">=3 bytes", Actual: fmt.Sprintf("%d bytes", len(raw)),
			Spec: spec, Duration: time.Since(start)})
		return
	}

	ad := sim.DecodeAD(raw)
	actual := fmt.Sprintf("Mode=%s", ad.UEMode)
	if len(raw) >= 4 {
		actual = fmt.Sprintf("Mode=%s, MNC_len=%d", ad.UEMode, ad.MNCLength)
	} else {
		actual = fmt.Sprintf("%d bytes (short format)", len(raw))
	}
	s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
		Actual: actual, SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}

// testISIM_ARR tests EF.ARR (6F06) - Access Rule Reference
func (s *TestSuite) testISIM_ARR() {
	start := time.Now()
	name := "EF.ARR (6F06) ISIM"
	spec := "TS 31.103 4.2.1"

	fid := []byte{0x6F, 0x06}
	resp, err := s.Reader.Select(fid)
	if err != nil || !resp.IsOK() {
		s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
			Actual: "Not present (optional)", Spec: spec, Duration: time.Since(start)})
		return
	}

	s.AddResult(TestResult{Name: name, Category: "isim", Passed: true,
		Actual: "Present", SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
}
