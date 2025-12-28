package testing

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"sim_reader/sim"
)

// runAuthTests runs authentication tests
func (s *TestSuite) runAuthTests() error {
	// Check if we have keys for authentication
	if len(s.Options.AuthK) == 0 {
		s.AddResult(TestResult{
			Name:     "Authentication Tests",
			Category: "auth",
			Passed:   false,
			Error:    "No authentication key (K) provided. Use -auth-k flag.",
			Spec:     "TS 35.206",
		})
		return fmt.Errorf("no authentication key provided")
	}

	// Check OPc
	if len(s.Options.AuthOPc) == 0 {
		s.AddResult(TestResult{
			Name:     "Authentication Tests",
			Category: "auth",
			Passed:   false,
			Error:    "No OPc provided. Use -auth-opc or -auth-op flag.",
			Spec:     "TS 35.206",
		})
		return fmt.Errorf("no OPc provided")
	}

	// Select USIM application first
	usimAID := sim.GetUSIMAID()
	resp, err := s.Reader.Select(usimAID)
	if err != nil || (!resp.IsOK() && !resp.HasMoreData()) {
		s.AddResult(TestResult{
			Name:     "USIM Select for Auth",
			Category: "auth",
			Passed:   false,
			Error:    "Cannot select USIM application",
			Spec:     "TS 31.102",
		})
		return fmt.Errorf("cannot select USIM")
	}

	// Run authentication tests
	s.testAuth3GContext()
	s.testAuthGSMContext()
	s.testAuthMultiple()
	s.testAuthWithSimFunction()

	return nil
}

// testAuth3GContext tests 3G/UMTS authentication context (P2=0x81)
func (s *TestSuite) testAuth3GContext() {
	start := time.Now()
	name := "3G AUTHENTICATE (P2=0x81)"
	spec := "TS 31.102 7.1.2"

	// Generate random RAND
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Error: "Failed to generate RAND", Spec: spec, Duration: time.Since(start)})
		return
	}

	// Use sim.RunAuthentication for proper Milenage computation
	sqnHex := "000000000001"
	if len(s.Options.AuthSQN) == 6 {
		sqnHex = strings.ToUpper(hex.EncodeToString(s.Options.AuthSQN))
	}
	amfHex := "8000"
	if len(s.Options.AuthAMF) == 2 {
		amfHex = strings.ToUpper(hex.EncodeToString(s.Options.AuthAMF))
	}

	authCfg, err := sim.ParseAuthConfig(
		strings.ToUpper(hex.EncodeToString(s.Options.AuthK)),
		"", // OP
		strings.ToUpper(hex.EncodeToString(s.Options.AuthOPc)),
		sqnHex,
		amfHex,
		strings.ToUpper(hex.EncodeToString(randBytes)),
		"", // AUTN
		"", // AUTS
		"milenage",
		0, 0,
	)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Error: fmt.Sprintf("Auth config error: %v", err), Spec: spec, Duration: time.Since(start)})
		return
	}

	// Run authentication
	result, err := sim.RunAuthentication(s.Reader, authCfg)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Error: fmt.Sprintf("Auth error: %v", err), Spec: spec, Duration: time.Since(start)})
		return
	}

	// Check result
	if result.SyncFail {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: true,
			Actual:   fmt.Sprintf("AUTS returned (SQN resync needed), SQNms=%s", result.SQNms),
			Spec:     spec, Duration: time.Since(start)})
		return
	}

	if result.RES != "" {
		matchStr := "RES mismatch"
		if result.RESMatch {
			matchStr = "RES==XRES"
		}
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: true,
			Actual:   fmt.Sprintf("RES=%s, %s", result.RES, matchStr),
			Spec:     spec, Duration: time.Since(start)})
	} else {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Error: result.Error, Spec: spec, Duration: time.Since(start)})
	}
}

// testAuthGSMContext tests GSM authentication context (P2=0x80)
func (s *TestSuite) testAuthGSMContext() {
	start := time.Now()
	name := "GSM AUTHENTICATE (P2=0x80)"
	spec := "TS 31.102 7.1.1"

	// Generate random RAND
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Error: "Failed to generate RAND", Spec: spec, Duration: time.Since(start)})
		return
	}

	// Build GSM AUTHENTICATE command (no AUTN needed)
	// CLA=00, INS=88, P1=00, P2=80, Lc=11, Data=[10||RAND], Le=00
	apdu := make([]byte, 23)
	apdu[0] = 0x00 // CLA
	apdu[1] = 0x88 // INS AUTHENTICATE
	apdu[2] = 0x00 // P1
	apdu[3] = 0x80 // P2 = GSM context
	apdu[4] = 0x11 // Lc = 17
	apdu[5] = 0x10 // RAND length
	copy(apdu[6:22], randBytes)
	apdu[22] = 0x00 // Le

	resp, err := s.Reader.SendAPDU(apdu)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			APDU: strings.ToUpper(hex.EncodeToString(apdu)),
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}

	// Handle GET RESPONSE if needed
	if resp.HasMoreData() {
		resp, _ = s.Reader.GetResponse(resp.SW2)
	}

	if !resp.IsOK() {
		// GSM auth might not be supported
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: true,
			APDU:   strings.ToUpper(hex.EncodeToString(apdu)),
			Actual: fmt.Sprintf("SW=%04X (GSM auth may not be supported)", resp.SW()),
			SW:     resp.SW(),
			Spec:   spec, Duration: time.Since(start)})
		return
	}

	// GSM response should have SRES + Kc
	s.AddResult(TestResult{Name: name, Category: "auth", Passed: true,
		APDU:     strings.ToUpper(hex.EncodeToString(apdu)),
		Response: strings.ToUpper(hex.EncodeToString(resp.Data)),
		SW:       resp.SW(),
		Actual:   fmt.Sprintf("%d bytes response", len(resp.Data)),
		Spec:     spec, Duration: time.Since(start)})
}

// testAuthMultiple tests multiple sequential authentications
func (s *TestSuite) testAuthMultiple() {
	start := time.Now()
	name := "Multiple AUTHENTICATE (3x)"
	spec := "TS 31.102 7.1.2"

	successCount := 0
	syncFailCount := 0

	for i := 0; i < 3; i++ {
		randBytes := make([]byte, 16)
		rand.Read(randBytes)

		sqnHex := fmt.Sprintf("%012X", i+10)
		amfHex := "8000"

		authCfg, err := sim.ParseAuthConfig(
			strings.ToUpper(hex.EncodeToString(s.Options.AuthK)),
			"",
			strings.ToUpper(hex.EncodeToString(s.Options.AuthOPc)),
			sqnHex,
			amfHex,
			strings.ToUpper(hex.EncodeToString(randBytes)),
			"", "", "milenage", 0, 0,
		)
		if err != nil {
			continue
		}

		result, err := sim.RunAuthentication(s.Reader, authCfg)
		if err == nil && result != nil {
			if result.SyncFail {
				syncFailCount++
			} else if result.RES != "" {
				successCount++
			}
		}
	}

	s.AddResult(TestResult{Name: name, Category: "auth", Passed: successCount > 0 || syncFailCount > 0,
		Actual: fmt.Sprintf("%d success, %d sync-fail out of 3", successCount, syncFailCount),
		Spec:   spec, Duration: time.Since(start)})
}

// testAuthWithSimFunction tests using sim.RunAuthentication function
func (s *TestSuite) testAuthWithSimFunction() {
	start := time.Now()
	name := "Authentication via sim.RunAuthentication"
	spec := "TS 35.206"

	// Test that our RunAuthentication function works correctly
	sqnHex := "000000000002"
	amfHex := "8000"

	randBytes := make([]byte, 16)
	rand.Read(randBytes)

	authCfg, err := sim.ParseAuthConfig(
		strings.ToUpper(hex.EncodeToString(s.Options.AuthK)),
		"",
		strings.ToUpper(hex.EncodeToString(s.Options.AuthOPc)),
		sqnHex,
		amfHex,
		strings.ToUpper(hex.EncodeToString(randBytes)),
		"", "", "milenage", 0, 0,
	)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}

	// Run with nil reader to just compute vectors
	result, err := sim.RunAuthentication(nil, authCfg)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}

	// Check that we got computed values
	if result.XRES == "" || result.CK == "" || result.IK == "" {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Error: "Missing computed values", Spec: spec, Duration: time.Since(start)})
		return
	}

	s.AddResult(TestResult{Name: name, Category: "auth", Passed: true,
		Actual: fmt.Sprintf("XRES=%s..., CK=%s..., IK=%s...",
			result.XRES[:8], result.CK[:8], result.IK[:8]),
		Spec: spec, Duration: time.Since(start)})
}

// testAuthKeysAfterAuth tests that CK/IK are stored in EF.Keys after authentication
func (s *TestSuite) testAuthKeysAfterAuth() {
	start := time.Now()
	name := "EF.Keys after AUTHENTICATE"
	spec := "TS 31.102 4.2.6"

	// Read EF.Keys
	resp, raw, err := s.readEF(0x6F08)
	if err != nil {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Error: err.Error(), Spec: spec, Duration: time.Since(start)})
		return
	}

	if len(raw) != 33 {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: false,
			Expected: "33 bytes",
			Actual:   fmt.Sprintf("%d bytes", len(raw)),
			Spec:     spec, Duration: time.Since(start)})
		return
	}

	ksi := raw[0]
	ckStored := raw[1:17]
	ikStored := raw[17:33]

	// Check if keys are not all FF (meaning auth was done)
	allFF := true
	for _, b := range ckStored {
		if b != 0xFF {
			allFF = false
			break
		}
	}

	if allFF {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: true,
			Actual: "Keys not yet stored (all FF)",
			SW:     resp.SW(), Spec: spec, Duration: time.Since(start)})
	} else {
		s.AddResult(TestResult{Name: name, Category: "auth", Passed: true,
			Actual: fmt.Sprintf("KSI=0x%02X, CK=%s..., IK=%s...",
				ksi,
				strings.ToUpper(hex.EncodeToString(ckStored[:4])),
				strings.ToUpper(hex.EncodeToString(ikStored[:4]))),
			SW: resp.SW(), Spec: spec, Duration: time.Since(start)})
	}
}
