// Package testing provides a comprehensive test suite for SIM/USIM/ISIM cards
// covering 3GPP TS 31.102, TS 31.103 and GSMA SGP.22 specifications.
package testing

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"sim_reader/card"
)

// TestResult represents the result of a single test
type TestResult struct {
	Name     string `json:"name"`
	Category string `json:"category"` // usim, isim, auth, apdu, security
	Passed   bool   `json:"passed"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	APDU     string `json:"apdu,omitempty"`     // hex string of sent command
	Response string `json:"response,omitempty"` // hex string of response
	SW       uint16 `json:"sw,omitempty"`
	Error    string `json:"error,omitempty"`
	Spec     string `json:"spec,omitempty"` // e.g. "TS 31.102 4.2.8"
	Duration time.Duration `json:"duration_ns"`
}

// TestOptions contains configuration for running tests
type TestOptions struct {
	ADMKey    []byte // ADM key for write tests
	PIN1      string // PIN1 for verification tests
	AuthK     []byte // K key for authentication
	AuthOP    []byte // OP for computing OPc
	AuthOPc   []byte // Pre-computed OPc
	AuthSQN   []byte // Sequence number
	AuthAMF   []byte // Authentication Management Field
	Algorithm string // milenage or tuak
	MCC       int    // Mobile Country Code
	MNC       int    // Mobile Network Code
	Verbose   bool   // Verbose output
}

// TestSuite is the main test orchestrator
type TestSuite struct {
	Reader    *card.Reader
	Options   TestOptions
	Results   []TestResult
	StartTime time.Time
	EndTime   time.Time
}

// TestSummary contains aggregated test results
type TestSummary struct {
	Total      int               `json:"total"`
	Passed     int               `json:"passed"`
	Failed     int               `json:"failed"`
	PassRate   float64           `json:"pass_rate"`
	Duration   time.Duration     `json:"duration_ns"`
	ByCategory map[string]int    `json:"by_category"`
	FailedTests []string         `json:"failed_tests,omitempty"`
}

// NewTestSuite creates a new test suite
func NewTestSuite(reader *card.Reader, opts TestOptions) *TestSuite {
	return &TestSuite{
		Reader:  reader,
		Options: opts,
		Results: make([]TestResult, 0),
	}
}

// AddResult adds a test result to the suite
func (s *TestSuite) AddResult(r TestResult) {
	s.Results = append(s.Results, r)
	if s.Options.Verbose {
		status := "✓"
		if !r.Passed {
			status = "✗"
		}
		fmt.Printf("  [%s] %s: %s\n", status, r.Name, r.Actual)
	}
}

// RunAll runs all test categories
func (s *TestSuite) RunAll() error {
	s.StartTime = time.Now()
	
	fmt.Println("\n=== SIM CARD TEST SUITE ===\n")
	
	// Perform warm reset to ensure clean card state
	// This is essential when running tests multiple times without removing the card
	if err := s.Reader.Reconnect(false); err != nil {
		fmt.Printf("Warning: card reset failed: %v (continuing anyway)\n", err)
	}
	
	// Run each category
	categories := []string{"usim", "isim", "auth", "apdu", "security"}
	for _, cat := range categories {
		if err := s.RunCategory(cat); err != nil {
			// Log error but continue with other categories
			fmt.Printf("Warning: %s tests error: %v\n", cat, err)
		}
		// Reset card state between categories to prevent cross-contamination
		s.resetCardState()
	}
	
	s.EndTime = time.Now()
	return nil
}

// resetCardState resets card to a known state after each test category
func (s *TestSuite) resetCardState() {
	// Select MF to reset file context
	s.Reader.Select([]byte{0x3F, 0x00})
}

// RunCategory runs tests for a specific category
func (s *TestSuite) RunCategory(category string) error {
	category = strings.ToLower(strings.TrimSpace(category))
	
	switch category {
	case "usim":
		fmt.Println("--- USIM Tests (TS 31.102) ---")
		return s.runUSIMTests()
	case "isim":
		fmt.Println("--- ISIM Tests (TS 31.103) ---")
		return s.runISIMTests()
	case "auth":
		fmt.Println("--- Authentication Tests ---")
		return s.runAuthTests()
	case "apdu":
		fmt.Println("--- APDU Command Tests (TS 102.221) ---")
		return s.runAPDUTests()
	case "security":
		fmt.Println("--- Security/Negative Tests ---")
		return s.runSecurityTests()
	default:
		return fmt.Errorf("unknown test category: %s", category)
	}
}

// GetSummary returns aggregated test results
func (s *TestSuite) GetSummary() TestSummary {
	summary := TestSummary{
		Total:       len(s.Results),
		ByCategory:  make(map[string]int),
		FailedTests: make([]string, 0),
	}
	
	for _, r := range s.Results {
		if r.Passed {
			summary.Passed++
		} else {
			summary.Failed++
			summary.FailedTests = append(summary.FailedTests, r.Name)
		}
		summary.ByCategory[r.Category]++
	}
	
	if summary.Total > 0 {
		summary.PassRate = float64(summary.Passed) / float64(summary.Total) * 100
	}
	
	summary.Duration = s.EndTime.Sub(s.StartTime)
	
	return summary
}

// Helper functions for creating test results

func (s *TestSuite) pass(category, name, actual, spec string) TestResult {
	return TestResult{
		Name:     name,
		Category: category,
		Passed:   true,
		Actual:   actual,
		Spec:     spec,
	}
}

func (s *TestSuite) fail(category, name, expected, actual, errMsg, spec string) TestResult {
	return TestResult{
		Name:     name,
		Category: category,
		Passed:   false,
		Expected: expected,
		Actual:   actual,
		Error:    errMsg,
		Spec:     spec,
	}
}

func (s *TestSuite) passAPDU(category, name string, apdu []byte, resp *card.APDUResponse, spec string) TestResult {
	return TestResult{
		Name:     name,
		Category: category,
		Passed:   true,
		APDU:     strings.ToUpper(hex.EncodeToString(apdu)),
		Response: strings.ToUpper(hex.EncodeToString(resp.Data)),
		SW:       resp.SW(),
		Actual:   fmt.Sprintf("SW=%04X", resp.SW()),
		Spec:     spec,
	}
}

func (s *TestSuite) failAPDU(category, name string, apdu []byte, resp *card.APDUResponse, expected string, errMsg, spec string) TestResult {
	r := TestResult{
		Name:     name,
		Category: category,
		Passed:   false,
		APDU:     strings.ToUpper(hex.EncodeToString(apdu)),
		Expected: expected,
		Error:    errMsg,
		Spec:     spec,
	}
	if resp != nil {
		r.Response = strings.ToUpper(hex.EncodeToString(resp.Data))
		r.SW = resp.SW()
		r.Actual = fmt.Sprintf("SW=%04X", resp.SW())
	}
	return r
}

