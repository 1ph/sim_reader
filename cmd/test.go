package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"sim_reader/algorithms"
	"sim_reader/card"
	"sim_reader/output"
	"sim_reader/sim"
	"sim_reader/testing"
)

var (
	// Test command flags
	testOutput   string
	testOnly     string
	testAuthK    string
	testAuthOP   string
	testAuthOPc  string
	testAuthSQN  string
	testAuthAMF  string
	testAuthAlgo string
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run SIM card test suite",
	Long: `Run comprehensive SIM card test suite.
Tests USIM files, ISIM files, authentication, APDU commands, and security.

Examples:
  # Run full test suite
  sim_reader test -a 4444444444444444 \
    -k FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 \
    --opc 808182838485868788898A8B8C8D8E8F \
    -o baseline

  # Run only USIM file tests
  sim_reader test -a 4444444444444444 --only usim

  # Run only authentication tests
  sim_reader test --only auth \
    -k FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 \
    --opc 808182838485868788898A8B8C8D8E8F

  # Run multiple categories
  sim_reader test -a 4444444444444444 --only usim,isim

Test categories:
  - usim     USIM application file tests
  - isim     ISIM application file tests
  - auth     Authentication tests (Milenage/TUAK)
  - apdu     Low-level APDU tests
  - security Security-related tests`,
	Run: runTest,
}

func init() {
	testCmd.Flags().StringVarP(&testOutput, "output", "o", "",
		"Output file prefix for test reports (.json + .html)")
	testCmd.Flags().StringVar(&testOnly, "only", "",
		"Run specific test category: usim,isim,auth,apdu,security (comma-separated)")

	// Auth parameters for test suite
	testCmd.Flags().StringVarP(&testAuthK, "key", "k", "",
		"Subscriber key K for auth tests (32 hex chars)")
	testCmd.Flags().StringVar(&testAuthOP, "op", "",
		"Operator key OP for auth tests")
	testCmd.Flags().StringVar(&testAuthOPc, "opc", "",
		"Precomputed OPc for auth tests")
	testCmd.Flags().StringVar(&testAuthSQN, "sqn", "000000000000",
		"Sequence number SQN for auth tests")
	testCmd.Flags().StringVar(&testAuthAMF, "amf", "8000",
		"Authentication Management Field for auth tests")
	testCmd.Flags().StringVar(&testAuthAlgo, "algo", "milenage",
		"Algorithm for auth tests: milenage or tuak")

	rootCmd.AddCommand(testCmd)
}

func runTest(cmd *cobra.Command, args []string) {
	// Connect to reader
	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	fmt.Println()
	printSuccess("Running SIM Card Test Suite...")

	// Parse auth config for tests
	var testK, testOPc []byte
	if testAuthK != "" {
		k, err := sim.ParseHexBytes(testAuthK)
		if err == nil {
			testK = k
		}
	}
	if testAuthOPc != "" {
		opc, err := sim.ParseHexBytes(testAuthOPc)
		if err == nil {
			testOPc = opc
		}
	} else if testAuthOP != "" {
		// Compute OPc from OP
		op, err := sim.ParseHexBytes(testAuthOP)
		if err == nil && len(testK) > 0 {
			computed, _ := algorithms.ComputeOPc(testK, op)
			testOPc = computed
		}
	}

	// Parse ADM key
	var admKeyBytes []byte
	if admKey != "" {
		key, err := card.ParseADMKey(admKey)
		if err == nil {
			admKeyBytes = key
		}
	}

	// Parse SQN and AMF
	var sqnBytes, amfBytes []byte
	if testAuthSQN != "" {
		sqn, _ := sim.ParseHexBytes(testAuthSQN)
		sqnBytes = sqn
	}
	if testAuthAMF != "" {
		amf, _ := sim.ParseHexBytes(testAuthAMF)
		amfBytes = amf
	}

	// Create test options
	opts := testing.TestOptions{
		ADMKey:    admKeyBytes,
		PIN1:      pin1,
		AuthK:     testK,
		AuthOPc:   testOPc,
		AuthSQN:   sqnBytes,
		AuthAMF:   amfBytes,
		Algorithm: testAuthAlgo,
		Verbose:   true,
	}

	// Create and run test suite
	suite := testing.NewTestSuite(reader, opts)

	if testOnly != "" {
		// Run specific categories
		categories := strings.Split(testOnly, ",")
		for _, cat := range categories {
			cat = strings.TrimSpace(cat)
			if err := suite.RunCategory(cat); err != nil {
				printWarning(fmt.Sprintf("Category %s: %v", cat, err))
			}
		}
	} else {
		// Run all tests
		suite.RunAll()
	}

	// Convert results for output
	outResults := make([]output.TestResult, len(suite.Results))
	for i, r := range suite.Results {
		outResults[i] = output.TestResult{
			Name:     r.Name,
			Category: r.Category,
			Passed:   r.Passed,
			Expected: r.Expected,
			Actual:   r.Actual,
			APDU:     r.APDU,
			Response: r.Response,
			SW:       r.SW,
			Error:    r.Error,
			Spec:     r.Spec,
		}
	}

	// Print summary
	output.PrintTestSummary(outResults)

	// Generate reports if output prefix specified
	if testOutput != "" {
		if err := suite.GenerateReport(testOutput); err != nil {
			printError(fmt.Sprintf("Report generation failed: %v", err))
		}
	}
}

