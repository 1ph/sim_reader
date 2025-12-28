package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"sim_reader/output"
	"sim_reader/sim"
)

var (
	// Auth command flags
	authK      string
	authOP     string
	authOPc    string
	authSQN    string
	authAMF    string
	authRAND   string
	authAUTN   string
	authAUTS   string
	authAlgo   string
	authMCC    int
	authMNC    int
	authNoCard bool
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Run authentication test",
	Long: `Run USIM authentication test (Milenage/TUAK algorithm).
Computes authentication vectors and optionally sends AUTHENTICATE to card.

Examples:
  # Compute auth vectors without card (simulation only)
  sim_reader auth -k F2464E3293019A7E51ABAA7B1262B7D8 \
    --opc B10B351A0CCD8BE31E0C9F088945A812 --no-card

  # Compute OPc from OP automatically
  sim_reader auth -k F2464E3293019A7E51ABAA7B1262B7D8 \
    --op CDC202D5123E20F62B6D676AC72CB318 --no-card

  # Run authentication with card
  sim_reader auth -k F2464E3293019A7E51ABAA7B1262B7D8 \
    --opc B10B351A0CCD8BE31E0C9F088945A812 --mcc 250 --mnc 88

  # Use specific SQN
  sim_reader auth -k ... --opc ... --sqn 000000000001 --no-card

  # Send pre-computed AUTN to card (from dump)
  sim_reader auth -k ... --opc ... --rand 7D6AF2DF993240BA... --autn 000000000C80...

  # Process AUTS from dump to extract SQNms (resync)
  sim_reader auth -k ... --opc ... --rand 7D6AF2DF... --auts AABBCCDDEEFF... --no-card

  # TUAK algorithm
  sim_reader auth -k ... --opc ... --algo tuak --no-card`,
	Run: runAuth,
}

func init() {
	authCmd.Flags().StringVarP(&authK, "key", "k", "",
		"Subscriber key K (32 hex chars for 128-bit, 64 for 256-bit)")
	authCmd.Flags().StringVar(&authOP, "op", "",
		"Operator key OP (for computing OPc)")
	authCmd.Flags().StringVar(&authOPc, "opc", "",
		"Precomputed OPc (if OP not provided)")
	authCmd.Flags().StringVar(&authSQN, "sqn", "000000000000",
		"Sequence number SQN (12 hex chars)")
	authCmd.Flags().StringVar(&authAMF, "amf", "8000",
		"Authentication Management Field (4 hex chars)")
	authCmd.Flags().StringVar(&authRAND, "rand", "",
		"Random challenge RAND (32 hex chars, auto-generated if empty)")
	authCmd.Flags().StringVar(&authAUTN, "autn", "",
		"Pre-computed AUTN from dump (32 hex chars, skip calculation)")
	authCmd.Flags().StringVar(&authAUTS, "auts", "",
		"AUTS from dump for SQN resync (28/44/76 hex chars)")
	authCmd.Flags().StringVar(&authAlgo, "algo", "milenage",
		"Algorithm: milenage or tuak")
	authCmd.Flags().IntVar(&authMCC, "mcc", 0,
		"Mobile Country Code (for KASME computation)")
	authCmd.Flags().IntVar(&authMNC, "mnc", 0,
		"Mobile Network Code (for KASME computation)")
	authCmd.Flags().BoolVar(&authNoCard, "no-card", false,
		"Compute auth vectors without sending to card")

	rootCmd.AddCommand(authCmd)
}

func runAuth(cmd *cobra.Command, args []string) {
	// Validate K is provided
	if authK == "" {
		printError("Subscriber key -k/--key is required")
		cmd.Help()
		return
	}

	// Validate OPc or OP is provided
	if authOPc == "" && authOP == "" {
		printError("Either --opc or --op is required")
		return
	}

	fmt.Println()
	if authNoCard {
		printSuccess("Running Authentication Test (no card)...")
	} else {
		printSuccess("Running Authentication Test...")
	}
	fmt.Println()

	// Parse auth config
	authCfg, err := sim.ParseAuthConfig(
		authK, authOP, authOPc,
		authSQN, authAMF, authRAND,
		authAUTN, authAUTS,
		authAlgo,
		authMCC, authMNC,
	)
	if err != nil {
		printError(fmt.Sprintf("Auth config error: %v", err))
		return
	}

	// Run authentication without card if requested
	if authNoCard {
		result, err := sim.RunAuthentication(nil, authCfg)
		if err != nil {
			printError(fmt.Sprintf("Authentication error: %v", err))
		}
		output.PrintAuthResult(result, authAlgo)
		return
	}

	// Connect to reader for card-based auth
	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	result, err := sim.RunAuthentication(reader, authCfg)
	if err != nil {
		printError(fmt.Sprintf("Authentication error: %v", err))
	}

	// Print results
	output.PrintAuthResult(result, authAlgo)

	// If sync failure, show how to update SQN
	if result != nil && result.SyncFail && result.SQNms != "" {
		fmt.Println()
		printWarning("Sync failure detected! SIM card SQN is ahead of network.")
		printSuccess(fmt.Sprintf("SIM SQN (SQNms): %s", result.SQNms))
		nextSQN := sim.IncrementSQNHex(result.SQNms)
		printSuccess(fmt.Sprintf("Use --sqn %s for next authentication (SQNms+1)", nextSQN))
	}
}

