package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"sim_reader/output"
	"sim_reader/sim"
)

var progCmd = &cobra.Command{
	Use:   "prog",
	Short: "Programmable card operations",
	Long: `Operations for programmable SIM cards (Grcard, sysmoUSIM, etc.).

WARNING: These operations are DANGEROUS and can PERMANENTLY BRICK your card!
Only use on blank/programmable SIM cards.

Examples:
  # Show programmable card info
  sim_reader prog info

  # Program card (use write command with config file)
  sim_reader write -a 4444444444444444 -f prog_config.json

  # Safe test mode (dry run)
  sim_reader write -a 4444444444444444 -f prog_config.json --dry-run`,
}

var progInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show programmable card information",
	Long: `Show information about programmable card capabilities.
Detects card type, supported operations, and File IDs.

Examples:
  sim_reader prog info
  sim_reader prog info -a 4444444444444444`,
	Run: runProgInfo,
}

func init() {
	progCmd.AddCommand(progInfoCmd)
	rootCmd.AddCommand(progCmd)
}

func runProgInfo(cmd *cobra.Command, args []string) {
	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	cardTypeName := sim.ShowProgrammableCardInfo(reader)
	atrHex := fmt.Sprintf("%X", reader.ATR())
	output.PrintProgrammableCardInfo(cardTypeName, atrHex)
}

