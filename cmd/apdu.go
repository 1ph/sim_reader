package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"sim_reader/card"
	"sim_reader/output"
)

var apduCmd = &cobra.Command{
	Use:   "apdu [hex_string]",
	Short: "Send raw APDU command to the card",
	Long: `Send raw APDU command to the card in hexadecimal format.
Spaces in the hex string are automatically removed.

Examples:
  # SELECT MF (Master File)
  sim_reader apdu 00A40000023F00

  # SELECT MF with spaces
  sim_reader apdu "00 A4 00 00 02 3F 00"
  
  # Multiple arguments will be joined
  sim_reader apdu 8020010010 0102030405060708090A0B0C0D0E0F00 000000000000`,
	Args: cobra.MinimumNArgs(1),
	Run:  runAPDU,
}

func init() {
	rootCmd.AddCommand(apduCmd)
}

func runAPDU(cmd *cobra.Command, args []string) {
	// Join all arguments and remove spaces
	hexStr := strings.Join(args, "")
	hexStr = strings.ReplaceAll(hexStr, " ", "")

	// Decode hex string
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		output.PrintError(fmt.Sprintf("Invalid hex string: %v", err))
		return
	}

	// Connect to reader
	reader, err := connectAndPrepareReader()
	if err != nil {
		output.PrintError(err.Error())
		return
	}
	defer reader.Close()

	if !outputJSON {
		output.PrintSuccess(fmt.Sprintf("Sending APDU: %X", data))
	}

	// Send APDU
	resp, err := reader.SendAPDU(data)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to send APDU: %v", err))
		return
	}

	// Output result
	if outputJSON {
		// Simplistic JSON output for raw APDU
		type APDUResult struct {
			Command  string `json:"command"`
			Response string `json:"response"`
			SW       string `json:"sw"`
			OK       bool   `json:"ok"`
		}
		result := APDUResult{
			Command:  fmt.Sprintf("%X", data),
			Response: fmt.Sprintf("%X", resp.Data),
			SW:       fmt.Sprintf("%04X", resp.SW()),
			OK:       resp.IsOK(),
		}
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		fmt.Println()
		output.PrintSuccess(fmt.Sprintf("Response SW: %04X (%s)", resp.SW(), card.SWToString(resp.SW())))
		if len(resp.Data) > 0 {
			output.PrintSuccess(fmt.Sprintf("Response Data: %X", resp.Data))
		} else {
			output.PrintWarning("No response data")
		}
	}
}
