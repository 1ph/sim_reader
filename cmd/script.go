package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"sim_reader/output"
	"sim_reader/sim"
)

var (
	// Script command flags
	scriptFile    string
	pcomVerbose   bool
	pcomStopError bool
)

var scriptCmd = &cobra.Command{
	Use:   "script",
	Short: "Execute APDU scripts",
	Long: `Execute APDU scripts in various formats.

Supported formats:
  - Simple format: plain APDU commands (one per line)
  - PCOM format: RuSIM/OX24 personalization scripts`,
}

var scriptRunCmd = &cobra.Command{
	Use:   "run [file]",
	Short: "Run simple APDU script",
	Long: `Run APDU script in simple format (one command per line).

Example script format:
  # Select MF
  00 A4 00 04 02 3F00
  # Read binary
  00 B0 00 00 00

Examples:
  sim_reader script run script.txt
  sim_reader script run -a 77111606 script.txt`,
	Args: cobra.ExactArgs(1),
	Run:  runScriptRun,
}

var scriptPcomCmd = &cobra.Command{
	Use:   "pcom [file]",
	Short: "Run PCOM personalization script",
	Long: `Run .pcom personalization script (RuSIM/OX24 format).

Examples:
  sim_reader script pcom /path/to/_2.LTE_Profile.pcom
  sim_reader script pcom script.pcom --stop-on-error
  sim_reader script pcom script.pcom --verbose=false`,
	Args: cobra.ExactArgs(1),
	Run:  runScriptPcom,
}

func init() {
	// Pcom command flags
	scriptPcomCmd.Flags().BoolVar(&pcomVerbose, "verbose", true,
		"Verbose output for PCOM scripts")
	scriptPcomCmd.Flags().BoolVar(&pcomStopError, "stop-on-error", false,
		"Stop PCOM script on first error")

	scriptCmd.AddCommand(scriptRunCmd, scriptPcomCmd)
	rootCmd.AddCommand(scriptCmd)
}

func runScriptRun(cmd *cobra.Command, args []string) {
	scriptFile = args[0]

	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	fmt.Println()
	printSuccess(fmt.Sprintf("Running script: %s", scriptFile))

	results, err := sim.RunScript(reader, scriptFile)
	if err != nil {
		printError(fmt.Sprintf("Script error: %v", err))
		return
	}
	output.PrintScriptResults(results)
}

func runScriptPcom(cmd *cobra.Command, args []string) {
	scriptFile = args[0]

	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	fmt.Println()
	printSuccess(fmt.Sprintf("Running .pcom script: %s", scriptFile))
	fmt.Println()

	executor := sim.NewPcomExecutor(reader)
	executor.SetVerbose(pcomVerbose)
	executor.SetStopOnError(pcomStopError)

	err = executor.ExecuteFile(scriptFile)
	if err != nil {
		printError(fmt.Sprintf("Script error: %v", err))
	}

	// Print statistics
	total, success, failed := executor.GetStatistics()
	fmt.Println()
	if failed > 0 {
		printWarning(fmt.Sprintf("Script completed: %d commands, %d success, %d failed", total, success, failed))
	} else {
		printSuccess(fmt.Sprintf("Script completed: %d commands, %d success", total, success))
	}
}

