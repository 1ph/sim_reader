package cmd

import (
	"fmt"

	"sim_reader/card"
	"sim_reader/output"
)

// requireADMKey checks if ADM key is provided and returns error if not
func requireADMKey() error {
	if admKey == "" {
		return fmt.Errorf("ADM key is required for write operations. Use -a/--adm <key>")
	}
	return nil
}

// listReaders prints the list of available smart card readers
func listReaders() error {
	readers, err := card.ListReaders()
	if err != nil {
		return fmt.Errorf("failed to list readers: %w", err)
	}
	output.PrintReaderList(readers)
	return nil
}

// printError prints an error message using the output package
func printError(msg string) {
	output.PrintError(msg)
}

// printSuccess prints a success message using the output package
func printSuccess(msg string) {
	if !outputJSON {
		output.PrintSuccess(msg)
	}
}

// printWarning prints a warning message using the output package
func printWarning(msg string) {
	if !outputJSON {
		output.PrintWarning(msg)
	}
}

