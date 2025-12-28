package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"sim_reader/card"
	"sim_reader/output"
	"sim_reader/sim"
)

var (
	version = "3.2.0"

	// Global flags
	readerIndex int
	admKey      string
	admKey2     string
	admKey3     string
	admKey4     string
	pin1        string
	outputJSON  bool
)

var rootCmd = &cobra.Command{
	Use:   "sim_reader",
	Short: "SIM Card Reader/Writer",
	Long: `SIM Card Reader/Writer v` + version + `
Read and write SIM/USIM/ISIM card parameters.

This tool supports:
  - Reading USIM/ISIM data (IMSI, IMPI, IMPU, PLMN, services)
  - Writing SIM card parameters
  - GlobalPlatform operations (applet management)
  - Authentication testing (Milenage/TUAK)
  - SIM card test suites
  - Programmable card operations`,
	Version: version,
}

func init() {
	// Persistent flags available for all subcommands
	rootCmd.PersistentFlags().IntVarP(&readerIndex, "reader", "r", -1,
		"Reader index (use 'sim_reader read --list' to see available readers)")
	rootCmd.PersistentFlags().StringVarP(&admKey, "adm", "a", "",
		"ADM1 key (hex: F38A3DEC... or decimal: 77111606)")
	rootCmd.PersistentFlags().StringVar(&admKey2, "adm2", "",
		"ADM2 key (for files requiring higher access level)")
	rootCmd.PersistentFlags().StringVar(&admKey3, "adm3", "",
		"ADM3 key (for files requiring even higher access)")
	rootCmd.PersistentFlags().StringVar(&admKey4, "adm4", "",
		"ADM4 key (for maximum access level)")
	rootCmd.PersistentFlags().StringVarP(&pin1, "pin", "p", "",
		"PIN1 code if card is PIN protected")
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false,
		"Output in JSON format")
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// GetVersion returns the current version
func GetVersion() string {
	return version
}

// connectAndPrepareReader is a helper that connects to the reader,
// performs reset, verifies PIN and ADM keys. Returns reader or error.
func connectAndPrepareReader() (*card.Reader, error) {
	// Auto-select reader if only one available and none specified
	if readerIndex < 0 {
		readers, err := card.ListReaders()
		if err != nil {
			return nil, fmt.Errorf("failed to list readers: %w", err)
		}
		if len(readers) == 0 {
			return nil, fmt.Errorf("no smart card readers found")
		}
		if len(readers) == 1 {
			readerIndex = 0
			if !outputJSON {
				output.PrintSuccess(fmt.Sprintf("Auto-selected reader: %s", readers[0]))
			}
		} else {
			output.PrintReaderList(readers)
			return nil, fmt.Errorf("multiple readers found, use -r <index> to select one")
		}
	}

	// Connect to reader
	reader, err := card.Connect(readerIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Perform warm reset to ensure clean card state
	if err := reader.Reconnect(false); err != nil {
		// Warm reset failed, try cold reset
		if err := reader.Reconnect(true); err != nil {
			// If both fail, just continue - some readers don't support reset
			if !outputJSON {
				output.PrintWarning(fmt.Sprintf("Card reset failed: %v (continuing anyway)", err))
			}
		}
	}

	if !outputJSON {
		output.PrintReaderInfo(reader.Name(), reader.ATRHex())
	}

	// Detect card driver and set global card mode
	drv := sim.FindDriver(reader)
	if drv != nil {
		sim.UseGSMCommands = (drv.BaseCLA() == 0xA0)
	} else {
		sim.UseGSMCommands = sim.IsGSMOnlyCard(reader.ATRHex())
	}

	// Verify PIN1 if provided
	if pin1 != "" {
		if !outputJSON {
			output.PrintSuccess("Verifying PIN1...")
		}
		if err := reader.VerifyPIN1(pin1); err != nil {
			reader.Close()
			return nil, fmt.Errorf("PIN1 verification failed: %w", err)
		}
		if !outputJSON {
			output.PrintSuccess("PIN1 verified successfully")
		}
	}

	// Verify ADM keys
	if err := verifyADMKeys(reader); err != nil {
		reader.Close()
		return nil, err
	}

	// Always detect AIDs from EF_DIR first (silent, for non-standard cards)
	sim.DetectApplicationAIDs(reader)

	return reader, nil
}

// verifyADMKeys verifies all provided ADM keys
func verifyADMKeys(reader *card.Reader) error {
	// Verify ADM1 if provided
	if admKey != "" {
		key, err := card.ParseADMKey(admKey)
		if err != nil {
			return fmt.Errorf("invalid ADM key: %w", err)
		}

		if !outputJSON {
			output.PrintSuccess(fmt.Sprintf("Verifying ADM1 (key: %s)...", card.KeyToHex(key)))
		}
		if err := reader.VerifyADM1(key); err != nil {
			if !outputJSON {
				output.PrintError(fmt.Sprintf("ADM1 verification failed: %v", err))
				output.PrintWarning("Continuing without ADM access (some files may be restricted)")
			}
		} else {
			sim.SetADMKey(key)
			if !outputJSON {
				output.PrintSuccess("ADM1 verified successfully")
			}
		}
	} else {
		if !outputJSON {
			output.PrintWarning("No ADM key provided. Some protected files may not be readable.")
		}
	}

	// Verify ADM2 if provided
	if admKey2 != "" {
		key2, err := card.ParseADMKey(admKey2)
		if err != nil {
			return fmt.Errorf("invalid ADM2 key: %w", err)
		}

		if !outputJSON {
			output.PrintSuccess(fmt.Sprintf("Verifying ADM2 (key: %s)...", card.KeyToHex(key2)))
		}
		if err := reader.VerifyADM2(key2); err != nil {
			if !outputJSON {
				output.PrintError(fmt.Sprintf("ADM2 verification failed: %v", err))
			}
		} else {
			sim.SetADMKey2(key2)
			if !outputJSON {
				output.PrintSuccess("ADM2 verified successfully")
			}
		}
	}

	// Verify ADM3 if provided
	if admKey3 != "" {
		key3, err := card.ParseADMKey(admKey3)
		if err != nil {
			return fmt.Errorf("invalid ADM3 key: %w", err)
		}

		if !outputJSON {
			output.PrintSuccess(fmt.Sprintf("Verifying ADM3 (key: %s)...", card.KeyToHex(key3)))
		}
		if err := reader.VerifyADM3(key3); err != nil {
			if !outputJSON {
				output.PrintError(fmt.Sprintf("ADM3 verification failed: %v", err))
			}
		} else {
			sim.SetADMKey3(key3)
			if !outputJSON {
				output.PrintSuccess("ADM3 verified successfully")
			}
		}
	}

	// Verify ADM4 if provided
	if admKey4 != "" {
		key4, err := card.ParseADMKey(admKey4)
		if err != nil {
			return fmt.Errorf("invalid ADM4 key: %w", err)
		}

		if !outputJSON {
			output.PrintSuccess(fmt.Sprintf("Verifying ADM4 (key: %s)...", card.KeyToHex(key4)))
		}
		if err := reader.VerifyADM4(key4); err != nil {
			if !outputJSON {
				output.PrintError(fmt.Sprintf("ADM4 verification failed: %v", err))
			}
		} else {
			sim.SetADMKey4(key4)
			if !outputJSON {
				output.PrintSuccess("ADM4 verified successfully")
			}
		}
	}

	return nil
}

