package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"sim_reader/output"
	"sim_reader/sim"
)

var (
	// Read command flags
	listReadersFlag   bool
	showPhonebook     bool
	showSMS           bool
	showApplets       bool
	showAllServices   bool
	showRaw           bool
	analyzeCard       bool
	dumpTestData      string
	checkADMStatus    bool
	debugFCP          bool
	createSamplePath  string
)

var readCmd = &cobra.Command{
	Use:   "read",
	Short: "Read SIM card data",
	Long: `Read USIM/ISIM applications, phonebook, SMS, applets.

Examples:
  # List available readers
  sim_reader read --list

  # Read card with default settings
  sim_reader read -a 77111606

  # Read card with phonebook
  sim_reader read -a 77111606 --phonebook

  # Read card with all services detail
  sim_reader read -a 77111606 --services

  # Analyze card structure
  sim_reader read --analyze

  # Dump card data as JSON
  sim_reader read -a 77111606 --json

  # Create sample config file
  sim_reader read --create-sample my_config.json`,
	Run: runRead,
}

func init() {
	readCmd.Flags().BoolVarP(&listReadersFlag, "list", "l", false,
		"List available smart card readers")
	readCmd.Flags().BoolVar(&showPhonebook, "phonebook", false,
		"Show phonebook entries (EF_ADN)")
	readCmd.Flags().BoolVar(&showSMS, "sms", false,
		"Show SMS messages (EF_SMS)")
	readCmd.Flags().BoolVar(&showApplets, "applets", false,
		"Show GlobalPlatform applets")
	readCmd.Flags().BoolVar(&showAllServices, "services", false,
		"Show all UST/IST services in detail")
	readCmd.Flags().BoolVar(&showRaw, "raw", false,
		"Show raw hex data")
	readCmd.Flags().BoolVar(&analyzeCard, "analyze", false,
		"Analyze card: show ATR, applications, try GSM access")
	readCmd.Flags().StringVar(&dumpTestData, "dump", "",
		"Dump card data as Go test code (provide card name)")
	readCmd.Flags().BoolVar(&checkADMStatus, "adm-check", false,
		"Check ADM key slots status (safe on most cards)")
	readCmd.Flags().BoolVar(&debugFCP, "debug-fcp", false,
		"Show raw FCP data when reading file access conditions")
	readCmd.Flags().StringVar(&createSamplePath, "create-sample", "",
		"Create sample config file at specified path")

	rootCmd.AddCommand(readCmd)
}

func runRead(cmd *cobra.Command, args []string) {
	// Handle --list flag without connecting to card
	if listReadersFlag {
		if err := listReaders(); err != nil {
			printError(err.Error())
		}
		return
	}

	// Handle --create-sample flag without connecting to card
	if createSamplePath != "" {
		if err := sim.CreateSampleConfig(createSamplePath); err != nil {
			printError(fmt.Sprintf("Failed to create sample config: %v", err))
			return
		}
		printSuccess(fmt.Sprintf("Sample config created: %s", createSamplePath))
		return
	}

	// Connect to reader
	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	// Analyze card if requested
	if analyzeCard {
		fmt.Println()
		printSuccess("Analyzing card...")
		cardInfo, err := sim.AnalyzeCard(reader, checkADMStatus)
		if err != nil {
			printError(fmt.Sprintf("Analysis failed: %v", err))
		} else {
			output.PrintCardAnalysis(cardInfo)
		}
	}

	// Read file access conditions if -adm-check is enabled
	if checkADMStatus {
		fmt.Println()
		printSuccess("Reading file access conditions...")
		sim.DebugFCP = debugFCP
		usimAccess := sim.ReadFileAccessConditions(reader)
		isimAccess := sim.ReadISIMFileAccessConditions(reader)
		output.PrintFileAccessConditions(usimAccess, isimAccess)
	}

	// Read USIM data
	if !outputJSON {
		fmt.Println()
		printSuccess("Reading USIM application...")
	}
	usimData, err := sim.ReadUSIM(reader)
	if err != nil {
		if !outputJSON {
			printError(fmt.Sprintf("Failed to read USIM: %v", err))
			// If USIM failed and not in analyze mode, suggest it
			if !analyzeCard {
				printWarning("Tip: Use --analyze flag to examine the card structure")
				// Auto-analyze on USIM failure
				fmt.Println()
				printSuccess("Auto-analyzing card...")
				cardInfo, anaErr := sim.AnalyzeCard(reader, checkADMStatus)
				if anaErr == nil {
					output.PrintCardAnalysis(cardInfo)
				}
			}
		}
	} else if !outputJSON {
		output.PrintUSIMData(usimData)
	}

	// Read ISIM data (only if USIM was found)
	var isimData *sim.ISIMData
	if usimData != nil {
		if !outputJSON {
			fmt.Println()
			printSuccess("Reading ISIM application...")
		}
		isimData, err = sim.ReadISIM(reader)
		if err != nil {
			if !outputJSON {
				printWarning(fmt.Sprintf("ISIM: %v", err))
			}
		} else if !outputJSON {
			output.PrintISIMData(isimData)
		}
	}

	// Read Phonebook if requested
	if showPhonebook {
		fmt.Println()
		printSuccess("Reading Phonebook (EF_ADN)...")
		entries, err := sim.ReadPhonebook(reader)
		if err != nil {
			printWarning(fmt.Sprintf("Phonebook: %v", err))
		} else {
			output.PrintPhonebook(entries)
		}
	}

	// Read SMS if requested
	if showSMS {
		fmt.Println()
		printSuccess("Reading SMS (EF_SMS)...")
		messages, err := sim.ReadSMS(reader)
		if err != nil {
			printWarning(fmt.Sprintf("SMS: %v", err))
		} else {
			output.PrintSMS(messages)
		}
	}

	// Show GlobalPlatform applets if requested
	if showApplets {
		fmt.Println()
		printSuccess("Reading GlobalPlatform applets...")
		applets, err := sim.ListApplets(reader)
		if err != nil {
			printWarning(fmt.Sprintf("Applets: %v", err))
		} else {
			output.PrintApplets(applets)
		}
	}

	// Output JSON if requested
	if outputJSON {
		jsonConfig := sim.ExportToConfig(usimData, isimData)
		jsonData, err := json.MarshalIndent(jsonConfig, "", "  ")
		if err != nil {
			printError(fmt.Sprintf("JSON export failed: %v", err))
		} else {
			fmt.Println(string(jsonData))
		}
		return
	}

	// Show all services if requested
	if showAllServices {
		output.PrintAllServices(usimData, isimData)
	}

	// Show raw data if requested
	if showRaw {
		if usimData != nil && len(usimData.RawFiles) > 0 {
			fmt.Println()
			printSuccess("USIM Raw Data:")
			output.PrintRawData(usimData.RawFiles)
		}
		if isimData != nil && isimData.Available && len(isimData.RawFiles) > 0 {
			fmt.Println()
			printSuccess("ISIM Raw Data:")
			output.PrintRawData(isimData.RawFiles)
		}
	}

	// Dump test data if requested
	if dumpTestData != "" {
		fmt.Println()
		printSuccess("Generating test data dump...")
		fmt.Println()
		dump := sim.DumpTestData(dumpTestData, reader.ATRHex(), usimData, isimData)
		fmt.Println(dump)
	}

	if !outputJSON {
		fmt.Println()
		printSuccess("Done!")
	}
}

