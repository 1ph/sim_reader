package main

import (
	"flag"
	"fmt"
	"os"

	"sim_reader/card"
	"sim_reader/output"
	"sim_reader/sim"
)

var (
	version = "2.0.1"
)

func main() {
	// Command line flags - Reading
	listReaders := flag.Bool("list", false, "List available smart card readers")
	readerIndex := flag.Int("r", -1, "Reader index (use -list to see available readers)")
	admKey := flag.String("adm", "", "ADM1 key (hex or decimal format)")
	showRaw := flag.Bool("raw", false, "Show raw hex data")
	showAllServices := flag.Bool("services", false, "Show all UST/IST services in detail")
	showVersion := flag.Bool("version", false, "Show version")
	pin1 := flag.String("pin", "", "PIN1 code (if card is PIN protected)")
	analyzeCard := flag.Bool("analyze", false, "Analyze card: show ATR, applications, try GSM access")
	dumpTestData := flag.String("dump", "", "Dump card data as Go test code (provide card name)")

	// Command line flags - Writing
	writeConfig := flag.String("write", "", "Write parameters from JSON config file")
	createSample := flag.String("create-sample", "", "Create sample config file")

	// Individual write flags
	writeIMSI := flag.String("write-imsi", "", "Write IMSI to card")
	writeIMPI := flag.String("write-impi", "", "Write IMPI (IMS Private Identity)")
	writeIMPU := flag.String("write-impu", "", "Write IMPU (IMS Public Identity)")
	writeDomain := flag.String("write-domain", "", "Write Home Network Domain")
	writePCSCF := flag.String("write-pcscf", "", "Write P-CSCF address")
	writeSPN := flag.String("write-spn", "", "Write Service Provider Name")
	writeHPLMN := flag.String("write-hplmn", "", "Write HPLMN (MCC:MNC:ACT, e.g., 250:88:eutran,utran,gsm)")

	// Service enable flags
	enableVoLTE := flag.Bool("enable-volte", false, "Enable VoLTE services")
	enableVoWiFi := flag.Bool("enable-vowifi", false, "Enable VoWiFi services")
	enableSMSOverIP := flag.Bool("enable-sms-ip", false, "Enable SMS over IP (ISIM)")
	enableVoicePref := flag.Bool("enable-voice-pref", false, "Enable Voice Domain Preference (ISIM)")

	// Service disable flags
	disableVoLTE := flag.Bool("disable-volte", false, "Disable VoLTE services")
	disableVoWiFi := flag.Bool("disable-vowifi", false, "Disable VoWiFi services")
	disableSMSOverIP := flag.Bool("disable-sms-ip", false, "Disable SMS over IP (ISIM)")
	disableVoicePref := flag.Bool("disable-voice-pref", false, "Disable Voice Domain Preference (ISIM)")

	// Other flags
	clearFPLMN := flag.Bool("clear-fplmn", false, "Clear Forbidden PLMN list")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SIM Card Reader/Writer v%s
Read and write SIM/USIM/ISIM card parameters

Usage:
  %s [options]

READING OPTIONS:
`, version, os.Args[0])
		fmt.Fprintf(os.Stderr, `  -list              List available smart card readers
  -r <index>         Reader index (auto-selects if only one)
  -adm <key>         ADM1 key (hex: F38A3DEC... or decimal: 77111606)
  -pin <code>        PIN1 code if card is PIN protected
  -analyze           Analyze card (ATR, applications, GSM 2G access)
  -dump <name>       Dump card data as Go test code (for regression tests)
  -services          Show all UST/IST services in detail
  -raw               Show raw hex data
  -version           Show version

WRITING OPTIONS (require -adm):
  -write <file>      Apply configuration from JSON file
  -create-sample <f> Create sample JSON config file
  
  Individual parameters:
  -write-imsi <val>  Write IMSI (e.g., 250880000000001)
  -write-impi <val>  Write IMPI (e.g., 250880...@ims.domain.org)
  -write-impu <val>  Write IMPU (e.g., sip:250880...@ims.domain.org)
  -write-domain <v>  Write Home Network Domain
  -write-pcscf <val> Write P-CSCF address
  -write-spn <val>   Write Service Provider Name
  -write-hplmn <val> Write HPLMN (format: MCC:MNC:ACT)
                     ACT: eutran,utran,gsm,nr,ngran (comma-separated)
  
  Service toggles (enable):
  -enable-volte      Enable VoLTE (UST service 87)
  -enable-vowifi     Enable VoWiFi (UST services 89,90,124)
  -enable-sms-ip     Enable SMS over IP (IST service 7)
  -enable-voice-pref Enable Voice Domain Preference (IST service 12)
  
  Service toggles (disable):
  -disable-volte     Disable VoLTE (UST service 87)
  -disable-vowifi    Disable VoWiFi (UST services 89,90,124)
  -disable-sms-ip    Disable SMS over IP (IST service 7)
  -disable-voice-pref Disable Voice Domain Preference (IST service 12)
  
  Other:
  -clear-fplmn       Clear Forbidden PLMN list

EXAMPLES:
  # List readers
  %s -list

  # Read card
  %s -adm 77111606

  # Read with all services
  %s -adm 77111606 -services

  # Write from JSON config
  %s -adm 77111606 -write config.json

  # Create sample config
  %s -create-sample my_config.json

  # Write individual parameters
  %s -adm 77111606 -write-imsi 250880000000001
  %s -adm 77111606 -write-pcscf pcscf.ims.domain.org

  # Enable services
  %s -adm 77111606 -enable-volte -enable-vowifi

  # Disable services
  %s -adm 77111606 -disable-volte -disable-vowifi

  # Clear forbidden networks
  %s -adm 77111606 -clear-fplmn

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
	}

	flag.Parse()

	// Version
	if *showVersion {
		fmt.Printf("SIM Card Reader/Writer v%s\n", version)
		os.Exit(0)
	}

	// Create sample config
	if *createSample != "" {
		if err := sim.CreateSampleConfig(*createSample); err != nil {
			output.PrintError(fmt.Sprintf("Failed to create sample config: %v", err))
			os.Exit(1)
		}
		output.PrintSuccess(fmt.Sprintf("Sample config created: %s", *createSample))
		os.Exit(0)
	}

	// List readers
	if *listReaders {
		readers, err := card.ListReaders()
		if err != nil {
			output.PrintError(fmt.Sprintf("Failed to list readers: %v", err))
			os.Exit(1)
		}
		output.PrintReaderList(readers)
		os.Exit(0)
	}

	// Check if any write operation is requested
	isWriteMode := *writeConfig != "" || *writeIMSI != "" || *writeIMPI != "" ||
		*writeIMPU != "" || *writeDomain != "" || *writePCSCF != "" || *writeSPN != "" ||
		*writeHPLMN != "" ||
		*enableVoLTE || *enableVoWiFi || *enableSMSOverIP || *enableVoicePref ||
		*disableVoLTE || *disableVoWiFi || *disableSMSOverIP || *disableVoicePref ||
		*clearFPLMN

	// Require ADM key for write operations
	if isWriteMode && *admKey == "" {
		output.PrintError("ADM key is required for write operations. Use -adm <key>")
		os.Exit(1)
	}

	// Auto-select reader if only one available and none specified
	if *readerIndex < 0 {
		readers, err := card.ListReaders()
		if err != nil {
			output.PrintError(fmt.Sprintf("Failed to list readers: %v", err))
			os.Exit(1)
		}
		if len(readers) == 0 {
			output.PrintError("No smart card readers found")
			os.Exit(1)
		}
		if len(readers) == 1 {
			*readerIndex = 0
			output.PrintSuccess(fmt.Sprintf("Auto-selected reader: %s", readers[0]))
		} else {
			output.PrintReaderList(readers)
			output.PrintWarning("Multiple readers found. Use -r <index> to select one.")
			os.Exit(1)
		}
	}

	// Connect to reader
	reader, err := card.Connect(*readerIndex)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to connect: %v", err))
		os.Exit(1)
	}
	defer reader.Close()

	output.PrintReaderInfo(reader.Name(), reader.ATRHex())

	// Verify PIN1 if provided
	if *pin1 != "" {
		output.PrintSuccess("Verifying PIN1...")
		if err := reader.VerifyPIN1(*pin1); err != nil {
			output.PrintError(fmt.Sprintf("PIN1 verification failed: %v", err))
			os.Exit(1)
		}
		output.PrintSuccess("PIN1 verified successfully")
	}

	// Verify ADM1 if provided
	if *admKey != "" {
		key, err := card.ParseADMKey(*admKey)
		if err != nil {
			output.PrintError(fmt.Sprintf("Invalid ADM key: %v", err))
			os.Exit(1)
		}

		output.PrintSuccess(fmt.Sprintf("Verifying ADM1 (key: %s)...", card.KeyToHex(key)))
		if err := reader.VerifyADM1(key); err != nil {
			output.PrintError(fmt.Sprintf("ADM1 verification failed: %v", err))
			output.PrintWarning("Continuing without ADM access (some files may be restricted)")
		} else {
			output.PrintSuccess("ADM1 verified successfully")
		}
	} else {
		output.PrintWarning("No ADM key provided. Some protected files may not be readable.")
	}

	// Handle write operations
	if isWriteMode {
		fmt.Println()
		output.PrintSuccess("Starting write operations...")

		// Apply JSON config
		if *writeConfig != "" {
			config, err := sim.LoadConfig(*writeConfig)
			if err != nil {
				output.PrintError(fmt.Sprintf("Failed to load config: %v", err))
				os.Exit(1)
			}
			if err := sim.ApplyConfig(reader, config); err != nil {
				output.PrintError(fmt.Sprintf("Config apply failed: %v", err))
			}
		}

		// Individual write operations
		if *writeIMSI != "" {
			if err := sim.WriteIMSI(reader, *writeIMSI); err != nil {
				output.PrintError(fmt.Sprintf("Write IMSI failed: %v", err))
			} else {
				output.PrintSuccess("IMSI written successfully")
			}
		}

		if *writeSPN != "" {
			if err := sim.WriteSPN(reader, *writeSPN, 0x00); err != nil {
				output.PrintError(fmt.Sprintf("Write SPN failed: %v", err))
			} else {
				output.PrintSuccess("SPN written successfully")
			}
		}

		if *writeIMPI != "" {
			if err := sim.WriteIMPI(reader, *writeIMPI); err != nil {
				output.PrintError(fmt.Sprintf("Write IMPI failed: %v", err))
			} else {
				output.PrintSuccess("IMPI written successfully")
			}
		}

		if *writeIMPU != "" {
			if err := sim.WriteIMPU(reader, *writeIMPU); err != nil {
				output.PrintError(fmt.Sprintf("Write IMPU failed: %v", err))
			} else {
				output.PrintSuccess("IMPU written successfully")
			}
		}

		if *writeDomain != "" {
			if err := sim.WriteDomain(reader, *writeDomain); err != nil {
				output.PrintError(fmt.Sprintf("Write Domain failed: %v", err))
			} else {
				output.PrintSuccess("Domain written successfully")
			}
		}

		if *writePCSCF != "" {
			if err := sim.WritePCSCF(reader, *writePCSCF); err != nil {
				output.PrintError(fmt.Sprintf("Write P-CSCF failed: %v", err))
			} else {
				output.PrintSuccess("P-CSCF written successfully")
			}
		}

		if *writeHPLMN != "" {
			if err := sim.WriteHPLMNFromString(reader, *writeHPLMN); err != nil {
				output.PrintError(fmt.Sprintf("Write HPLMN failed: %v", err))
			} else {
				output.PrintSuccess("HPLMN written successfully")
			}
		}

		if *enableVoLTE {
			if err := sim.EnableVoLTE(reader); err != nil {
				output.PrintError(fmt.Sprintf("Enable VoLTE failed: %v", err))
			} else {
				output.PrintSuccess("VoLTE enabled")
			}
		}

		if *enableVoWiFi {
			if err := sim.EnableVoWiFi(reader); err != nil {
				output.PrintError(fmt.Sprintf("Enable VoWiFi failed: %v", err))
			} else {
				output.PrintSuccess("VoWiFi enabled")
			}
		}

		if *enableSMSOverIP {
			if err := sim.EnableISIMSMSOverIP(reader); err != nil {
				output.PrintError(fmt.Sprintf("Enable SMS over IP failed: %v", err))
			} else {
				output.PrintSuccess("SMS over IP enabled (ISIM)")
			}
		}

		if *enableVoicePref {
			if err := sim.EnableISIMVoiceDomainPref(reader); err != nil {
				output.PrintError(fmt.Sprintf("Enable Voice Domain Pref failed: %v", err))
			} else {
				output.PrintSuccess("Voice Domain Preference enabled (ISIM)")
			}
		}

		// Disable operations
		if *disableVoLTE {
			if err := sim.DisableVoLTE(reader); err != nil {
				output.PrintError(fmt.Sprintf("Disable VoLTE failed: %v", err))
			} else {
				output.PrintSuccess("VoLTE disabled")
			}
		}

		if *disableVoWiFi {
			if err := sim.DisableVoWiFi(reader); err != nil {
				output.PrintError(fmt.Sprintf("Disable VoWiFi failed: %v", err))
			} else {
				output.PrintSuccess("VoWiFi disabled")
			}
		}

		if *disableSMSOverIP {
			if err := sim.DisableISIMSMSOverIP(reader); err != nil {
				output.PrintError(fmt.Sprintf("Disable SMS over IP failed: %v", err))
			} else {
				output.PrintSuccess("SMS over IP disabled (ISIM)")
			}
		}

		if *disableVoicePref {
			if err := sim.DisableISIMVoiceDomainPref(reader); err != nil {
				output.PrintError(fmt.Sprintf("Disable Voice Domain Pref failed: %v", err))
			} else {
				output.PrintSuccess("Voice Domain Preference disabled (ISIM)")
			}
		}

		if *clearFPLMN {
			if err := sim.ClearForbiddenPLMN(reader); err != nil {
				output.PrintError(fmt.Sprintf("Clear FPLMN failed: %v", err))
			} else {
				output.PrintSuccess("Forbidden PLMN list cleared")
			}
		}

		fmt.Println()
		output.PrintSuccess("Write operations completed. Reading card to verify...")
	}

	// Always detect AIDs from EF_DIR first (silent, for non-standard cards)
	sim.DetectApplicationAIDs(reader)

	// Analyze card if requested
	if *analyzeCard {
		fmt.Println()
		output.PrintSuccess("Analyzing card...")
		cardInfo, err := sim.AnalyzeCard(reader)
		if err != nil {
			output.PrintError(fmt.Sprintf("Analysis failed: %v", err))
		} else {
			output.PrintCardAnalysis(cardInfo)
		}
	}

	// Read USIM data
	fmt.Println()
	output.PrintSuccess("Reading USIM application...")
	usimData, err := sim.ReadUSIM(reader)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to read USIM: %v", err))
		// If USIM failed and not in analyze mode, suggest it
		if !*analyzeCard {
			output.PrintWarning("Tip: Use -analyze flag to examine the card structure")
			// Auto-analyze on USIM failure
			fmt.Println()
			output.PrintSuccess("Auto-analyzing card...")
			cardInfo, anaErr := sim.AnalyzeCard(reader)
			if anaErr == nil {
				output.PrintCardAnalysis(cardInfo)
			}
		}
	} else {
		output.PrintUSIMData(usimData)
	}

	// Read ISIM data (only if USIM was found)
	var isimData *sim.ISIMData
	if usimData != nil {
		fmt.Println()
		output.PrintSuccess("Reading ISIM application...")
		isimData, err = sim.ReadISIM(reader)
		if err != nil {
			output.PrintWarning(fmt.Sprintf("ISIM: %v", err))
		} else {
			output.PrintISIMData(isimData)
		}
	}

	// Show all services if requested
	if *showAllServices {
		output.PrintAllServices(usimData, isimData)
	}

	// Show raw data if requested
	if *showRaw {
		if usimData != nil && len(usimData.RawFiles) > 0 {
			fmt.Println()
			output.PrintSuccess("USIM Raw Data:")
			output.PrintRawData(usimData.RawFiles)
		}
		if isimData != nil && isimData.Available && len(isimData.RawFiles) > 0 {
			fmt.Println()
			output.PrintSuccess("ISIM Raw Data:")
			output.PrintRawData(isimData.RawFiles)
		}
	}

	// Dump test data if requested
	if *dumpTestData != "" {
		fmt.Println()
		output.PrintSuccess("Generating test data dump...")
		fmt.Println()
		dump := sim.DumpTestData(*dumpTestData, reader.ATRHex(), usimData, isimData)
		fmt.Println(dump)
	}

	fmt.Println()
	output.PrintSuccess("Done!")
}
