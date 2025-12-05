package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"sim_reader/card"
	"sim_reader/output"
	"sim_reader/sim"
)

var (
	version = "2.2.0"
)

func main() {
	// Command line flags - Reading
	listReaders := flag.Bool("list", false, "List available smart card readers")
	readerIndex := flag.Int("r", -1, "Reader index (use -list to see available readers)")
	admKey := flag.String("adm", "", "ADM1 key (hex or decimal format)")
	admKey2 := flag.String("adm2", "", "ADM2 key (hex or decimal format) - for files requiring higher access")
	admKey3 := flag.String("adm3", "", "ADM3 key (hex or decimal format) - for files requiring even higher access")
	admKey4 := flag.String("adm4", "", "ADM4 key (hex or decimal format)")
	pin1 := flag.String("pin", "", "PIN1 code (if card is PIN protected)")

	showRaw := flag.Bool("raw", false, "Show raw hex data")
	showAllServices := flag.Bool("services", false, "Show all UST/IST services in detail")
	showVersion := flag.Bool("version", false, "Show version")
	dumpTestData := flag.String("dump", "", "Dump card data as Go test code (provide card name)")
	showPhonebook := flag.Bool("phonebook", false, "Show phonebook entries (EF_ADN)")
	showSMS := flag.Bool("sms", false, "Show SMS messages (EF_SMS)")
	analyzeCard := flag.Bool("analyze", false, "Analyze card: show ATR, applications, try GSM access")
	checkADMStatus := flag.Bool("adm-check", false, "Check ADM key slots status (safe on most cards, use with caution)")
	debugFCP := flag.Bool("debug-fcp", false, "Show raw FCP data when reading file access conditions")

	showApplets := flag.Bool("applets", false, "Show GlobalPlatform applets")
	runScript := flag.String("script", "", "Run APDU script file (simple format)")
	runPcom := flag.String("pcom", "", "Run .pcom personalization script (RuSIM/OX24 format)")
	pcomVerbose := flag.Bool("pcom-verbose", true, "Verbose output for .pcom scripts")
	pcomStop := flag.Bool("pcom-stop-on-error", false, "Stop .pcom script on first error")
	outputJSON := flag.Bool("json", false, "Output data in JSON config format (can be edited and loaded back)")

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
	writeUserPLMN := flag.String("write-user-plmn", "", "Write User PLMN (MCC:MNC:ACT, e.g., 001:01:eutran,utran,gsm)")
	writeOPLMN := flag.String("write-oplmn", "", "Write Operator PLMN (MCC:MNC:ACT, e.g., 250:20:eutran,utran,gsm)")
	setOpMode := flag.String("set-op-mode", "", "Set UE operation mode (normal, type-approval, cell-test, etc.)")

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

	// Authentication flags
	authMode := flag.Bool("auth", false, "Run authentication test mode")
	authK := flag.String("auth-k", "", "Subscriber key K (32 hex chars for 128-bit, 64 for 256-bit)")
	authOP := flag.String("auth-op", "", "Operator key OP (for computing OPc)")
	authOPc := flag.String("auth-opc", "", "Precomputed OPc (if OP not provided)")
	authSQN := flag.String("auth-sqn", "000000000000", "Sequence number SQN (12 hex chars)")
	authAMF := flag.String("auth-amf", "8000", "Authentication Management Field (4 hex chars)")
	authRAND := flag.String("auth-rand", "", "Random challenge RAND (32 hex chars, auto-generated if empty)")
	authAUTN := flag.String("auth-autn", "", "Pre-computed AUTN (32 hex chars, skip calculation)")
	authAUTS := flag.String("auth-auts", "", "AUTS from dump (28/44/76 hex chars, for SQN resync)")
	authAlgo := flag.String("auth-algo", "milenage", "Algorithm: milenage or tuak")
	authMCC := flag.Int("auth-mcc", 0, "Mobile Country Code for KASME computation")
	authMNC := flag.Int("auth-mnc", 0, "Mobile Network Code for KASME computation")
	authNoCard := flag.Bool("auth-no-card", false, "Run auth computation without sending to card")

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
  -adm2 <key>        ADM2 key (for files requiring higher access level)
  -adm3 <key>        ADM3 key (for files requiring even higher access)
  -adm4 <key>        ADM4 key (for maximum access level)
  -pin <code>        PIN1 code if card is PIN protected
  -analyze           Analyze card (ATR, applications, GSM 2G access)
  -dump <name>       Dump card data as Go test code (for regression tests)
  -phonebook         Show phonebook entries (ADN)
  -sms               Show SMS messages
  -applets           Show GlobalPlatform applets
  -script <file>     Run APDU script file (simple format)
  -pcom <file>       Run .pcom personalization script (RuSIM/OX24 format)
  -pcom-verbose      Verbose output for .pcom scripts (default: true)
  -pcom-stop-on-error Stop .pcom script on first error
  -services          Show all UST/IST services in detail
  -raw               Show raw hex data
  -json              Output in JSON config format (edit and reload with -write)
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
  -write-hplmn <val> Write Home PLMN (format: MCC:MNC:ACT)
  -write-oplmn <val> Write Operator PLMN (format: MCC:MNC:ACT)
  -write-user-plmn   Write User PLMN (format: MCC:MNC:ACT)
                     ACT: eutran,utran,gsm,nr,ngran (comma-separated)
  -set-op-mode <m>   Set UE operation mode:
                     normal, type-approval, normal-specific,
                     type-approval-specific, maintenance, cell-test
  
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

AUTHENTICATION OPTIONS:
  -auth              Run authentication test mode
  -auth-k <hex>      Subscriber key K (32 hex chars for 128-bit)
  -auth-op <hex>     Operator key OP (to compute OPc)
  -auth-opc <hex>    Precomputed OPc (alternative to -auth-op)
  -auth-sqn <hex>    Sequence number SQN (12 hex chars, default: 000000000000)
  -auth-amf <hex>    Auth Management Field (4 hex chars, default: 8000)
  -auth-rand <hex>   Random challenge (32 hex chars, auto-generated if empty)
  -auth-autn <hex>   Pre-computed AUTN from dump (32 hex chars, skip calculation)
  -auth-auts <hex>   AUTS from dump for SQN resync (28/44/76 hex chars)
  -auth-algo <name>  Algorithm: milenage (default) or tuak
  -auth-mcc <int>    Mobile Country Code (for KASME)
  -auth-mnc <int>    Mobile Network Code (for KASME)
  -auth-no-card      Compute auth vectors without sending to card

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

  # Run .pcom personalization script (RuSIM/OX24 format)
  %s -pcom /path/to/_2.LTE_Profile.pcom

  # Run .pcom script with stop on first error
  %s -pcom /path/to/script.pcom -pcom-stop-on-error

  # Authentication test (compute vectors only)
  %s -auth -auth-k F2464E3293019A7E51ABAA7B1262B7D8 -auth-opc B10B351A0CCD8BE31E0C9F088945A812 -auth-no-card

  # Authentication test with card
  %s -auth -auth-k F2464E3293019A7E51ABAA7B1262B7D8 -auth-opc B10B351A0CCD8BE31E0C9F088945A812 -auth-mcc 250 -auth-mnc 88

  # Authentication with OP (computes OPc automatically)
  %s -auth -auth-k F2464E3293019A7E51ABAA7B1262B7D8 -auth-op CDC202D5123E20F62B6D676AC72CB318 -auth-sqn 000000000001

  # Send pre-computed AUTN to card (from dump)
  %s -auth -auth-k F2464E3293019A7E51ABAA7B1262B7D8 -auth-opc B10B351A0CCD8BE31E0C9F088945A812 -auth-rand 7D6AF2DF993240BA9B191B68F1750C43 -auth-autn 000000000C808000ABCD1234EFGH5678

  # Process AUTS from dump to extract SQNms
  %s -auth -auth-k F2464E3293019A7E51ABAA7B1262B7D8 -auth-opc B10B351A0CCD8BE31E0C9F088945A812 -auth-rand 7D6AF2DF993240BA9B191B68F1750C43 -auth-auts AABBCCDDEEFF00112233445566778899 -auth-no-card

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
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

	// Handle authentication mode without card
	if *authMode && *authNoCard {
		fmt.Println()
		output.PrintSuccess("Running Authentication Test (no card)...")
		fmt.Println()

		// Parse auth config
		authCfg, err := sim.ParseAuthConfig(
			*authK, *authOP, *authOPc,
			*authSQN, *authAMF, *authRAND,
			*authAUTN, *authAUTS,
			*authAlgo,
			*authMCC, *authMNC,
		)
		if err != nil {
			output.PrintError(fmt.Sprintf("Auth config error: %v", err))
			os.Exit(1)
		}

		// Run authentication without card
		result, err := sim.RunAuthentication(nil, authCfg)
		if err != nil {
			output.PrintError(fmt.Sprintf("Authentication error: %v", err))
		}

		// Print results
		output.PrintAuthResult(result, *authAlgo)
		os.Exit(0)
	}

	// Check if any write operation is requested
	isWriteMode := *writeConfig != "" || *writeIMSI != "" || *writeIMPI != "" ||
		*writeIMPU != "" || *writeDomain != "" || *writePCSCF != "" || *writeSPN != "" ||
		*writeHPLMN != "" || *writeUserPLMN != "" || *writeOPLMN != "" || *setOpMode != "" ||
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
			if !*outputJSON {
				output.PrintSuccess(fmt.Sprintf("Auto-selected reader: %s", readers[0]))
			}
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

	if !*outputJSON {
		output.PrintReaderInfo(reader.Name(), reader.ATRHex())
	}

	// Verify PIN1 if provided
	if *pin1 != "" {
		if !*outputJSON {
			output.PrintSuccess("Verifying PIN1...")
		}
		if err := reader.VerifyPIN1(*pin1); err != nil {
			output.PrintError(fmt.Sprintf("PIN1 verification failed: %v", err))
			os.Exit(1)
		}
		if !*outputJSON {
			output.PrintSuccess("PIN1 verified successfully")
		}
	}

	// Verify ADM1 if provided
	if *admKey != "" {
		key, err := card.ParseADMKey(*admKey)
		if err != nil {
			output.PrintError(fmt.Sprintf("Invalid ADM key: %v", err))
			os.Exit(1)
		}

		if !*outputJSON {
			output.PrintSuccess(fmt.Sprintf("Verifying ADM1 (key: %s)...", card.KeyToHex(key)))
		}
		if err := reader.VerifyADM1(key); err != nil {
			if !*outputJSON {
				output.PrintError(fmt.Sprintf("ADM1 verification failed: %v", err))
				output.PrintWarning("Continuing without ADM access (some files may be restricted)")
			}
		} else {
			// Store ADM key for re-authentication after SELECT AID
			sim.SetADMKey(key)
			if !*outputJSON {
				output.PrintSuccess("ADM1 verified successfully")
			}
		}
	} else {
		if !*outputJSON {
			output.PrintWarning("No ADM key provided. Some protected files may not be readable.")
		}
	}

	// Verify ADM2 if provided (for files requiring higher access)
	if *admKey2 != "" {
		key2, err := card.ParseADMKey(*admKey2)
		if err != nil {
			output.PrintError(fmt.Sprintf("Invalid ADM2 key: %v", err))
			os.Exit(1)
		}

		if !*outputJSON {
			output.PrintSuccess(fmt.Sprintf("Verifying ADM2 (key: %s)...", card.KeyToHex(key2)))
		}
		if err := reader.VerifyADM2(key2); err != nil {
			if !*outputJSON {
				output.PrintError(fmt.Sprintf("ADM2 verification failed: %v", err))
			}
		} else {
			sim.SetADMKey2(key2)
			if !*outputJSON {
				output.PrintSuccess("ADM2 verified successfully")
			}
		}
	}

	// Verify ADM3 if provided (for files requiring even higher access)
	if *admKey3 != "" {
		key3, err := card.ParseADMKey(*admKey3)
		if err != nil {
			output.PrintError(fmt.Sprintf("Invalid ADM3 key: %v", err))
			os.Exit(1)
		}

		if !*outputJSON {
			output.PrintSuccess(fmt.Sprintf("Verifying ADM3 (key: %s)...", card.KeyToHex(key3)))
		}
		if err := reader.VerifyADM3(key3); err != nil {
			if !*outputJSON {
				output.PrintError(fmt.Sprintf("ADM3 verification failed: %v", err))
			}
		} else {
			sim.SetADMKey3(key3)
			if !*outputJSON {
				output.PrintSuccess("ADM3 verified successfully")
			}
		}
	}

	// Verify ADM4 if provided
	if *admKey4 != "" {
		key4, err := card.ParseADMKey(*admKey4)
		if err != nil {
			output.PrintError(fmt.Sprintf("Invalid ADM4 key: %v", err))
			os.Exit(1)
		}

		if !*outputJSON {
			output.PrintSuccess(fmt.Sprintf("Verifying ADM4 (key: %s)...", card.KeyToHex(key4)))
		}
		if err := reader.VerifyADM4(key4); err != nil {
			if !*outputJSON {
				output.PrintError(fmt.Sprintf("ADM4 verification failed: %v", err))
			}
		} else {
			sim.SetADMKey4(key4)
			if !*outputJSON {
				output.PrintSuccess("ADM4 verified successfully")
			}
		}
	}

	// Always detect AIDs from EF_DIR first (silent, for non-standard cards)
	// This MUST be done before any write operations!
	sim.DetectApplicationAIDs(reader)

	// Handle authentication mode
	if *authMode {
		fmt.Println()
		output.PrintSuccess("Running Authentication Test...")
		fmt.Println()

		// Parse auth config
		authCfg, err := sim.ParseAuthConfig(
			*authK, *authOP, *authOPc,
			*authSQN, *authAMF, *authRAND,
			*authAUTN, *authAUTS,
			*authAlgo,
			*authMCC, *authMNC,
		)
		if err != nil {
			output.PrintError(fmt.Sprintf("Auth config error: %v", err))
			os.Exit(1)
		}

		// Run authentication (pass nil reader if -auth-no-card)
		var authReader *card.Reader
		if !*authNoCard {
			authReader = reader
		}

		result, err := sim.RunAuthentication(authReader, authCfg)
		if err != nil {
			output.PrintError(fmt.Sprintf("Authentication error: %v", err))
		}

		// Print results
		output.PrintAuthResult(result, *authAlgo)

		// If sync failure, show how to update SQN
		if result != nil && result.SyncFail && result.SQNms != "" {
			fmt.Println()
			output.PrintWarning("Sync failure detected! SIM card SQN is ahead of network.")
			output.PrintSuccess(fmt.Sprintf("SIM SQN (SQNms): %s", result.SQNms))
			nextSQN := sim.IncrementSQNHex(result.SQNms)
			output.PrintSuccess(fmt.Sprintf("Use -auth-sqn %s for next authentication (SQNms+1)", nextSQN))
		}

		os.Exit(0)
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

		if *writeUserPLMN != "" {
			if err := sim.WriteUserPLMNFromString(reader, *writeUserPLMN); err != nil {
				output.PrintError(fmt.Sprintf("Write User PLMN failed: %v", err))
			} else {
				output.PrintSuccess("User PLMN written successfully")
			}
		}

		if *writeOPLMN != "" {
			if err := sim.WriteOPLMNFromString(reader, *writeOPLMN); err != nil {
				output.PrintError(fmt.Sprintf("Write Operator PLMN failed: %v", err))
			} else {
				output.PrintSuccess("Operator PLMN written successfully")
			}
		}

		if *setOpMode != "" {
			if err := sim.SetOperationModeFromString(reader, *setOpMode); err != nil {
				output.PrintError(fmt.Sprintf("Set Operation Mode failed: %v", err))
			} else {
				output.PrintSuccess(fmt.Sprintf("Operation mode set to: %s", *setOpMode))
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

	// Analyze card if requested
	if *analyzeCard {
		fmt.Println()
		output.PrintSuccess("Analyzing card...")
		cardInfo, err := sim.AnalyzeCard(reader, *checkADMStatus)
		if err != nil {
			output.PrintError(fmt.Sprintf("Analysis failed: %v", err))
		} else {
			output.PrintCardAnalysis(cardInfo)
		}
	}

	// Read file access conditions if -adm-check is enabled (independent of -analyze)
	if *checkADMStatus {
		fmt.Println()
		output.PrintSuccess("Reading file access conditions...")
		sim.DebugFCP = *debugFCP
		usimAccess := sim.ReadFileAccessConditions(reader)
		isimAccess := sim.ReadISIMFileAccessConditions(reader)
		output.PrintFileAccessConditions(usimAccess, isimAccess)
	}

	// Read USIM data
	if !*outputJSON {
		fmt.Println()
		output.PrintSuccess("Reading USIM application...")
	}
	usimData, err := sim.ReadUSIM(reader)
	if err != nil {
		if !*outputJSON {
			output.PrintError(fmt.Sprintf("Failed to read USIM: %v", err))
			// If USIM failed and not in analyze mode, suggest it
			if !*analyzeCard {
				output.PrintWarning("Tip: Use -analyze flag to examine the card structure")
				// Auto-analyze on USIM failure
				fmt.Println()
				output.PrintSuccess("Auto-analyzing card...")
				cardInfo, anaErr := sim.AnalyzeCard(reader, *checkADMStatus)
				if anaErr == nil {
					output.PrintCardAnalysis(cardInfo)
				}
			}
		}
	} else if !*outputJSON {
		output.PrintUSIMData(usimData)
	}

	// Read ISIM data (only if USIM was found)
	var isimData *sim.ISIMData
	if usimData != nil {
		if !*outputJSON {
			fmt.Println()
			output.PrintSuccess("Reading ISIM application...")
		}
		isimData, err = sim.ReadISIM(reader)
		if err != nil {
			if !*outputJSON {
				output.PrintWarning(fmt.Sprintf("ISIM: %v", err))
			}
		} else if !*outputJSON {
			output.PrintISIMData(isimData)
		}
	}

	// Read Phonebook if requested
	if *showPhonebook {
		fmt.Println()
		output.PrintSuccess("Reading Phonebook (EF_ADN)...")
		entries, err := sim.ReadPhonebook(reader)
		if err != nil {
			output.PrintWarning(fmt.Sprintf("Phonebook: %v", err))
		} else {
			output.PrintPhonebook(entries)
		}
	}

	// Read SMS if requested
	if *showSMS {
		fmt.Println()
		output.PrintSuccess("Reading SMS (EF_SMS)...")
		messages, err := sim.ReadSMS(reader)
		if err != nil {
			output.PrintWarning(fmt.Sprintf("SMS: %v", err))
		} else {
			output.PrintSMS(messages)
		}
	}

	// Show GlobalPlatform applets if requested
	if *showApplets {
		fmt.Println()
		output.PrintSuccess("Reading GlobalPlatform applets...")
		applets, err := sim.ListApplets(reader)
		if err != nil {
			output.PrintWarning(fmt.Sprintf("Applets: %v", err))
		} else {
			output.PrintApplets(applets)
		}
	}

	// Run APDU script if requested (simple format)
	if *runScript != "" {
		fmt.Println()
		output.PrintSuccess(fmt.Sprintf("Running script: %s", *runScript))
		results, err := sim.RunScript(reader, *runScript)
		if err != nil {
			output.PrintError(fmt.Sprintf("Script error: %v", err))
		} else {
			output.PrintScriptResults(results)
		}
	}

	// Run .pcom script if requested (RuSIM/OX24 format)
	if *runPcom != "" {
		fmt.Println()
		output.PrintSuccess(fmt.Sprintf("Running .pcom script: %s", *runPcom))
		fmt.Println()

		executor := sim.NewPcomExecutor(reader)
		executor.SetVerbose(*pcomVerbose)
		executor.SetStopOnError(*pcomStop)

		err := executor.ExecuteFile(*runPcom)
		if err != nil {
			output.PrintError(fmt.Sprintf("Script error: %v", err))
		}

		// Print statistics
		total, success, failed := executor.GetStatistics()
		fmt.Println()
		if failed > 0 {
			output.PrintWarning(fmt.Sprintf("Script completed: %d commands, %d success, %d failed", total, success, failed))
		} else {
			output.PrintSuccess(fmt.Sprintf("Script completed: %d commands, %d success", total, success))
		}
	}

	// Output JSON if requested
	if *outputJSON {
		jsonConfig := sim.ExportToConfig(usimData, isimData)
		jsonData, err := json.MarshalIndent(jsonConfig, "", "  ")
		if err != nil {
			output.PrintError(fmt.Sprintf("JSON export failed: %v", err))
		} else {
			fmt.Println(string(jsonData))
		}
	}

	// Show all services if requested
	if *showAllServices && !*outputJSON {
		output.PrintAllServices(usimData, isimData)
	}

	// Show raw data if requested
	if *showRaw && !*outputJSON {
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

	if !*outputJSON {
		fmt.Println()
		output.PrintSuccess("Done!")
	}
}
