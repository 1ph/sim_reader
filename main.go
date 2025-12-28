package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"sim_reader/algorithms"
	"sim_reader/card"
	"sim_reader/output"
	"sim_reader/sim"
	_ "sim_reader/sim/card_drivers"
	"sim_reader/testing"
)

var (
	version = "3.1.0"
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

	// GlobalPlatform (secured cards) flags
	gpList := flag.Bool("gp-list", false, "GlobalPlatform: list applets/packages via Secure Channel (SCP02)")
	gpProbe := flag.Bool("gp-probe", false, "GlobalPlatform: check if provided KVN+keys are correct (INITIALIZE UPDATE + cryptogram verify only)")
	gpKVN := flag.Int("gp-kvn", 0, "GlobalPlatform: Key Version Number (KVN) for INITIALIZE UPDATE (0-255)")
	gpSec := flag.String("gp-sec", "mac", "GlobalPlatform: security level (mac or mac+enc)")
	gpKeyENC := flag.String("gp-key-enc", "", "GlobalPlatform: static ENC key (hex, 16 or 24 bytes)")
	gpKeyMAC := flag.String("gp-key-mac", "", "GlobalPlatform: static MAC key (hex, 16 or 24 bytes)")
	gpKeyDEK := flag.String("gp-key-dek", "", "GlobalPlatform: static DEK key (hex, 16 or 24 bytes, optional)")
	gpKeyPSK := flag.String("gp-key-psk", "", "GlobalPlatform: convenience key (hex) to set ENC=MAC=PSK (optional)")
	gpSDAID := flag.String("gp-sd-aid", "A000000003000000", "GlobalPlatform: Security Domain / Card Manager AID to select (hex)")
	gpDelete := flag.String("gp-delete", "", "GlobalPlatform: DELETE by AID (comma-separated hex AIDs) - DANGEROUS")
	gpLoadCAP := flag.String("gp-load-cap", "", "GlobalPlatform: path to .cap (ZIP) to LOAD+INSTALL")
	gpPackageAID := flag.String("gp-package-aid", "", "GlobalPlatform: package (load file) AID for INSTALL [for load] (hex)")
	gpAppletAID := flag.String("gp-applet-aid", "", "GlobalPlatform: applet class AID for INSTALL [for install] (hex)")
	gpInstanceAID := flag.String("gp-instance-aid", "", "GlobalPlatform: applet instance AID (hex). Defaults to -gp-applet-aid if empty.")
	gpVerifyAID := flag.String("gp-verify-aid", "", "GlobalPlatform: SELECT AID and show SW (hex)")
	gpAramAddRule := flag.Bool("gp-aram-add-rule", false, "GlobalPlatform: add ARA-M access rule via STORE DATA (requires Secure Channel)")
	gpAramAID := flag.String("gp-aram-aid", "A00000015141434C00", "GlobalPlatform: ARA-M applet AID (hex)")
	gpAramRuleAID := flag.String("gp-aram-rule-aid", "FFFFFFFFFFFF", "GlobalPlatform: target applet AID for rule (hex), use FFFFFFFFFFFF for wildcard")
	gpAramCertHash := flag.String("gp-aram-cert-hash", "", "GlobalPlatform: Android app certificate hash (SHA-1=20 bytes or SHA-256=32 bytes, hex)")
	gpAramPerm := flag.String("gp-aram-perm", "0000000000000001", "GlobalPlatform: PERM-AR-DO value (hex, commonly 8 bytes)")

	// GlobalPlatform: load keys from DMS-style "var_out" file
	gpDMSFile := flag.String("gp-dms", "", "GlobalPlatform: path to DMS var_out key file (e.g. DMS72100_decr.out)")
	gpDMSICCID := flag.String("gp-dms-iccid", "", "GlobalPlatform: ICCID to select row in -gp-dms")
	gpDMSIMSI := flag.String("gp-dms-imsi", "", "GlobalPlatform: IMSI to select row in -gp-dms (alternative to -gp-dms-iccid)")
	gpDMSKeyset := flag.String("gp-dms-keyset", "cm", "GlobalPlatform: keyset name in -gp-dms (cm, psk40, psk41, a..h, auto)")
	gpAuto := flag.Bool("gp-auto", false, "GlobalPlatform: auto-probe KVN+keyset (requires -gp-dms). Finds working combination for the card.")

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
	showCardAlgo := flag.Bool("show-card-algo", false, "Show current USIM auth algorithm (EF 8F90) if supported")
	setCardAlgo := flag.String("set-card-algo", "", "Set USIM auth algorithm (EF 8F90): milenage, s3g-128, tuak, s3g-256 (requires -adm)")

	// ADM key change flags
	changeADM1 := flag.String("change-adm1", "", "Change ADM1 key to new value (requires -adm with current key)")
	changeADM2 := flag.String("change-adm2", "", "Change ADM2 key to new value (requires -adm2 with current key)")
	changeADM3 := flag.String("change-adm3", "", "Change ADM3 key to new value (requires -adm3 with current key)")
	changeADM4 := flag.String("change-adm4", "", "Change ADM4 key to new value (requires -adm4 with current key)")

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

	// Programmable card flags (use -write with "programmable" section in JSON)
	progInfo := flag.Bool("prog-info", false, "Show programmable card information and supported operations")
	progDryRun := flag.Bool("prog-dry-run", false, "Simulate programming without writing (test mode)")
	progForce := flag.Bool("prog-force", false, "Force programming on unrecognized cards (DANGEROUS!)")

	// Test suite flags
	testMode := flag.Bool("test", false, "Run full SIM card test suite")
	testOutput := flag.String("test-output", "", "Output file prefix for test reports (.json + .html)")
	testOnly := flag.String("test-only", "", "Run specific test category: usim,isim,auth,apdu,security")

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
  -gp-list           GlobalPlatform list via Secure Channel (SCP02)
  -gp-key-enc <hex>  GlobalPlatform ENC key (required for -gp-* ops)
  -gp-key-mac <hex>  GlobalPlatform MAC key (required for -gp-* ops)
  -gp-key-dek <hex>  GlobalPlatform DEK key (optional)
  -gp-kvn <n>        GlobalPlatform KVN (default: 0)
  -gp-sec <lvl>      GlobalPlatform security level: mac or mac+enc
  -gp-sd-aid <hex>   GlobalPlatform SD/Card Manager AID (default: A000000003000000)
  -gp-delete <aids>  GlobalPlatform DELETE (comma-separated AIDs) - DANGEROUS
  -gp-load-cap <p>   GlobalPlatform LOAD+INSTALL from .cap ZIP (requires -gp-package-aid and -gp-applet-aid)
  -gp-package-aid <h> GlobalPlatform package AID (hex) for install-for-load
  -gp-applet-aid <h>  GlobalPlatform applet AID (hex) for install-for-install
  -gp-instance-aid <h> GlobalPlatform instance AID (hex, default: applet AID)
  -gp-verify-aid <h> GlobalPlatform SELECT verify (hex)
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
  -show-card-algo    Show current USIM auth algorithm (EF 8F90)
  -set-card-algo <a> Set USIM auth algorithm (milenage, s3g-128, tuak, s3g-256)

ADM KEY CHANGE (use with caution - wrong key will decrement counter!):
  -change-adm1 <new> Change ADM1 key (requires -adm with current key)
  -change-adm2 <new> Change ADM2 key (requires -adm2 with current key)
  -change-adm3 <new> Change ADM3 key (requires -adm3 with current key)
  -change-adm4 <new> Change ADM4 key (requires -adm4 with current key)

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

PROGRAMMABLE CARD OPTIONS (⚠️  DANGEROUS - CAN PERMANENTLY BRICK CARD!):
  -prog-info           Show programmable card information (card type, File IDs)
  -prog-dry-run        Simulate without writing (SAFE - test your commands!)
  -prog-force          Force on unrecognized cards (EXTREMELY DANGEROUS!)

  ⚠️  READ BEFORE USE:
  • Programmable operations are PERMANENT and CANNOT BE UNDONE
  • ALWAYS use -prog-dry-run first to test your commands
  • Wrong keys will PERMANENTLY BRICK the card
  • Only for blank/programmable SIM cards (Grcard, open5gs, etc.)
  • Regular operator SIM cards are NOT programmable
  • Use -write <config.json> with "programmable" section to program card
  • See docs/programmable_custom_example.json for example config

TEST SUITE OPTIONS:
  -test              Run comprehensive SIM card test suite
  -test-output <p>   Output file prefix (.json + .html reports)
  -test-only <cat>   Run specific category: usim,isim,auth,apdu,security

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

  # Change ADM1 key (sysmoUSIM default key example)
  %s -adm 4444444444444444 -change-adm1 1122334455667788

  # Change ADM1 key (decimal format)
  %s -adm 88888888 -change-adm1 12345678

  # Programmable card: show info
  %s -prog-info

  # Programmable card: DRY RUN (test without writing)
  %s -adm 4444444444444444 -write programmable_config.json -prog-dry-run

  # Programmable card: program card from JSON config (PERMANENT!)
  %s -adm 4444444444444444 -write programmable_config.json

  # See docs/programmable_custom_example.json for example config

  # Run full test suite
  %s -test -adm 4444444444444444 -auth-k FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 -auth-opc 808182838485868788898A8B8C8D8E8F -test-output baseline

  # Run only USIM file tests
  %s -test -test-only usim -adm 4444444444444444

  # Run only authentication tests
  %s -test -test-only auth -auth-k FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 -auth-opc 808182838485868788898A8B8C8D8E8F

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
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
		*clearFPLMN ||
		*changeADM1 != "" || *changeADM2 != "" || *changeADM3 != "" || *changeADM4 != "" ||
		*setCardAlgo != ""

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

	// Perform warm reset to ensure clean card state
	// This is essential when running multiple times without removing the card
	if err := reader.Reconnect(false); err != nil {
		// Warm reset failed, try cold reset
		if err := reader.Reconnect(true); err != nil {
			// If both fail, just continue - some readers don't support reset
			if !*outputJSON {
				output.PrintWarning(fmt.Sprintf("Card reset failed: %v (continuing anyway)", err))
			}
		}
	}

	if !*outputJSON {
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

	// Handle test suite mode
	if *testMode {
		fmt.Println()
		output.PrintSuccess("Running SIM Card Test Suite...")

		// Parse auth config for tests
		var testAuthK, testAuthOPc []byte
		if *authK != "" {
			k, err := sim.ParseHexBytes(*authK)
			if err == nil {
				testAuthK = k
			}
		}
		if *authOPc != "" {
			opc, err := sim.ParseHexBytes(*authOPc)
			if err == nil {
				testAuthOPc = opc
			}
		} else if *authOP != "" {
			// Compute OPc from OP
			op, err := sim.ParseHexBytes(*authOP)
			if err == nil && len(testAuthK) > 0 {
				computed, _ := algorithms.ComputeOPc(testAuthK, op)
				testAuthOPc = computed
			}
		}

		// Parse ADM key
		var admKeyBytes []byte
		if *admKey != "" {
			key, err := card.ParseADMKey(*admKey)
			if err == nil {
				admKeyBytes = key
			}
		}

		// Parse SQN and AMF
		var sqnBytes, amfBytes []byte
		if *authSQN != "" {
			sqn, _ := sim.ParseHexBytes(*authSQN)
			sqnBytes = sqn
		}
		if *authAMF != "" {
			amf, _ := sim.ParseHexBytes(*authAMF)
			amfBytes = amf
		}

		// Create test options
		opts := testing.TestOptions{
			ADMKey:    admKeyBytes,
			PIN1:      *pin1,
			AuthK:     testAuthK,
			AuthOPc:   testAuthOPc,
			AuthSQN:   sqnBytes,
			AuthAMF:   amfBytes,
			Algorithm: *authAlgo,
			Verbose:   true,
		}

		// Create and run test suite
		suite := testing.NewTestSuite(reader, opts)

		if *testOnly != "" {
			// Run specific category
			categories := strings.Split(*testOnly, ",")
			for _, cat := range categories {
				cat = strings.TrimSpace(cat)
				if err := suite.RunCategory(cat); err != nil {
					output.PrintWarning(fmt.Sprintf("Category %s: %v", cat, err))
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
		if *testOutput != "" {
			if err := suite.GenerateReport(*testOutput); err != nil {
				output.PrintError(fmt.Sprintf("Report generation failed: %v", err))
			}
		}

		os.Exit(0)
	}

	// GlobalPlatform secure operations (SCP02) - independent of SIM/USIM reading.
	// If any -gp-* operation is requested, run it and exit.
	gpRequested := *gpList || *gpProbe || *gpAramAddRule || *gpDelete != "" || *gpLoadCAP != "" || *gpVerifyAID != ""
	if gpRequested {
		// Resolve keys (explicit flags override DMS file)
		var encKey, macKey, dekKey []byte
		var err error
		var dmsRow map[string]string

		// Optional: load from DMS file
		if *gpDMSFile != "" {
			db, e := sim.LoadDMSKeyDB(*gpDMSFile)
			if e != nil {
				output.PrintError(fmt.Sprintf("Failed to load -gp-dms: %v", e))
				os.Exit(1)
			}
			var row map[string]string

			// If ICCID/IMSI not explicitly provided, try to read ICCID from the card and use it.
			if *gpDMSICCID == "" && *gpDMSIMSI == "" {
				cardICCID, iccErr := sim.ReadICCIDQuick(reader)
				if iccErr != nil {
					output.PrintError("When using -gp-dms, provide -gp-dms-iccid/-gp-dms-imsi or ensure ICCID can be read from the card.")
					output.PrintError(fmt.Sprintf("ICCID read failed: %v", iccErr))
					os.Exit(1)
				}
				*gpDMSICCID = cardICCID
				if !*outputJSON {
					output.PrintSuccess(fmt.Sprintf("DMS: using ICCID from card: %s", cardICCID))
				}
			} else if *gpDMSICCID != "" {
				// If user provided ICCID, warn if it doesn't match the card currently in reader.
				if cardICCID, iccErr := sim.ReadICCIDQuick(reader); iccErr == nil && cardICCID != "" && cardICCID != *gpDMSICCID {
					if !*outputJSON {
						output.PrintWarning(fmt.Sprintf("DMS: provided ICCID (%s) does not match card ICCID (%s). Keys may not fit this card.", *gpDMSICCID, cardICCID))
					}
				}
			}

			if *gpDMSICCID != "" {
				row, e = db.FindByICCID(*gpDMSICCID)
			} else {
				row, e = db.FindByIMSI(*gpDMSIMSI)
			}
			if e != nil {
				output.PrintError(fmt.Sprintf("DMS row select failed: %v", e))
				os.Exit(1)
			}
			dmsRow = row
			// If not auto mode, extract immediately
			if !*gpAuto && strings.ToLower(strings.TrimSpace(*gpDMSKeyset)) != "auto" {
				encKey, macKey, dekKey, e = sim.GPKeysFromDMS(row, *gpDMSKeyset)
				if e != nil {
					output.PrintError(fmt.Sprintf("Failed to extract GP keys from -gp-dms: %v", e))
					os.Exit(1)
				}
			}
		}

		// Optional: PSK convenience (ENC=MAC)
		if *gpKeyPSK != "" {
			psk, e := sim.ParseHexBytes(*gpKeyPSK)
			if e != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-key-psk: %v", e))
				os.Exit(1)
			}
			encKey, macKey = psk, psk
		}

		// Explicit keys override everything
		if *gpKeyENC != "" {
			encKey, err = sim.ParseHexBytes(*gpKeyENC)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-key-enc: %v", err))
				os.Exit(1)
			}
		}
		if *gpKeyMAC != "" {
			macKey, err = sim.ParseHexBytes(*gpKeyMAC)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-key-mac: %v", err))
				os.Exit(1)
			}
		}
		if *gpKeyDEK != "" {
			dekKey, err = sim.ParseHexBytes(*gpKeyDEK)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-key-dek: %v", err))
				os.Exit(1)
			}
		}

		// Validate keys
		if (len(encKey) == 0 || len(macKey) == 0) && !(*gpAuto || strings.ToLower(strings.TrimSpace(*gpDMSKeyset)) == "auto") {
			output.PrintError("GlobalPlatform operations require ENC and MAC keys. Provide -gp-key-enc/-gp-key-mac, or -gp-key-psk, or -gp-dms + -gp-dms-keyset.")
			os.Exit(1)
		}

		sec, err := sim.ParseGPSecurityLevel(*gpSec)
		if err != nil {
			output.PrintError(err.Error())
			os.Exit(1)
		}

		sdAID, err := sim.ParseAIDHex(*gpSDAID)
		if err != nil {
			output.PrintError(fmt.Sprintf("Invalid -gp-sd-aid: %v", err))
			os.Exit(1)
		}

		cfg := sim.GPConfig{
			KVN:      byte(*gpKVN & 0xFF),
			Security: sec,
			StaticKeys: card.GPKeySet{
				ENC: encKey,
				MAC: macKey,
				DEK: dekKey,
			},
			SDAID:     sdAID,
			BlockSize: 200,
		}

		// gp-auto: find working combination using DMS row (ICCID/IMSI-selected)
		if (*gpAuto || strings.ToLower(strings.TrimSpace(*gpDMSKeyset)) == "auto") && *gpDMSFile != "" {
			if dmsRow == nil {
				output.PrintError("GP auto requires a DMS row; provide -gp-dms and ensure ICCID/IMSI can be resolved")
				os.Exit(1)
			}

			output.PrintSuccess("GlobalPlatform: auto-probing keyset/KVN (safe INIT UPDATE verify)...")

			// Keyset candidates
			keysets := []string{"cm", "psk40", "psk41", "a", "b", "c", "d", "e", "f", "g", "h"}

			// KVN candidates (common in the wild): 0, small ints, SCP02 reserved range 0x20..0x2F, PSK ranges 0x40/0x41, and 0xFF.
			var kvns []int
			kvns = append(kvns, *gpKVN)
			for _, v := range []int{0, 1, 2, 3} {
				kvns = append(kvns, v)
			}
			for v := 0x20; v <= 0x2F; v++ {
				kvns = append(kvns, v)
			}
			kvns = append(kvns, 0x40, 0x41, 0xFF)
			// de-dup while preserving order
			seenKVN := map[int]bool{}
			var kvnList []int
			for _, v := range kvns {
				if v < 0 || v > 255 {
					continue
				}
				if seenKVN[v] {
					continue
				}
				seenKVN[v] = true
				kvnList = append(kvnList, v)
			}

			// SD AID candidates: user-provided + common GP ISD AID
			sdCandidates := [][]byte{sdAID}
			commonISD := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}
			if !bytes.Equal(sdAID, commonISD) {
				sdCandidates = append(sdCandidates, commonISD)
			}

			found := false
			for _, candSDAID := range sdCandidates {
				_, _ = reader.Select(candSDAID)

				for _, ks := range keysets {
					enc, mac, dek, e := sim.GPKeysFromDMS(dmsRow, ks)
					if e != nil {
						continue
					}
					for _, kvn := range kvnList {
						hostChallenge := make([]byte, 8)
						if _, e := rand.Read(hostChallenge); e != nil {
							output.PrintError(fmt.Sprintf("Failed to generate host challenge: %v", e))
							os.Exit(1)
						}
						e = card.ProbeSecureChannelAuto(reader, card.GPKeySet{ENC: enc, MAC: mac, DEK: dek}, byte(kvn), hostChallenge)
						if e == nil {
							cfg.KVN = byte(kvn)
							cfg.SDAID = candSDAID
							cfg.StaticKeys = card.GPKeySet{ENC: enc, MAC: mac, DEK: dek}
							if !*outputJSON {
								output.PrintSuccess(fmt.Sprintf("GP auto matched: keyset=%s kvn=%d sd-aid=%X", ks, kvn, candSDAID))
							}
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				output.PrintError("GP auto failed: no working keyset/KVN found for this card (from provided DMS row).")
				output.PrintWarning("Возможные причины: DMS файл не содержит правильных GP ключей для этой карты, другой SD AID, или карта требует SCP03 S16/другие параметры.")
				os.Exit(1)
			}
		}

		// gp-probe (safe key check without EXTERNAL AUTH)
		if *gpProbe {
			output.PrintSuccess("GlobalPlatform: probing KVN+keys (INITIALIZE UPDATE + cryptogram verify)...")
			hostChallenge := make([]byte, 8)
			if _, err := rand.Read(hostChallenge); err != nil {
				output.PrintError(fmt.Sprintf("Failed to generate host challenge: %v", err))
				os.Exit(1)
			}
			// Select SD/CM before probe (same as OpenGPSCP02 behaviour)
			if len(cfg.SDAID) > 0 {
				_, _ = reader.Select(cfg.SDAID)
			}
			if err := card.ProbeSecureChannelAuto(reader, cfg.StaticKeys, cfg.KVN, hostChallenge); err != nil {
				output.PrintError(fmt.Sprintf("GP probe failed: %v", err))
				os.Exit(1)
			}
			output.PrintSuccess("GP probe OK: keys/KVN match this card")
		}

		// gp-verify-aid
		if *gpVerifyAID != "" {
			aid, err := sim.ParseAIDHex(*gpVerifyAID)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-verify-aid: %v", err))
				os.Exit(1)
			}
			sw, err := sim.GPSelectVerify(reader, aid)
			if err != nil {
				output.PrintError(fmt.Sprintf("GP SELECT failed: %v", err))
				os.Exit(1)
			}
			output.PrintSuccess(fmt.Sprintf("GP SELECT SW=%04X (%s)", sw, card.SWToString(sw)))
		}

		// gp-list
		if *gpList {
			output.PrintSuccess("GlobalPlatform: listing registry via Secure Channel (auto SCP02/SCP03)...")
			applets, err := sim.ListAppletsSecure(reader, cfg)
			if err != nil {
				output.PrintError(fmt.Sprintf("GP list failed: %v", err))
				os.Exit(1)
			}
			output.PrintApplets(applets)
		}

		// gp-aram-add-rule
		if *gpAramAddRule {
			if *gpAramCertHash == "" {
				output.PrintError("ARA-M add rule requires -gp-aram-cert-hash")
				os.Exit(1)
			}
			aramAID, err := sim.ParseAIDHex(*gpAramAID)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-aram-aid: %v", err))
				os.Exit(1)
			}
			ruleAID, err := sim.ParseHexBytes(*gpAramRuleAID)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-aram-rule-aid: %v", err))
				os.Exit(1)
			}
			certHash, err := sim.ParseHexBytes(*gpAramCertHash)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-aram-cert-hash: %v", err))
				os.Exit(1)
			}
			perm, err := sim.ParseHexBytes(*gpAramPerm)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-aram-perm: %v", err))
				os.Exit(1)
			}

			output.PrintWarning("ARA-M STORE DATA modifies access-control rules on the card. Wrong rules may break expected device behavior.")
			err = sim.GPAramAddRule(reader, cfg, aramAID, sim.GPARAMRule{
				TargetAID: ruleAID,
				CertHash:  certHash,
				Perm:      perm,
				ApduRule:  0x01, // ALWAYS allow
			})
			if err != nil {
				output.PrintError(fmt.Sprintf("GP ARA-M add rule failed: %v", err))
				os.Exit(1)
			}
			output.PrintSuccess("GP ARA-M rule added successfully")
		}

		// gp-delete
		if *gpDelete != "" {
			aids, err := sim.ParseAIDList(*gpDelete)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-delete: %v", err))
				os.Exit(1)
			}
			if len(aids) == 0 {
				output.PrintError("-gp-delete provided but no AIDs parsed")
				os.Exit(1)
			}
			output.PrintWarning("GlobalPlatform DELETE is dangerous and may brick the card.")
			if err := sim.DeleteAIDs(reader, cfg, aids); err != nil {
				output.PrintError(fmt.Sprintf("GP delete failed: %v", err))
				os.Exit(1)
			}
			output.PrintSuccess("GP delete completed")
		}

		// gp-load-cap (+ install)
		if *gpLoadCAP != "" {
			if err := sim.EnsureFileExists(*gpLoadCAP); err != nil {
				output.PrintError(fmt.Sprintf("CAP file error: %v", err))
				os.Exit(1)
			}
			if *gpPackageAID == "" || *gpAppletAID == "" {
				output.PrintError("GP load requires -gp-package-aid and -gp-applet-aid")
				os.Exit(1)
			}
			pkgAID, err := sim.ParseAIDHex(*gpPackageAID)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-package-aid: %v", err))
				os.Exit(1)
			}
			appAID, err := sim.ParseAIDHex(*gpAppletAID)
			if err != nil {
				output.PrintError(fmt.Sprintf("Invalid -gp-applet-aid: %v", err))
				os.Exit(1)
			}
			instAID := appAID
			if *gpInstanceAID != "" {
				instAID, err = sim.ParseAIDHex(*gpInstanceAID)
				if err != nil {
					output.PrintError(fmt.Sprintf("Invalid -gp-instance-aid: %v", err))
					os.Exit(1)
				}
			}
			output.PrintWarning("GlobalPlatform LOAD/INSTALL modifies card content. Ensure you have correct keys and a backup.")
			if err := sim.InstallLoadAndApplet(reader, cfg, *gpLoadCAP, sdAID, pkgAID, appAID, instAID); err != nil {
				output.PrintError(fmt.Sprintf("GP load/install failed: %v", err))
				os.Exit(1)
			}
			output.PrintSuccess("GP load/install completed")
		}

		os.Exit(0)
	}

	// Show/set proprietary USIM authentication algorithm (EF 8F90) if requested
	if *showCardAlgo || *setCardAlgo != "" {
		drv := sim.FindDriver(reader)
		if drv == nil {
			output.PrintWarning("This card does not support proprietary USIM algorithm selector (EF 8F90).")
		} else {
			if *setCardAlgo != "" {
				err := drv.SetAlgorithmType(reader, *setCardAlgo)
				if err != nil {
					output.PrintError(fmt.Sprintf("Failed to update USIM auth algorithm: %v", err))
				} else {
					output.PrintSuccess(fmt.Sprintf("USIM auth algorithm updated to: %s", *setCardAlgo))
				}
			}

			algo, err := drv.GetAlgorithmType(reader)
			if err != nil {
				output.PrintWarning(fmt.Sprintf("USIM auth algorithm read failed: %v", err))
			} else {
				output.PrintSuccess(fmt.Sprintf("USIM auth algorithm: %s", algo))
			}
		}
	}

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

	// Handle programmable card info request
	if *progInfo {
		cardTypeName := sim.ShowProgrammableCardInfo(reader)
		atrHex := fmt.Sprintf("%X", reader.ATR())
		output.PrintProgrammableCardInfo(cardTypeName, atrHex)
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

			// Show programmable card info and warnings if present
			if config.Programmable != nil {
				cardTypeName := sim.ShowProgrammableCardInfo(reader)
				atrHex := fmt.Sprintf("%X", reader.ATR())
				output.PrintProgrammableCardInfo(cardTypeName, atrHex)
				output.PrintProgrammableWriteWarning(*progDryRun)
			}

			if err := sim.ApplyConfig(reader, config, *progDryRun, *progForce); err != nil {
				output.PrintError(fmt.Sprintf("Config apply failed: %v", err))
			}

			// Exit after dry run
			if *progDryRun && config.Programmable != nil {
				os.Exit(0)
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

		// ADM key change operations
		if *changeADM1 != "" {
			if *admKey == "" {
				output.PrintError("Change ADM1 requires -adm with current ADM1 key")
			} else {
				oldKey, _ := card.ParseADMKey(*admKey)
				newKey, err := card.ParseADMKey(*changeADM1)
				if err != nil {
					output.PrintError(fmt.Sprintf("Invalid new ADM1 key: %v", err))
				} else {
					output.PrintWarning(fmt.Sprintf("Changing ADM1: %s -> %s", card.KeyToHex(oldKey), card.KeyToHex(newKey)))
					if err := reader.ChangeADM1(oldKey, newKey); err != nil {
						output.PrintError(fmt.Sprintf("Change ADM1 failed: %v", err))
					} else {
						output.PrintSuccess("ADM1 key changed successfully")
					}
				}
			}
		}

		if *changeADM2 != "" {
			if *admKey2 == "" {
				output.PrintError("Change ADM2 requires -adm2 with current ADM2 key")
			} else {
				oldKey, _ := card.ParseADMKey(*admKey2)
				newKey, err := card.ParseADMKey(*changeADM2)
				if err != nil {
					output.PrintError(fmt.Sprintf("Invalid new ADM2 key: %v", err))
				} else {
					output.PrintWarning(fmt.Sprintf("Changing ADM2: %s -> %s", card.KeyToHex(oldKey), card.KeyToHex(newKey)))
					if err := reader.ChangeADM2(oldKey, newKey); err != nil {
						output.PrintError(fmt.Sprintf("Change ADM2 failed: %v", err))
					} else {
						output.PrintSuccess("ADM2 key changed successfully")
					}
				}
			}
		}

		if *changeADM3 != "" {
			if *admKey3 == "" {
				output.PrintError("Change ADM3 requires -adm3 with current ADM3 key")
			} else {
				oldKey, _ := card.ParseADMKey(*admKey3)
				newKey, err := card.ParseADMKey(*changeADM3)
				if err != nil {
					output.PrintError(fmt.Sprintf("Invalid new ADM3 key: %v", err))
				} else {
					output.PrintWarning(fmt.Sprintf("Changing ADM3: %s -> %s", card.KeyToHex(oldKey), card.KeyToHex(newKey)))
					if err := reader.ChangeADM3(oldKey, newKey); err != nil {
						output.PrintError(fmt.Sprintf("Change ADM3 failed: %v", err))
					} else {
						output.PrintSuccess("ADM3 key changed successfully")
					}
				}
			}
		}

		if *changeADM4 != "" {
			if *admKey4 == "" {
				output.PrintError("Change ADM4 requires -adm4 with current ADM4 key")
			} else {
				oldKey, _ := card.ParseADMKey(*admKey4)
				newKey, err := card.ParseADMKey(*changeADM4)
				if err != nil {
					output.PrintError(fmt.Sprintf("Invalid new ADM4 key: %v", err))
				} else {
					output.PrintWarning(fmt.Sprintf("Changing ADM4: %s -> %s", card.KeyToHex(oldKey), card.KeyToHex(newKey)))
					if err := reader.ChangeADM4(oldKey, newKey); err != nil {
						output.PrintError(fmt.Sprintf("Change ADM4 failed: %v", err))
					} else {
						output.PrintSuccess("ADM4 key changed successfully")
					}
				}
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
