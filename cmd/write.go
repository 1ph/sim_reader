package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"sim_reader/card"
	"sim_reader/output"
	"sim_reader/sim"
)

var (
	// Write command flags
	writeConfigFile string
	writeIMSI       string
	writeIMPI       string
	writeIMPU       string
	writeDomain     string
	writePCSCF      string
	writeSPN        string
	writeHPLMN      string
	writeUserPLMN   string
	writeOPLMN      string
	setOpMode       string

	// Service enable flags
	enableVoLTE     bool
	enableVoWiFi    bool
	enableSMSOverIP bool
	enableVoicePref bool

	// Service disable flags
	disableVoLTE     bool
	disableVoWiFi    bool
	disableSMSOverIP bool
	disableVoicePref bool

	// Other write flags
	clearFPLMN   bool
	setCardAlgo  string
	showCardAlgo bool

	// ADM key change flags
	changeADM1 string
	changeADM2 string
	changeADM3 string
	changeADM4 string

	// Programmable card flags
	progDryRun bool
	progForce  bool
)

var writeCmd = &cobra.Command{
	Use:   "write",
	Short: "Write SIM card parameters",
	Long: `Write parameters to SIM/USIM/ISIM card.
Requires ADM key (-a/--adm) for most operations.

Examples:
  # Write from JSON config file
  sim_reader write -a 77111606 -f config.json

  # Write IMSI
  sim_reader write -a 77111606 --imsi 250880000000001

  # Write ISIM parameters
  sim_reader write -a 77111606 --impi 250880...@ims.domain.org --impu sip:250880...@ims.domain.org

  # Enable VoLTE and VoWiFi
  sim_reader write -a 77111606 --enable-volte --enable-vowifi

  # Disable services
  sim_reader write -a 77111606 --disable-volte

  # Write PLMN settings
  sim_reader write -a 77111606 --hplmn 250:88:eutran,utran,gsm

  # Clear forbidden PLMN list
  sim_reader write -a 77111606 --clear-fplmn

  # Change ADM1 key
  sim_reader write -a 77111606 --change-adm1 1122334455667788

  # Set authentication algorithm
  sim_reader write -a 77111606 --set-algo milenage

  # Programmable card: dry run (safe test)
  sim_reader write -a 4444444444444444 -f prog_config.json --dry-run

  # Programmable card: actual write (DANGEROUS!)
  sim_reader write -a 4444444444444444 -f prog_config.json`,
	Run: runWrite,
}

func init() {
	// Config file
	writeCmd.Flags().StringVarP(&writeConfigFile, "file", "f", "",
		"Apply configuration from JSON file")

	// Individual parameters
	writeCmd.Flags().StringVar(&writeIMSI, "imsi", "",
		"Write IMSI (e.g., 250880000000001)")
	writeCmd.Flags().StringVar(&writeIMPI, "impi", "",
		"Write IMPI (IMS Private Identity)")
	writeCmd.Flags().StringVar(&writeIMPU, "impu", "",
		"Write IMPU (IMS Public Identity)")
	writeCmd.Flags().StringVar(&writeDomain, "domain", "",
		"Write Home Network Domain")
	writeCmd.Flags().StringVar(&writePCSCF, "pcscf", "",
		"Write P-CSCF address")
	writeCmd.Flags().StringVar(&writeSPN, "spn", "",
		"Write Service Provider Name")
	writeCmd.Flags().StringVar(&writeHPLMN, "hplmn", "",
		"Write HPLMN (MCC:MNC:ACT, e.g., 250:88:eutran,utran,gsm)")
	writeCmd.Flags().StringVar(&writeUserPLMN, "user-plmn", "",
		"Write User PLMN (MCC:MNC:ACT)")
	writeCmd.Flags().StringVar(&writeOPLMN, "oplmn", "",
		"Write Operator PLMN (MCC:MNC:ACT)")
	writeCmd.Flags().StringVar(&setOpMode, "op-mode", "",
		"Set UE operation mode (normal, type-approval, cell-test, etc.)")

	// Service enable flags
	writeCmd.Flags().BoolVar(&enableVoLTE, "enable-volte", false,
		"Enable VoLTE services")
	writeCmd.Flags().BoolVar(&enableVoWiFi, "enable-vowifi", false,
		"Enable VoWiFi services")
	writeCmd.Flags().BoolVar(&enableSMSOverIP, "enable-sms-ip", false,
		"Enable SMS over IP (ISIM)")
	writeCmd.Flags().BoolVar(&enableVoicePref, "enable-voice-pref", false,
		"Enable Voice Domain Preference (ISIM)")

	// Service disable flags
	writeCmd.Flags().BoolVar(&disableVoLTE, "disable-volte", false,
		"Disable VoLTE services")
	writeCmd.Flags().BoolVar(&disableVoWiFi, "disable-vowifi", false,
		"Disable VoWiFi services")
	writeCmd.Flags().BoolVar(&disableSMSOverIP, "disable-sms-ip", false,
		"Disable SMS over IP (ISIM)")
	writeCmd.Flags().BoolVar(&disableVoicePref, "disable-voice-pref", false,
		"Disable Voice Domain Preference (ISIM)")

	// Other flags
	writeCmd.Flags().BoolVar(&clearFPLMN, "clear-fplmn", false,
		"Clear Forbidden PLMN list")
	writeCmd.Flags().BoolVar(&showCardAlgo, "show-algo", false,
		"Show current USIM auth algorithm (EF 8F90)")
	writeCmd.Flags().StringVar(&setCardAlgo, "set-algo", "",
		"Set USIM auth algorithm: milenage, s3g-128, tuak, s3g-256")

	// ADM key change flags
	writeCmd.Flags().StringVar(&changeADM1, "change-adm1", "",
		"Change ADM1 key to new value (requires -a with current key)")
	writeCmd.Flags().StringVar(&changeADM2, "change-adm2", "",
		"Change ADM2 key to new value (requires --adm2 with current key)")
	writeCmd.Flags().StringVar(&changeADM3, "change-adm3", "",
		"Change ADM3 key to new value (requires --adm3 with current key)")
	writeCmd.Flags().StringVar(&changeADM4, "change-adm4", "",
		"Change ADM4 key to new value (requires --adm4 with current key)")

	// Programmable card flags
	writeCmd.Flags().BoolVar(&progDryRun, "dry-run", false,
		"Simulate programmable card operations without writing (SAFE test mode)")
	writeCmd.Flags().BoolVar(&progForce, "force", false,
		"Force programmable operations on unrecognized cards (EXTREMELY DANGEROUS!)")

	rootCmd.AddCommand(writeCmd)
}

func runWrite(cmd *cobra.Command, args []string) {
	// Check if any write operation is requested
	isWriteMode := writeConfigFile != "" || writeIMSI != "" || writeIMPI != "" ||
		writeIMPU != "" || writeDomain != "" || writePCSCF != "" || writeSPN != "" ||
		writeHPLMN != "" || writeUserPLMN != "" || writeOPLMN != "" || setOpMode != "" ||
		enableVoLTE || enableVoWiFi || enableSMSOverIP || enableVoicePref ||
		disableVoLTE || disableVoWiFi || disableSMSOverIP || disableVoicePref ||
		clearFPLMN ||
		changeADM1 != "" || changeADM2 != "" || changeADM3 != "" || changeADM4 != "" ||
		setCardAlgo != ""

	// Only show algo doesn't require ADM
	if !isWriteMode && !showCardAlgo {
		cmd.Help()
		return
	}

	// Require ADM key for write operations
	if isWriteMode {
		if err := requireADMKey(); err != nil {
			printError(err.Error())
			return
		}
	}

	// Connect to reader
	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	// Show/set proprietary USIM authentication algorithm (EF 8F90) if requested
	if showCardAlgo || setCardAlgo != "" {
		drv := sim.FindDriver(reader)
		if drv == nil {
			printWarning("This card does not support proprietary USIM algorithm selector (EF 8F90).")
		} else {
			if setCardAlgo != "" {
				err := drv.SetAlgorithmType(reader, setCardAlgo)
				if err != nil {
					printError(fmt.Sprintf("Failed to update USIM auth algorithm: %v", err))
				} else {
					printSuccess(fmt.Sprintf("USIM auth algorithm updated to: %s", setCardAlgo))
				}
			}

			algo, err := drv.GetAlgorithmType(reader)
			if err != nil {
				printWarning(fmt.Sprintf("USIM auth algorithm read failed: %v", err))
			} else {
				printSuccess(fmt.Sprintf("USIM auth algorithm: %s", algo))
			}
		}
	}

	if !isWriteMode {
		return
	}

	fmt.Println()
	printSuccess("Starting write operations...")

	// Apply JSON config
	if writeConfigFile != "" {
		config, err := sim.LoadConfig(writeConfigFile)
		if err != nil {
			printError(fmt.Sprintf("Failed to load config: %v", err))
			return
		}

		// Show programmable card warning if programmable fields are present
		if config.RequiresProgrammableCard() {
			output.PrintProgrammableWriteWarning(progDryRun)
		}

		if err := sim.ApplyConfig(reader, config, progDryRun, progForce); err != nil {
			printError(fmt.Sprintf("Config apply failed: %v", err))
		}

		// Exit after dry run for programmable operations
		if progDryRun && config.RequiresProgrammableCard() {
			return
		}
	}

	// Individual write operations
	if writeIMSI != "" {
		if err := sim.WriteIMSI(reader, writeIMSI); err != nil {
			printError(fmt.Sprintf("Write IMSI failed: %v", err))
		} else {
			printSuccess("IMSI written successfully")
		}
	}

	if writeSPN != "" {
		if err := sim.WriteSPN(reader, writeSPN, 0x00); err != nil {
			printError(fmt.Sprintf("Write SPN failed: %v", err))
		} else {
			printSuccess("SPN written successfully")
		}
	}

	if writeIMPI != "" {
		if err := sim.WriteIMPI(reader, writeIMPI); err != nil {
			printError(fmt.Sprintf("Write IMPI failed: %v", err))
		} else {
			printSuccess("IMPI written successfully")
		}
	}

	if writeIMPU != "" {
		if err := sim.WriteIMPU(reader, writeIMPU); err != nil {
			printError(fmt.Sprintf("Write IMPU failed: %v", err))
		} else {
			printSuccess("IMPU written successfully")
		}
	}

	if writeDomain != "" {
		if err := sim.WriteDomain(reader, writeDomain); err != nil {
			printError(fmt.Sprintf("Write Domain failed: %v", err))
		} else {
			printSuccess("Domain written successfully")
		}
	}

	if writePCSCF != "" {
		if err := sim.WritePCSCF(reader, writePCSCF); err != nil {
			printError(fmt.Sprintf("Write P-CSCF failed: %v", err))
		} else {
			printSuccess("P-CSCF written successfully")
		}
	}

	if writeHPLMN != "" {
		if err := sim.WriteHPLMNFromString(reader, writeHPLMN); err != nil {
			printError(fmt.Sprintf("Write HPLMN failed: %v", err))
		} else {
			printSuccess("HPLMN written successfully")
		}
	}

	if writeUserPLMN != "" {
		if err := sim.WriteUserPLMNFromString(reader, writeUserPLMN); err != nil {
			printError(fmt.Sprintf("Write User PLMN failed: %v", err))
		} else {
			printSuccess("User PLMN written successfully")
		}
	}

	if writeOPLMN != "" {
		if err := sim.WriteOPLMNFromString(reader, writeOPLMN); err != nil {
			printError(fmt.Sprintf("Write Operator PLMN failed: %v", err))
		} else {
			printSuccess("Operator PLMN written successfully")
		}
	}

	if setOpMode != "" {
		if err := sim.SetOperationModeFromString(reader, setOpMode); err != nil {
			printError(fmt.Sprintf("Set Operation Mode failed: %v", err))
		} else {
			printSuccess(fmt.Sprintf("Operation mode set to: %s", setOpMode))
		}
	}

	// Enable operations
	if enableVoLTE {
		if err := sim.EnableVoLTE(reader); err != nil {
			printError(fmt.Sprintf("Enable VoLTE failed: %v", err))
		} else {
			printSuccess("VoLTE enabled")
		}
	}

	if enableVoWiFi {
		if err := sim.EnableVoWiFi(reader); err != nil {
			printError(fmt.Sprintf("Enable VoWiFi failed: %v", err))
		} else {
			printSuccess("VoWiFi enabled")
		}
	}

	if enableSMSOverIP {
		if err := sim.EnableISIMSMSOverIP(reader); err != nil {
			printError(fmt.Sprintf("Enable SMS over IP failed: %v", err))
		} else {
			printSuccess("SMS over IP enabled (ISIM)")
		}
	}

	if enableVoicePref {
		if err := sim.EnableISIMVoiceDomainPref(reader); err != nil {
			printError(fmt.Sprintf("Enable Voice Domain Pref failed: %v", err))
		} else {
			printSuccess("Voice Domain Preference enabled (ISIM)")
		}
	}

	// Disable operations
	if disableVoLTE {
		if err := sim.DisableVoLTE(reader); err != nil {
			printError(fmt.Sprintf("Disable VoLTE failed: %v", err))
		} else {
			printSuccess("VoLTE disabled")
		}
	}

	if disableVoWiFi {
		if err := sim.DisableVoWiFi(reader); err != nil {
			printError(fmt.Sprintf("Disable VoWiFi failed: %v", err))
		} else {
			printSuccess("VoWiFi disabled")
		}
	}

	if disableSMSOverIP {
		if err := sim.DisableISIMSMSOverIP(reader); err != nil {
			printError(fmt.Sprintf("Disable SMS over IP failed: %v", err))
		} else {
			printSuccess("SMS over IP disabled (ISIM)")
		}
	}

	if disableVoicePref {
		if err := sim.DisableISIMVoiceDomainPref(reader); err != nil {
			printError(fmt.Sprintf("Disable Voice Domain Pref failed: %v", err))
		} else {
			printSuccess("Voice Domain Preference disabled (ISIM)")
		}
	}

	if clearFPLMN {
		if err := sim.ClearForbiddenPLMN(reader); err != nil {
			printError(fmt.Sprintf("Clear FPLMN failed: %v", err))
		} else {
			printSuccess("Forbidden PLMN list cleared")
		}
	}

	// ADM key change operations
	if changeADM1 != "" {
		if admKey == "" {
			printError("Change ADM1 requires -a/--adm with current ADM1 key")
		} else {
			oldKey, _ := card.ParseADMKey(admKey)
			newKey, err := card.ParseADMKey(changeADM1)
			if err != nil {
				printError(fmt.Sprintf("Invalid new ADM1 key: %v", err))
			} else {
				printWarning(fmt.Sprintf("Changing ADM1: %s -> %s", card.KeyToHex(oldKey), card.KeyToHex(newKey)))
				if err := reader.ChangeADM1(oldKey, newKey); err != nil {
					printError(fmt.Sprintf("Change ADM1 failed: %v", err))
				} else {
					printSuccess("ADM1 key changed successfully")
				}
			}
		}
	}

	if changeADM2 != "" {
		if admKey2 == "" {
			printError("Change ADM2 requires --adm2 with current ADM2 key")
		} else {
			oldKey, _ := card.ParseADMKey(admKey2)
			newKey, err := card.ParseADMKey(changeADM2)
			if err != nil {
				printError(fmt.Sprintf("Invalid new ADM2 key: %v", err))
			} else {
				printWarning(fmt.Sprintf("Changing ADM2: %s -> %s", card.KeyToHex(oldKey), card.KeyToHex(newKey)))
				if err := reader.ChangeADM2(oldKey, newKey); err != nil {
					printError(fmt.Sprintf("Change ADM2 failed: %v", err))
				} else {
					printSuccess("ADM2 key changed successfully")
				}
			}
		}
	}

	if changeADM3 != "" {
		if admKey3 == "" {
			printError("Change ADM3 requires --adm3 with current ADM3 key")
		} else {
			oldKey, _ := card.ParseADMKey(admKey3)
			newKey, err := card.ParseADMKey(changeADM3)
			if err != nil {
				printError(fmt.Sprintf("Invalid new ADM3 key: %v", err))
			} else {
				printWarning(fmt.Sprintf("Changing ADM3: %s -> %s", card.KeyToHex(oldKey), card.KeyToHex(newKey)))
				if err := reader.ChangeADM3(oldKey, newKey); err != nil {
					printError(fmt.Sprintf("Change ADM3 failed: %v", err))
				} else {
					printSuccess("ADM3 key changed successfully")
				}
			}
		}
	}

	if changeADM4 != "" {
		if admKey4 == "" {
			printError("Change ADM4 requires --adm4 with current ADM4 key")
		} else {
			oldKey, _ := card.ParseADMKey(admKey4)
			newKey, err := card.ParseADMKey(changeADM4)
			if err != nil {
				printError(fmt.Sprintf("Invalid new ADM4 key: %v", err))
			} else {
				printWarning(fmt.Sprintf("Changing ADM4: %s -> %s", card.KeyToHex(oldKey), card.KeyToHex(newKey)))
				if err := reader.ChangeADM4(oldKey, newKey); err != nil {
					printError(fmt.Sprintf("Change ADM4 failed: %v", err))
				} else {
					printSuccess("ADM4 key changed successfully")
				}
			}
		}
	}

	fmt.Println()
	printSuccess("Write operations completed.")
}

