package cmd

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"sim_reader/card"
	"sim_reader/output"
	"sim_reader/sim"
)

var (
	// GP common flags
	gpKVN      int
	gpSec      string
	gpKeyENC   string
	gpKeyMAC   string
	gpKeyDEK   string
	gpKeyPSK   string
	gpSDAID    string

	// DMS support flags
	gpDMSFile    string
	gpDMSICCID   string
	gpDMSIMSI    string
	gpDMSKeyset  string
	gpAuto       bool

	// GP delete flags
	gpDeleteAIDs string

	// GP load flags
	gpLoadCAP     string
	gpPackageAID  string
	gpAppletAID   string
	gpInstanceAID string

	// GP verify flags
	gpVerifyAID string

	// GP ARAM flags
	gpAramAID      string
	gpAramRuleAID  string
	gpAramCertHash string
	gpAramPerm     string
)

var gpCmd = &cobra.Command{
	Use:   "gp",
	Short: "GlobalPlatform operations",
	Long: `GlobalPlatform secure operations (SCP02/SCP03).
Requires ENC and MAC keys for most operations.

Common flags (available for all gp subcommands):
  --key-enc, --key-mac, --key-dek   Static GP keys (hex)
  --key-psk                         Convenience: set ENC=MAC=PSK
  --kvn                             Key Version Number (default: 0)
  --sec                             Security level: mac or mac+enc
  --sd-aid                          Security Domain AID (default: A000000003000000)
  --dms                             DMS var_out key file path
  --dms-iccid, --dms-imsi           ICCID/IMSI for DMS row selection
  --dms-keyset                      Keyset name in DMS (cm, psk40, psk41, a..h)
  --auto                            Auto-probe KVN+keyset from DMS`,
}

var gpListCmd = &cobra.Command{
	Use:   "list",
	Short: "List applets via Secure Channel",
	Long: `List GlobalPlatform registry (applets, packages) via Secure Channel (SCP02/SCP03).

Examples:
  # List with explicit keys
  sim_reader gp list --key-enc AABBCC... --key-mac DDEEFF...

  # List with DMS file and auto-probe
  sim_reader gp list --dms keys.out --auto`,
	Run: runGPList,
}

var gpProbeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Verify KVN+keys without EXTERNAL AUTH",
	Long: `Probe GlobalPlatform keys: performs INITIALIZE UPDATE and verifies
card cryptogram, but does NOT send EXTERNAL AUTH (safe, no counter decrement).

Examples:
  sim_reader gp probe --key-enc AABBCC... --key-mac DDEEFF... --kvn 0`,
	Run: runGPProbe,
}

var gpDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete applets/packages by AID",
	Long: `Delete GlobalPlatform objects by AID. DANGEROUS - may brick card!

Examples:
  sim_reader gp delete --aids A0000001234567,A0000009876543 --key-enc X --key-mac Y`,
	Run: runGPDelete,
}

var gpLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load and install CAP file",
	Long: `Load CAP file and install applet. DANGEROUS - modifies card!

Examples:
  sim_reader gp load --cap /path/to/applet.cap \
    --package-aid A0000005591010FFFFFFFF8900 \
    --applet-aid A0000005591010FFFFFFFF89000100 \
    --key-enc X --key-mac Y`,
	Run: runGPLoad,
}

var gpAramCmd = &cobra.Command{
	Use:   "aram",
	Short: "Add ARA-M access rule",
	Long: `Add ARA-M (Access Rule Application Manager) access rule via STORE DATA.
Requires Secure Channel. Used for Android Secure Element access control.

Examples:
  sim_reader gp aram --cert-hash AABBCC... --rule-aid FFFFFFFFFFFF \
    --key-enc X --key-mac Y`,
	Run: runGPAram,
}

var gpVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify applet AID (SELECT and show SW)",
	Long: `SELECT applet by AID and show status word. Does not require Secure Channel.

Examples:
  sim_reader gp verify --aid A0000000871002FF49FF89`,
	Run: runGPVerify,
}

func init() {
	// GP common flags (persistent for all gp subcommands)
	gpCmd.PersistentFlags().IntVar(&gpKVN, "kvn", 0,
		"Key Version Number (KVN) for INITIALIZE UPDATE (0-255)")
	gpCmd.PersistentFlags().StringVar(&gpSec, "sec", "mac",
		"Security level: mac or mac+enc")
	gpCmd.PersistentFlags().StringVar(&gpKeyENC, "key-enc", "",
		"Static ENC key (hex, 16 or 24 bytes)")
	gpCmd.PersistentFlags().StringVar(&gpKeyMAC, "key-mac", "",
		"Static MAC key (hex, 16 or 24 bytes)")
	gpCmd.PersistentFlags().StringVar(&gpKeyDEK, "key-dek", "",
		"Static DEK key (hex, optional)")
	gpCmd.PersistentFlags().StringVar(&gpKeyPSK, "key-psk", "",
		"Convenience key: set ENC=MAC=PSK (hex)")
	gpCmd.PersistentFlags().StringVar(&gpSDAID, "sd-aid", "A000000003000000",
		"Security Domain / Card Manager AID (hex)")

	// DMS support
	gpCmd.PersistentFlags().StringVar(&gpDMSFile, "dms", "",
		"DMS var_out key file path")
	gpCmd.PersistentFlags().StringVar(&gpDMSICCID, "dms-iccid", "",
		"ICCID to select row in DMS file")
	gpCmd.PersistentFlags().StringVar(&gpDMSIMSI, "dms-imsi", "",
		"IMSI to select row in DMS file (alternative to --dms-iccid)")
	gpCmd.PersistentFlags().StringVar(&gpDMSKeyset, "dms-keyset", "cm",
		"Keyset name in DMS: cm, psk40, psk41, a..h, auto")
	gpCmd.PersistentFlags().BoolVar(&gpAuto, "auto", false,
		"Auto-probe KVN+keyset (requires --dms)")

	// Delete command flags
	gpDeleteCmd.Flags().StringVar(&gpDeleteAIDs, "aids", "",
		"Comma-separated AIDs to delete (hex)")

	// Load command flags
	gpLoadCmd.Flags().StringVar(&gpLoadCAP, "cap", "",
		"Path to CAP file (ZIP format)")
	gpLoadCmd.Flags().StringVar(&gpPackageAID, "package-aid", "",
		"Package (load file) AID (hex)")
	gpLoadCmd.Flags().StringVar(&gpAppletAID, "applet-aid", "",
		"Applet class AID (hex)")
	gpLoadCmd.Flags().StringVar(&gpInstanceAID, "instance-aid", "",
		"Instance AID (hex, defaults to applet-aid)")

	// Verify command flags
	gpVerifyCmd.Flags().StringVar(&gpVerifyAID, "aid", "",
		"AID to verify (hex)")

	// ARAM command flags
	gpAramCmd.Flags().StringVar(&gpAramAID, "aram-aid", "A00000015141434C00",
		"ARA-M applet AID (hex)")
	gpAramCmd.Flags().StringVar(&gpAramRuleAID, "rule-aid", "FFFFFFFFFFFF",
		"Target applet AID for rule (hex), FFFFFFFFFFFF for wildcard")
	gpAramCmd.Flags().StringVar(&gpAramCertHash, "cert-hash", "",
		"Android app certificate hash (SHA-1=20 or SHA-256=32 bytes, hex)")
	gpAramCmd.Flags().StringVar(&gpAramPerm, "perm", "0000000000000001",
		"PERM-AR-DO value (hex, commonly 8 bytes)")

	// Add subcommands
	gpCmd.AddCommand(gpListCmd, gpProbeCmd, gpDeleteCmd, gpLoadCmd, gpAramCmd, gpVerifyCmd)
	rootCmd.AddCommand(gpCmd)
}

// buildGPConfig creates GPConfig from flags
func buildGPConfig(reader *card.Reader) (*sim.GPConfig, error) {
	var encKey, macKey, dekKey []byte
	var err error
	var dmsRow map[string]string

	// Load from DMS file if provided
	if gpDMSFile != "" {
		db, e := sim.LoadDMSKeyDB(gpDMSFile)
		if e != nil {
			return nil, fmt.Errorf("failed to load --dms: %w", e)
		}

		// If ICCID/IMSI not provided, try to read from card
		if gpDMSICCID == "" && gpDMSIMSI == "" {
			cardICCID, iccErr := sim.ReadICCIDQuick(reader)
			if iccErr != nil {
				return nil, fmt.Errorf("when using --dms, provide --dms-iccid/--dms-imsi or ensure ICCID can be read from card: %w", iccErr)
			}
			gpDMSICCID = cardICCID
			printSuccess(fmt.Sprintf("DMS: using ICCID from card: %s", cardICCID))
		} else if gpDMSICCID != "" {
			// Warn if provided ICCID doesn't match card
			if cardICCID, iccErr := sim.ReadICCIDQuick(reader); iccErr == nil && cardICCID != "" && cardICCID != gpDMSICCID {
				printWarning(fmt.Sprintf("DMS: provided ICCID (%s) does not match card ICCID (%s)", gpDMSICCID, cardICCID))
			}
		}

		var row map[string]string
		if gpDMSICCID != "" {
			row, err = db.FindByICCID(gpDMSICCID)
		} else {
			row, err = db.FindByIMSI(gpDMSIMSI)
		}
		if err != nil {
			return nil, fmt.Errorf("DMS row select failed: %w", err)
		}
		dmsRow = row

		// Extract keys if not auto mode
		if !gpAuto && strings.ToLower(strings.TrimSpace(gpDMSKeyset)) != "auto" {
			encKey, macKey, dekKey, err = sim.GPKeysFromDMS(row, gpDMSKeyset)
			if err != nil {
				return nil, fmt.Errorf("failed to extract GP keys from --dms: %w", err)
			}
		}
	}

	// PSK convenience (ENC=MAC)
	if gpKeyPSK != "" {
		psk, e := sim.ParseHexBytes(gpKeyPSK)
		if e != nil {
			return nil, fmt.Errorf("invalid --key-psk: %w", e)
		}
		encKey, macKey = psk, psk
	}

	// Explicit keys override everything
	if gpKeyENC != "" {
		encKey, err = sim.ParseHexBytes(gpKeyENC)
		if err != nil {
			return nil, fmt.Errorf("invalid --key-enc: %w", err)
		}
	}
	if gpKeyMAC != "" {
		macKey, err = sim.ParseHexBytes(gpKeyMAC)
		if err != nil {
			return nil, fmt.Errorf("invalid --key-mac: %w", err)
		}
	}
	if gpKeyDEK != "" {
		dekKey, err = sim.ParseHexBytes(gpKeyDEK)
		if err != nil {
			return nil, fmt.Errorf("invalid --key-dek: %w", err)
		}
	}

	sec, err := sim.ParseGPSecurityLevel(gpSec)
	if err != nil {
		return nil, err
	}

	sdAID, err := sim.ParseAIDHex(gpSDAID)
	if err != nil {
		return nil, fmt.Errorf("invalid --sd-aid: %w", err)
	}

	cfg := &sim.GPConfig{
		KVN:      byte(gpKVN & 0xFF),
		Security: sec,
		StaticKeys: card.GPKeySet{
			ENC: encKey,
			MAC: macKey,
			DEK: dekKey,
		},
		SDAID:     sdAID,
		BlockSize: 200,
	}

	// Auto-probe if requested
	if gpAuto || strings.ToLower(strings.TrimSpace(gpDMSKeyset)) == "auto" {
		if gpDMSFile == "" || dmsRow == nil {
			return nil, fmt.Errorf("GP auto requires --dms with valid ICCID/IMSI")
		}

		printSuccess("GlobalPlatform: auto-probing keyset/KVN...")

		keysets := []string{"cm", "psk40", "psk41", "a", "b", "c", "d", "e", "f", "g", "h"}

		var kvns []int
		kvns = append(kvns, gpKVN)
		for _, v := range []int{0, 1, 2, 3} {
			kvns = append(kvns, v)
		}
		for v := 0x20; v <= 0x2F; v++ {
			kvns = append(kvns, v)
		}
		kvns = append(kvns, 0x40, 0x41, 0xFF)

		// De-dup KVNs
		seenKVN := map[int]bool{}
		var kvnList []int
		for _, v := range kvns {
			if v < 0 || v > 255 || seenKVN[v] {
				continue
			}
			seenKVN[v] = true
			kvnList = append(kvnList, v)
		}

		// SD AID candidates
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
						return nil, fmt.Errorf("failed to generate host challenge: %w", e)
					}
					e = card.ProbeSecureChannelAuto(reader, card.GPKeySet{ENC: enc, MAC: mac, DEK: dek}, byte(kvn), hostChallenge)
					if e == nil {
						cfg.KVN = byte(kvn)
						cfg.SDAID = candSDAID
						cfg.StaticKeys = card.GPKeySet{ENC: enc, MAC: mac, DEK: dek}
						printSuccess(fmt.Sprintf("GP auto matched: keyset=%s kvn=%d sd-aid=%X", ks, kvn, candSDAID))
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
			return nil, fmt.Errorf("GP auto failed: no working keyset/KVN found")
		}
	}

	// Validate keys
	if (len(cfg.StaticKeys.ENC) == 0 || len(cfg.StaticKeys.MAC) == 0) &&
		!gpAuto && strings.ToLower(strings.TrimSpace(gpDMSKeyset)) != "auto" {
		return nil, fmt.Errorf("GP operations require ENC and MAC keys. Use --key-enc/--key-mac, --key-psk, or --dms + --dms-keyset")
	}

	return cfg, nil
}

func runGPList(cmd *cobra.Command, args []string) {
	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	cfg, err := buildGPConfig(reader)
	if err != nil {
		printError(err.Error())
		return
	}

	printSuccess("GlobalPlatform: listing registry via Secure Channel...")
	applets, err := sim.ListAppletsSecure(reader, *cfg)
	if err != nil {
		printError(fmt.Sprintf("GP list failed: %v", err))
		return
	}
	output.PrintApplets(applets)
}

func runGPProbe(cmd *cobra.Command, args []string) {
	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	cfg, err := buildGPConfig(reader)
	if err != nil {
		printError(err.Error())
		return
	}

	printSuccess("GlobalPlatform: probing KVN+keys (INITIALIZE UPDATE + cryptogram verify)...")
	hostChallenge := make([]byte, 8)
	if _, err := rand.Read(hostChallenge); err != nil {
		printError(fmt.Sprintf("Failed to generate host challenge: %v", err))
		return
	}

	if len(cfg.SDAID) > 0 {
		_, _ = reader.Select(cfg.SDAID)
	}

	if err := card.ProbeSecureChannelAuto(reader, cfg.StaticKeys, cfg.KVN, hostChallenge); err != nil {
		printError(fmt.Sprintf("GP probe failed: %v", err))
		return
	}
	printSuccess("GP probe OK: keys/KVN match this card")
}

func runGPDelete(cmd *cobra.Command, args []string) {
	if gpDeleteAIDs == "" {
		printError("--aids is required")
		return
	}

	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	cfg, err := buildGPConfig(reader)
	if err != nil {
		printError(err.Error())
		return
	}

	aids, err := sim.ParseAIDList(gpDeleteAIDs)
	if err != nil {
		printError(fmt.Sprintf("Invalid --aids: %v", err))
		return
	}

	printWarning("GlobalPlatform DELETE is dangerous and may brick the card.")
	if err := sim.DeleteAIDs(reader, *cfg, aids); err != nil {
		printError(fmt.Sprintf("GP delete failed: %v", err))
		return
	}
	printSuccess("GP delete completed")
}

func runGPLoad(cmd *cobra.Command, args []string) {
	if gpLoadCAP == "" {
		printError("--cap is required")
		return
	}
	if gpPackageAID == "" || gpAppletAID == "" {
		printError("--package-aid and --applet-aid are required")
		return
	}

	if err := sim.EnsureFileExists(gpLoadCAP); err != nil {
		printError(fmt.Sprintf("CAP file error: %v", err))
		return
	}

	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	cfg, err := buildGPConfig(reader)
	if err != nil {
		printError(err.Error())
		return
	}

	sdAID, _ := sim.ParseAIDHex(gpSDAID)
	pkgAID, err := sim.ParseAIDHex(gpPackageAID)
	if err != nil {
		printError(fmt.Sprintf("Invalid --package-aid: %v", err))
		return
	}
	appAID, err := sim.ParseAIDHex(gpAppletAID)
	if err != nil {
		printError(fmt.Sprintf("Invalid --applet-aid: %v", err))
		return
	}

	instAID := appAID
	if gpInstanceAID != "" {
		instAID, err = sim.ParseAIDHex(gpInstanceAID)
		if err != nil {
			printError(fmt.Sprintf("Invalid --instance-aid: %v", err))
			return
		}
	}

	printWarning("GlobalPlatform LOAD/INSTALL modifies card content.")
	if err := sim.InstallLoadAndApplet(reader, *cfg, gpLoadCAP, sdAID, pkgAID, appAID, instAID); err != nil {
		printError(fmt.Sprintf("GP load/install failed: %v", err))
		return
	}
	printSuccess("GP load/install completed")
}

func runGPAram(cmd *cobra.Command, args []string) {
	if gpAramCertHash == "" {
		printError("--cert-hash is required")
		return
	}

	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	cfg, err := buildGPConfig(reader)
	if err != nil {
		printError(err.Error())
		return
	}

	aramAID, err := sim.ParseAIDHex(gpAramAID)
	if err != nil {
		printError(fmt.Sprintf("Invalid --aram-aid: %v", err))
		return
	}
	ruleAID, err := sim.ParseHexBytes(gpAramRuleAID)
	if err != nil {
		printError(fmt.Sprintf("Invalid --rule-aid: %v", err))
		return
	}
	certHash, err := sim.ParseHexBytes(gpAramCertHash)
	if err != nil {
		printError(fmt.Sprintf("Invalid --cert-hash: %v", err))
		return
	}
	perm, err := sim.ParseHexBytes(gpAramPerm)
	if err != nil {
		printError(fmt.Sprintf("Invalid --perm: %v", err))
		return
	}

	printWarning("ARA-M STORE DATA modifies access-control rules on the card.")
	err = sim.GPAramAddRule(reader, *cfg, aramAID, sim.GPARAMRule{
		TargetAID: ruleAID,
		CertHash:  certHash,
		Perm:      perm,
		ApduRule:  0x01, // ALWAYS allow
	})
	if err != nil {
		printError(fmt.Sprintf("GP ARA-M add rule failed: %v", err))
		return
	}
	printSuccess("GP ARA-M rule added successfully")
}

func runGPVerify(cmd *cobra.Command, args []string) {
	if gpVerifyAID == "" {
		printError("--aid is required")
		return
	}

	reader, err := connectAndPrepareReader()
	if err != nil {
		printError(err.Error())
		return
	}
	defer reader.Close()

	aid, err := sim.ParseAIDHex(gpVerifyAID)
	if err != nil {
		printError(fmt.Sprintf("Invalid --aid: %v", err))
		return
	}

	sw, err := sim.GPSelectVerify(reader, aid)
	if err != nil {
		printError(fmt.Sprintf("GP SELECT failed: %v", err))
		return
	}
	printSuccess(fmt.Sprintf("GP SELECT SW=%04X (%s)", sw, card.SWToString(sw)))
}

