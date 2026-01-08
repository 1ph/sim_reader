package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"

	"sim_reader/esim"
	"sim_reader/output"
	"sim_reader/sim"
)

var (
	// esim decode flags
	esimVerbose bool

	// esim validate flags
	esimTemplate       string
	esimValidateStrict bool
	esimCheckLengths   bool

	// esim build flags
	esimConfig     string
	esimBuildTpl   string
	esimOutput     string
	esimAppletCAP  string
	esimAppletAuth bool

	// esim compile flags
	esimCompileOutput string

	// esim export flags
	esimExportOutput string

	// esim card flags
	esimCardICCID string

	// esim download flags
	esimSMDPURL        string
	esimMatchingID     string
	esimActivationCode string
	esimInsecure       bool
)

var esimCmd = &cobra.Command{
	Use:   "esim",
	Short: "eSIM profile operations",
	Long: `eSIM profile operations: decode, validate, build, compile and export profiles.

This command group provides tools for working with eSIM profiles in DER format
(GSMA SGP.22 / SAIP format) and ASN.1 Value Notation text format.`,
}

var esimDecodeCmd = &cobra.Command{
	Use:   "decode <profile.der>",
	Short: "Decode and display eSIM profile",
	Long: `Decode eSIM profile from DER file and display its contents.

Examples:
  sim_reader esim decode profile.der
  sim_reader esim decode profile.der --verbose
  sim_reader esim decode profile.der --json`,
	Args: cobra.ExactArgs(1),
	Run:  runEsimDecode,
}

var esimValidateCmd = &cobra.Command{
	Use:   "validate <profile.der>",
	Short: "Validate eSIM profile",
	Long: `Validate eSIM profile structure and parameters.

Checks performed:
  - Required elements: Header, MF, End
  - ICCID: format and Luhn checksum
  - IMSI: format and length
  - AKA parameters: Ki/OPc presence and length
  - PIN/PUK: format and length
  - Applications: AID validity, LoadBlock/InstanceList
  - Personalization: APDU format

Template comparison (with --template):
  - Element presence and order
  - EF file sizes (with --check-lengths)
  - Missing/extra elements

Examples:
  sim_reader esim validate profile.der
  sim_reader esim validate profile.der --template base.der
  sim_reader esim validate profile.der --template base.der --strict --check-lengths`,
	Args: cobra.ExactArgs(1),
	Run:  runEsimValidate,
}

var esimBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build eSIM profile from config",
	Long: `Build eSIM profile from JSON configuration and template.

The configuration file (JSON) contains profile parameters: ICCID, IMSI, Ki, OPc,
ISIM settings, PIN/PUK codes, and optional applet configuration.

Template can be either:
  - DER binary file (.der)
  - ASN.1 Value Notation text file (.txt, .asn1)

Applets can be included via:
  - JSON config: global_platform.applets section with use_for_esim: true
  - CLI flag: --applet <cap_file> (requires AID config in JSON)

Examples:
  sim_reader esim build --config config.json --template base.der -o profile.der
  sim_reader esim build -c config.json -t template.txt -o profile.der
  sim_reader esim build -c config.json -t base.der --use-applet-auth -o profile.der`,
	Run: runEsimBuild,
}

var esimCompileCmd = &cobra.Command{
	Use:   "compile <profile.txt>",
	Short: "Compile ASN.1 Value Notation text to DER",
	Long: `Compile eSIM profile from ASN.1 Value Notation text format to binary DER.

This command parses text files in ASN.1 Value Notation format (like TS48 GTP
profiles) and compiles them into binary DER format suitable for eSIM provisioning.

Examples:
  sim_reader esim compile profile.txt -o profile.der
  sim_reader esim compile "TS48 V7.0 eSIM_GTP_SAIP2.3_BERTLV_SUCI.txt" -o gtp.der`,
	Args: cobra.ExactArgs(1),
	Run:  runEsimCompile,
}

var esimExportCmd = &cobra.Command{
	Use:   "export <profile.der>",
	Short: "Export DER profile to ASN.1 Value Notation text",
	Long: `Export eSIM profile from binary DER format to ASN.1 Value Notation text.

This command reads a DER profile and generates a human-readable text file
in ASN.1 Value Notation format, which can be edited and recompiled.

Examples:
  sim_reader esim export profile.der -o profile.txt
  sim_reader esim export profile.der  # prints to stdout`,
	Args: cobra.ExactArgs(1),
	Run:  runEsimExport,
}

var esimCardCmd = &cobra.Command{
	Use:   "card",
	Short: "eUICC card management operations",
}

var esimCardListCmd = &cobra.Command{
	Use:   "list",
	Short: "List profiles on eUICC",
	Run:   runEsimCardList,
}

var esimCardEnableCmd = &cobra.Command{
	Use:   "enable <iccid>",
	Short: "Enable profile on eUICC",
	Args:  cobra.ExactArgs(1),
	Run:   runEsimCardEnable,
}

var esimCardDisableCmd = &cobra.Command{
	Use:   "disable <iccid>",
	Short: "Disable profile on eUICC",
	Args:  cobra.ExactArgs(1),
	Run:   runEsimCardDisable,
}

var esimCardDeleteCmd = &cobra.Command{
	Use:   "delete <iccid>",
	Short: "Delete profile from eUICC",
	Args:  cobra.ExactArgs(1),
	Run:   runEsimCardDelete,
}

var esimDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download profile from SM-DP+",
	Long: `Download profile from SM-DP+ server.

Using activation code:
  sim_reader esim download -s '1$SMDP_ADDRESS$MATCHING_ID'
  Example: sim_reader esim download -s '1$testsmdpplus1.example.com$variantnats3g'

Using separate flags:
  sim_reader esim download --smdp testsmdpplus1.example.com --matching-id variantnats3g`,
	Run: runEsimDownload,
}

var esimInstallCmd = &cobra.Command{
	Use:   "install <file.bpp>",
	Short: "Install profile from BPP file",
	Args:  cobra.ExactArgs(1),
	Run:   runEsimInstall,
}

func init() {
	// esim decode flags
	esimDecodeCmd.Flags().BoolVarP(&esimVerbose, "verbose", "v", false,
		"Show detailed information including raw hex data")

	// esim validate flags
	esimValidateCmd.Flags().StringVarP(&esimTemplate, "template", "t", "",
		"Template profile to compare against (DER or ASN.1 text)")
	esimValidateCmd.Flags().BoolVar(&esimValidateStrict, "strict", false,
		"Require exact match with template (errors instead of warnings)")
	esimValidateCmd.Flags().BoolVar(&esimCheckLengths, "check-lengths", false,
		"Check EF file sizes match template")

	// esim build flags
	esimBuildCmd.Flags().StringVarP(&esimConfig, "config", "c", "",
		"JSON configuration file (required)")
	esimBuildCmd.Flags().StringVarP(&esimBuildTpl, "template", "t", "",
		"Template profile file - DER (.der) or ASN.1 text (.txt, .asn1) (required)")
	esimBuildCmd.Flags().StringVarP(&esimOutput, "output", "o", "profile.der",
		"Output profile DER file")
	esimBuildCmd.Flags().StringVar(&esimAppletCAP, "applet", "",
		"CAP file to include as PE-Application (requires AID config in JSON)")
	esimBuildCmd.Flags().BoolVar(&esimAppletAuth, "use-applet-auth", false,
		"Delegate authentication to applet (algorithmID=3)")

	_ = esimBuildCmd.MarkFlagRequired("config")
	_ = esimBuildCmd.MarkFlagRequired("template")

	// esim compile flags
	esimCompileCmd.Flags().StringVarP(&esimCompileOutput, "output", "o", "",
		"Output DER file (required)")
	_ = esimCompileCmd.MarkFlagRequired("output")

	// esim export flags
	esimExportCmd.Flags().StringVarP(&esimExportOutput, "output", "o", "",
		"Output TXT file (prints to stdout if not specified)")

	// esim card flags
	esimCardCmd.AddCommand(esimCardListCmd)
	esimCardCmd.AddCommand(esimCardEnableCmd)
	esimCardCmd.AddCommand(esimCardDisableCmd)
	esimCardCmd.AddCommand(esimCardDeleteCmd)

	// esim download flags
	esimDownloadCmd.Flags().StringVarP(&esimActivationCode, "activation-code", "s", "", "Activation code (format: 1$SMDP$MATCHING_ID)")
	esimDownloadCmd.Flags().StringVar(&esimSMDPURL, "smdp", "", "SM-DP+ server URL")
	esimDownloadCmd.Flags().StringVar(&esimMatchingID, "matching-id", "", "Matching ID")
	esimDownloadCmd.Flags().StringVarP(&esimOutput, "output", "o", "", "Output BPP file (if specified, profile will not be installed)")
	esimDownloadCmd.Flags().BoolVarP(&esimInsecure, "insecure", "k", false, "Skip TLS certificate verification (for testing)")

	// Register subcommands
	esimCmd.AddCommand(esimDecodeCmd)
	esimCmd.AddCommand(esimValidateCmd)
	esimCmd.AddCommand(esimBuildCmd)
	esimCmd.AddCommand(esimCompileCmd)
	esimCmd.AddCommand(esimExportCmd)
	esimCmd.AddCommand(esimCardCmd)
	esimCmd.AddCommand(esimDownloadCmd)
	esimCmd.AddCommand(esimInstallCmd)

	// Register esim command to root
	rootCmd.AddCommand(esimCmd)
}

func runEsimCardList(cmd *cobra.Command, args []string) {
	reader, err := connectAndPrepareReader()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer reader.Close()

	euicc := esim.NewEUICC(reader)
	if err := euicc.Init(); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer euicc.Close()

	profiles, err := euicc.ListProfiles()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	if outputJSON {
		data, _ := json.MarshalIndent(profiles, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Print table using output package style
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.Style().Color.Header = text.Colors{text.FgCyan, text.Bold}
	t.Style().Color.Row = text.Colors{text.FgWhite}
	t.Style().Color.RowAlternate = text.Colors{text.FgHiWhite}
	t.Style().Options.SeparateRows = false

	t.SetTitle("eUICC PROFILES")
	t.AppendHeader(table.Row{"ICCID", "State", "Nickname", "Provider", "Profile Name", "Profile Class"})

	for _, p := range profiles {
		nickname := p.Nickname
		if nickname == "" {
			nickname = "-"
		}
		profileName := p.ProfileName
		if profileName == "" {
			profileName = "-"
		}

		// Color state
		stateColor := text.FgYellow
		if p.State == "enabled" {
			stateColor = text.FgGreen
		}

		t.AppendRow(table.Row{
			p.ICCID,
			text.Colors{stateColor}.Sprint(p.State),
			nickname,
			p.ServiceProvider,
			profileName,
			p.ProfileClass,
		})
	}

	fmt.Println()
	t.Render()
	fmt.Println()
}

func runEsimCardEnable(cmd *cobra.Command, args []string) {
	iccid := args[0]
	reader, err := connectAndPrepareReader()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer reader.Close()

	euicc := esim.NewEUICC(reader)
	if err := euicc.Init(); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer euicc.Close()

	if err := euicc.EnableProfile(iccid); err != nil {
		output.PrintError(fmt.Sprintf("Failed to enable profile: %v", err))
		os.Exit(1)
	}
	output.PrintSuccess("Profile enabled successfully")
}

func runEsimCardDisable(cmd *cobra.Command, args []string) {
	iccid := args[0]
	reader, err := connectAndPrepareReader()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer reader.Close()

	euicc := esim.NewEUICC(reader)
	if err := euicc.Init(); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer euicc.Close()

	if err := euicc.DisableProfile(iccid); err != nil {
		output.PrintError(fmt.Sprintf("Failed to disable profile: %v", err))
		os.Exit(1)
	}
	output.PrintSuccess("Profile disabled successfully")
}

func runEsimCardDelete(cmd *cobra.Command, args []string) {
	iccid := args[0]
	reader, err := connectAndPrepareReader()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer reader.Close()

	euicc := esim.NewEUICC(reader)
	if err := euicc.Init(); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer euicc.Close()

	if err := euicc.DeleteProfile(iccid); err != nil {
		output.PrintError(fmt.Sprintf("Failed to delete profile: %v", err))
		os.Exit(1)
	}
	output.PrintSuccess("Profile deleted successfully")
}

func runEsimDownload(cmd *cobra.Command, args []string) {
	// Parse activation code or use flags
	smdpURL := esimSMDPURL
	matchingID := esimMatchingID

	activationCode := esimActivationCode

	// If no -a flag, check positional argument
	if activationCode == "" && len(args) == 1 {
		activationCode = args[0]
	}

	if activationCode != "" {
		// Parse activation code: 1$SMDP_ADDRESS$MATCHING_ID[OID]
		parts := strings.Split(activationCode, "$")

		if len(parts) < 3 {
			output.PrintError("Invalid activation code format. Expected: 1$SMDP_ADDRESS$MATCHING_ID")
			os.Exit(1)
		}

		if parts[0] != "1" {
			output.PrintError(fmt.Sprintf("Unsupported activation code version: %s (expected: 1)", parts[0]))
			os.Exit(1)
		}

		smdpURL = parts[1]
		matchingID = parts[2]

		// Optional: parts[3] could be OID for IMEI check, but we ignore it for now
	} else {
		// Use flags
		if smdpURL == "" || matchingID == "" {
			output.PrintError("Either provide activation code (-s) or use --smdp and --matching-id flags")
			os.Exit(1)
		}
	}

	// Add https:// prefix if not present
	if !strings.HasPrefix(smdpURL, "http://") && !strings.HasPrefix(smdpURL, "https://") {
		smdpURL = "https://" + smdpURL
	}

	reader, err := connectAndPrepareReader()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer reader.Close()

	euicc := esim.NewEUICC(reader)
	if err := euicc.Init(); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer euicc.Close()

	smdp := esim.NewSMDPClient(smdpURL, esimInsecure)
	lpa := esim.NewLPA(euicc, smdp)

	// smdpAddress for ES9+ should be without protocol (just hostname)
	smdpAddress := strings.TrimPrefix(smdpURL, "https://")
	smdpAddress = strings.TrimPrefix(smdpAddress, "http://")

	if esimOutput != "" {
		if err := lpa.DownloadProfileToFile(smdpAddress, matchingID, esimOutput); err != nil {
			output.PrintError(fmt.Sprintf("Download failed: %v", err))
			os.Exit(1)
		}
		output.PrintSuccess(fmt.Sprintf("Profile downloaded and saved to %s", esimOutput))
	} else {
		if err := lpa.DownloadProfile(smdpAddress, matchingID); err != nil {
			output.PrintError(fmt.Sprintf("Download and installation failed: %v", err))
			os.Exit(1)
		}
		output.PrintSuccess("Profile downloaded and installed successfully")
	}
}

func runEsimInstall(cmd *cobra.Command, args []string) {
	filename := args[0]
	reader, err := connectAndPrepareReader()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer reader.Close()

	euicc := esim.NewEUICC(reader)
	if err := euicc.Init(); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	defer euicc.Close()

	lpa := esim.NewLPA(euicc, nil)
	if err := lpa.InstallProfileFromFile(filename); err != nil {
		output.PrintError(fmt.Sprintf("Installation failed: %v", err))
		os.Exit(1)
	}
	output.PrintSuccess("Profile installed successfully from file")
}

func runEsimDecode(cmd *cobra.Command, args []string) {
	profilePath := args[0]

	profile, err := esim.LoadProfile(profilePath)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to load profile: %v", err))
		os.Exit(1)
	}

	if outputJSON {
		printProfileJSON(profile)
		return
	}

	printProfileSummary(profile, esimVerbose)
}

func runEsimValidate(cmd *cobra.Command, args []string) {
	profilePath := args[0]

	// Load profile (auto-detect format)
	profile, err := esim.LoadTemplate(profilePath)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to load profile: %v", err))
		os.Exit(1)
	}

	// Prepare validation options
	opts := &esim.ValidationOptions{
		TemplateStrict:    esimValidateStrict,
		CheckFieldLengths: esimCheckLengths,
	}

	// Load template if specified
	if esimTemplate != "" {
		template, err := esim.LoadTemplate(esimTemplate)
		if err != nil {
			output.PrintError(fmt.Sprintf("Failed to load template: %v", err))
			os.Exit(1)
		}
		opts.Template = template
	}

	result := esim.ValidateProfile(profile, opts)

	if outputJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	printValidationResult(result)

	if !result.Valid {
		os.Exit(1)
	}
}

func runEsimBuild(cmd *cobra.Command, args []string) {
	// Load template (auto-detect format: DER or ASN.1 text)
	template, err := esim.LoadTemplate(esimBuildTpl)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to load template: %v", err))
		os.Exit(1)
	}

	// Load config using sim.SIMConfig
	config, err := sim.LoadConfig(esimConfig)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to load config: %v", err))
		os.Exit(1)
	}

	// Apply CLI overrides
	if esimAppletAuth {
		config.UseAppletAuth = true
	}

	// Handle --applet flag: CLI takes priority over config file
	if esimAppletCAP != "" {
		if config.GlobalPlatform == nil {
			config.GlobalPlatform = &sim.GlobalPlatformConfig{}
		}
		if config.GlobalPlatform.Applets == nil {
			config.GlobalPlatform.Applets = &sim.GPAppletsConfig{}
		}

		// CLI --applet takes priority: override CAPPath in existing applet config
		foundApplet := false

		// First, try to find an applet with UseForESIM=true
		for i := range config.GlobalPlatform.Applets.Loads {
			if config.GlobalPlatform.Applets.Loads[i].UseForESIM {
				config.GlobalPlatform.Applets.Loads[i].CAPPath = esimAppletCAP
				foundApplet = true
				break
			}
		}

		// If no UseForESIM applet, use the first one available
		if !foundApplet && len(config.GlobalPlatform.Applets.Loads) > 0 {
			config.GlobalPlatform.Applets.Loads[0].CAPPath = esimAppletCAP
			config.GlobalPlatform.Applets.Loads[0].UseForESIM = true
			foundApplet = true
		}

		// If no existing applet config, we need AID info from JSON
		if !foundApplet {
			output.PrintWarning("--applet specified but no applet AID configuration in JSON config")
			output.PrintWarning("Add global_platform.applets.loads section with package_aid, applet_aid, instance_aid")
		}
	}

	// Build profile using SIMConfig
	result, err := esim.BuildProfileFromSIMConfig(template, config)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to build profile: %v", err))
		os.Exit(1)
	}

	// Save
	if err := esim.SaveProfile(result, esimOutput); err != nil {
		output.PrintError(fmt.Sprintf("Failed to save profile: %v", err))
		os.Exit(1)
	}

	output.PrintSuccess(fmt.Sprintf("Profile saved to: %s", esimOutput))
	output.PrintSuccess(fmt.Sprintf("ICCID: %s", result.GetICCID()))
	output.PrintSuccess(fmt.Sprintf("IMSI: %s", result.GetIMSI()))

	// Show applet info if any
	if len(result.Applications) > 0 {
		output.PrintSuccess(fmt.Sprintf("Applets: %d", len(result.Applications)))
	}
}

func runEsimCompile(cmd *cobra.Command, args []string) {
	txtPath := args[0]

	// Parse ASN.1 Value Notation text file
	profile, err := esim.ParseValueNotationFile(txtPath)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to parse text file: %v", err))
		os.Exit(1)
	}

	// Validate parsed profile
	result := esim.ValidateProfile(profile, nil)
	if !result.Valid {
		output.PrintWarning("Profile has validation issues:")
		for _, e := range result.Errors {
			fmt.Printf("  - %s: %s\n", e.Field, e.Message)
		}
	}

	// Save to DER
	if err := esim.SaveProfile(profile, esimCompileOutput); err != nil {
		output.PrintError(fmt.Sprintf("Failed to save DER profile: %v", err))
		os.Exit(1)
	}

	output.PrintSuccess(fmt.Sprintf("Compiled profile saved to: %s", esimCompileOutput))
	output.PrintSuccess(fmt.Sprintf("ICCID: %s", profile.GetICCID()))
	output.PrintSuccess(fmt.Sprintf("IMSI: %s", profile.GetIMSI()))
	output.PrintSuccess(fmt.Sprintf("Elements: %d", len(profile.Elements)))
}

func runEsimExport(cmd *cobra.Command, args []string) {
	derPath := args[0]

	// Load DER profile
	profile, err := esim.LoadProfile(derPath)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to load profile: %v", err))
		os.Exit(1)
	}

	// Generate ASN.1 Value Notation text
	text := esim.GenerateValueNotation(profile)

	if esimExportOutput == "" {
		// Print to stdout
		fmt.Print(text)
	} else {
		// Save to file
		if err := os.WriteFile(esimExportOutput, []byte(text), 0644); err != nil {
			output.PrintError(fmt.Sprintf("Failed to save text file: %v", err))
			os.Exit(1)
		}
		output.PrintSuccess(fmt.Sprintf("Exported to: %s", esimExportOutput))
		output.PrintSuccess(fmt.Sprintf("ICCID: %s", profile.GetICCID()))
		output.PrintSuccess(fmt.Sprintf("Elements: %d", len(profile.Elements)))
	}
}

func printProfileSummary(p *esim.Profile, verbose bool) {
	if verbose {
		fmt.Println(esim.DetailedReport(p))
	} else {
		fmt.Println(p.Summary())
	}
}

func printProfileJSON(p *esim.Profile) {
	// Create a simplified JSON representation
	data := map[string]interface{}{
		"version": map[string]int{
			"major": p.Header.MajorVersion,
			"minor": p.Header.MinorVersion,
		},
		"profileType":  p.GetProfileType(),
		"iccid":        p.GetICCID(),
		"imsi":         p.GetIMSI(),
		"algorithm":    p.GetAlgorithmName(),
		"hasUSIM":      p.HasUSIM(),
		"hasISIM":      p.HasISIM(),
		"hasCSIM":      p.HasCSIM(),
		"elementCount": len(p.Elements),
	}

	if ki := p.GetKi(); len(ki) > 0 {
		data["ki"] = hex.EncodeToString(ki)
	}
	if opc := p.GetOPC(); len(opc) > 0 {
		data["opc"] = hex.EncodeToString(opc)
	}

	// Applications
	if len(p.Applications) > 0 {
		apps := make([]map[string]interface{}, 0)
		for _, app := range p.Applications {
			appData := map[string]interface{}{}
			if app.LoadBlock != nil {
				appData["packageAID"] = hex.EncodeToString(app.LoadBlock.LoadPackageAID)
				appData["loadBlockSize"] = len(app.LoadBlock.LoadBlockObject)
			}
			instances := make([]map[string]interface{}, 0)
			for _, inst := range app.InstanceList {
				instData := map[string]interface{}{
					"instanceAID":    hex.EncodeToString(inst.InstanceAID),
					"classAID":       hex.EncodeToString(inst.ClassAID),
					"lifeCycleState": inst.LifeCycleState,
					"processDataLen": len(inst.ProcessData),
				}
				instances = append(instances, instData)
			}
			appData["instances"] = instances
			apps = append(apps, appData)
		}
		data["applications"] = apps
	}

	// Elements list
	elements := make([]string, 0)
	for _, elem := range p.Elements {
		elements = append(elements, esim.GetProfileElementName(elem.Tag))
	}
	data["elements"] = elements

	jsonData, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(jsonData))
}

func printValidationResult(r *esim.ValidationResult) {
	if r.Valid {
		output.PrintSuccess("Profile validation: PASSED")
	} else {
		output.PrintError("Profile validation: FAILED")
	}

	fmt.Println()

	for _, check := range r.Checks {
		status := "✓"
		if !check.Passed {
			status = "✗"
		}
		fmt.Printf("%s %s: %s\n", status, check.Name, check.Message)
	}

	if len(r.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, e := range r.Errors {
			fmt.Printf("  - %s: %s\n", e.Field, e.Message)
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range r.Warnings {
			fmt.Printf("  - %s: %s\n", w.Field, w.Message)
		}
	}
}

// luhnChecksum calculates Luhn checksum for ICCID validation
func luhnChecksum(s string) bool {
	if len(s) < 2 {
		return false
	}

	// Remove non-digits
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}

	if len(digits) < 2 {
		return false
	}

	// Luhn algorithm
	sum := 0
	isSecond := false

	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if isSecond {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		isSecond = !isSecond
	}

	return sum%10 == 0
}

// isValidAID checks if AID has valid format
func isValidAID(aid []byte) bool {
	// AID should be 5-16 bytes
	return len(aid) >= 5 && len(aid) <= 16
}

// isValidAPDU checks if APDU has valid format
func isValidAPDU(apdu []byte) bool {
	// Minimum APDU: CLA INS P1 P2 = 4 bytes
	if len(apdu) < 4 {
		return false
	}
	// Check Lc if present
	if len(apdu) > 4 {
		lc := int(apdu[4])
		// Case 3: CLA INS P1 P2 Lc Data
		if len(apdu) == 5+lc || len(apdu) == 5+lc+1 { // +1 for Le
			return true
		}
		// Case 1 or 2: just header or header + Le
		if len(apdu) == 4 || len(apdu) == 5 {
			return true
		}
		return false
	}
	return true
}

// formatAID formats AID for display
func formatAID(aid []byte) string {
	if len(aid) == 0 {
		return "(empty)"
	}
	return strings.ToUpper(hex.EncodeToString(aid))
}
