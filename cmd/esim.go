package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"sim_reader/esim"
	"sim_reader/output"
)

var (
	// esim decode flags
	esimVerbose bool

	// esim validate flags
	esimTemplate string

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
)

var esimCmd = &cobra.Command{
	Use:   "esim",
	Short: "eSIM profile operations",
	Long: `eSIM profile operations: decode, validate, and build profiles.

This command group provides tools for working with eSIM profiles in DER format
(GSMA SGP.22 / SAIP format).

Subcommands:
  decode    - Decode and display profile contents
  validate  - Validate profile structure and parameters
  build     - Build profile from JSON config and template`,
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

Examples:
  sim_reader esim validate profile.der
  sim_reader esim validate profile.der --template base.der`,
	Args: cobra.ExactArgs(1),
	Run:  runEsimValidate,
}

var esimBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build eSIM profile from config",
	Long: `Build eSIM profile from JSON configuration and template.

The configuration file should contain profile parameters like ICCID, IMSI,
Ki, OPc, ISIM settings, etc. A template profile provides the base structure.

Examples:
  sim_reader esim build --config config.json --template base.der -o profile.der
  sim_reader esim build -c config.json -t base.der -o profile.der --applet app.cap`,
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

func init() {
	// esim decode flags
	esimDecodeCmd.Flags().BoolVarP(&esimVerbose, "verbose", "v", false,
		"Show detailed information including raw hex data")

	// esim validate flags
	esimValidateCmd.Flags().StringVarP(&esimTemplate, "template", "t", "",
		"Template profile to compare against (optional)")

	// esim build flags
	esimBuildCmd.Flags().StringVarP(&esimConfig, "config", "c", "",
		"JSON configuration file (required)")
	esimBuildCmd.Flags().StringVarP(&esimBuildTpl, "template", "t", "",
		"Template profile DER file (required)")
	esimBuildCmd.Flags().StringVarP(&esimOutput, "output", "o", "profile.der",
		"Output profile DER file")
	esimBuildCmd.Flags().StringVar(&esimAppletCAP, "applet", "",
		"CAP file to include as PE-Application (optional)")
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

	// Register subcommands
	esimCmd.AddCommand(esimDecodeCmd)
	esimCmd.AddCommand(esimValidateCmd)
	esimCmd.AddCommand(esimBuildCmd)
	esimCmd.AddCommand(esimCompileCmd)
	esimCmd.AddCommand(esimExportCmd)

	// Register esim command to root
	rootCmd.AddCommand(esimCmd)
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

	profile, err := esim.LoadProfile(profilePath)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to load profile: %v", err))
		os.Exit(1)
	}

	result := esim.ValidateProfile(profile, nil)

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
	// Load template
	template, err := esim.LoadProfile(esimBuildTpl)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to load template: %v", err))
		os.Exit(1)
	}

	// Load config
	configData, err := os.ReadFile(esimConfig)
	if err != nil {
		output.PrintError(fmt.Sprintf("Failed to read config: %v", err))
		os.Exit(1)
	}

	var config esim.BuildConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		output.PrintError(fmt.Sprintf("Failed to parse config: %v", err))
		os.Exit(1)
	}

	// Set applet options
	if esimAppletCAP != "" {
		config.AppletCAP = esimAppletCAP
	}
	config.UseAppletAuth = esimAppletAuth

	// Build profile
	result, err := esim.BuildProfile(template, &config)
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
	fmt.Println(p.Summary())

	if verbose {
		fmt.Println("\n=== Detailed Information ===")

		// Show applications/applets
		if len(p.Applications) > 0 {
			fmt.Println("\n--- Java Card Applications (PE-Application) ---")
			for i, app := range p.Applications {
				fmt.Printf("\nApplication[%d]:\n", i)
				if app.LoadBlock != nil {
					fmt.Printf("  LoadBlock:\n")
					fmt.Printf("    PackageAID: %s\n", hex.EncodeToString(app.LoadBlock.LoadPackageAID))
					if len(app.LoadBlock.SecurityDomainAID) > 0 {
						fmt.Printf("    SecurityDomainAID: %s\n", hex.EncodeToString(app.LoadBlock.SecurityDomainAID))
					}
					fmt.Printf("    LoadBlockObject: %d bytes\n", len(app.LoadBlock.LoadBlockObject))
				}
				for j, inst := range app.InstanceList {
					fmt.Printf("  Instance[%d]:\n", j)
					fmt.Printf("    PackageAID: %s\n", hex.EncodeToString(inst.ApplicationLoadPackageAID))
					fmt.Printf("    ClassAID:   %s\n", hex.EncodeToString(inst.ClassAID))
					fmt.Printf("    InstanceAID: %s\n", hex.EncodeToString(inst.InstanceAID))
					fmt.Printf("    LifeCycle: 0x%02X\n", inst.LifeCycleState)
					if len(inst.ProcessData) > 0 {
						fmt.Printf("    ProcessData (%d APDUs):\n", len(inst.ProcessData))
						for k, apdu := range inst.ProcessData {
							apduHex := hex.EncodeToString(apdu)
							if len(apduHex) > 60 {
								apduHex = apduHex[:60] + "..."
							}
							fmt.Printf("      [%d] %s\n", k, apduHex)
						}
					}
				}
			}
		}

		// Show AKA params
		if len(p.AKAParams) > 0 {
			fmt.Println("\n--- AKA Parameters ---")
			for i, aka := range p.AKAParams {
				fmt.Printf("AKA[%d]:\n", i)
				if aka.AlgoConfig != nil {
					fmt.Printf("  Algorithm: %s (ID=%d)\n", p.GetAlgorithmName(), aka.AlgoConfig.AlgorithmID)
					if len(aka.AlgoConfig.Key) > 0 {
						fmt.Printf("  Ki:  %s\n", hex.EncodeToString(aka.AlgoConfig.Key))
					}
					if len(aka.AlgoConfig.OPC) > 0 {
						fmt.Printf("  OPc: %s\n", hex.EncodeToString(aka.AlgoConfig.OPC))
					}
				}
			}
		}

		// Show PIN/PUK
		fmt.Println("\n--- Security Codes ---")
		if pin1 := p.GetPIN1(); pin1 != "" {
			fmt.Printf("  PIN1: %s\n", pin1)
		}
		if puk1 := p.GetPUK1(); puk1 != "" {
			fmt.Printf("  PUK1: %s\n", puk1)
		}
		if adm1 := p.GetADM1(); adm1 != "" {
			fmt.Printf("  ADM1: %s\n", adm1)
		}
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
