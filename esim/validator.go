package esim

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ValidationResult represents the result of profile validation
type ValidationResult struct {
	Valid    bool              `json:"valid"`
	Checks   []ValidationCheck `json:"checks"`
	Errors   []ValidationError `json:"errors,omitempty"`
	Warnings []ValidationWarning `json:"warnings,omitempty"`
}

// ValidationCheck represents a single validation check
type ValidationCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationOptions configures validation behavior
type ValidationOptions struct {
	Template          *Profile // Optional template to compare against
	SkipLuhn          bool     // Skip ICCID Luhn checksum validation
	AllowEmptyPIN     bool     // Allow empty PIN values
	StrictApplet      bool     // Require all applet instances to have valid ProcessData
	TemplateStrict    bool     // Require exact match with template structure
	CheckFieldLengths bool     // Check EF file sizes match template
}

// ValidateProfile validates eSIM profile structure and parameters
func ValidateProfile(p *Profile, opts *ValidationOptions) *ValidationResult {
	if opts == nil {
		opts = &ValidationOptions{}
	}

	result := &ValidationResult{
		Valid:    true,
		Checks:   make([]ValidationCheck, 0),
		Errors:   make([]ValidationError, 0),
		Warnings: make([]ValidationWarning, 0),
	}

	// Required elements
	validateRequiredElements(p, result)

	// Header validation
	validateHeader(p, result, opts)

	// ICCID validation
	validateICCID(p, result, opts)

	// IMSI validation
	validateIMSI(p, result)

	// AKA parameters
	validateAKA(p, result)

	// PIN/PUK validation
	validatePINPUK(p, result, opts)

	// Applications (Java Card applets)
	validateApplications(p, result, opts)

	// Security Domains
	validateSecurityDomains(p, result)

	// EF file sizes vs actual content
	validateEFContentSizes(p, result)

	// Template comparison (if provided)
	if opts.Template != nil {
		validateAgainstTemplateWithOpts(p, opts.Template, result, opts)
	}

	// Update Valid flag based on errors
	result.Valid = len(result.Errors) == 0

	return result
}

func addCheck(r *ValidationResult, name string, passed bool, message string) {
	r.Checks = append(r.Checks, ValidationCheck{
		Name:    name,
		Passed:  passed,
		Message: message,
	})
}

func addError(r *ValidationResult, field, message string) {
	r.Errors = append(r.Errors, ValidationError{
		Field:   field,
		Message: message,
	})
}

func addWarning(r *ValidationResult, field, message string) {
	r.Warnings = append(r.Warnings, ValidationWarning{
		Field:   field,
		Message: message,
	})
}

func validateRequiredElements(p *Profile, r *ValidationResult) {
	// Check Header
	if p.Header == nil {
		addCheck(r, "ProfileHeader", false, "Missing required ProfileHeader")
		addError(r, "Header", "ProfileHeader element is required")
	} else {
		addCheck(r, "ProfileHeader", true, fmt.Sprintf("v%d.%d", p.Header.MajorVersion, p.Header.MinorVersion))
	}

	// Check MF
	if p.MF == nil {
		addCheck(r, "MasterFile", false, "Missing required MasterFile")
		addError(r, "MF", "MasterFile element is required")
	} else {
		addCheck(r, "MasterFile", true, "Present")
	}

	// Check End
	if p.End == nil {
		addCheck(r, "ProfileEnd", false, "Missing required End element")
		addError(r, "End", "End element is required")
	} else {
		addCheck(r, "ProfileEnd", true, "Present")
	}

	// Check for at least one SIM application
	hasApp := p.HasUSIM() || p.HasISIM() || p.HasCSIM()
	if !hasApp {
		addWarning(r, "Applications", "No SIM application (USIM/ISIM/CSIM) found in profile")
	}
}

func validateHeader(p *Profile, r *ValidationResult, opts *ValidationOptions) {
	if p.Header == nil {
		return
	}

	// Version check
	if p.Header.MajorVersion < 2 {
		addWarning(r, "Version", fmt.Sprintf("Old profile version %d.%d, recommend 2.x or higher",
			p.Header.MajorVersion, p.Header.MinorVersion))
	}

	// Profile type
	if p.Header.ProfileType == "" {
		addWarning(r, "ProfileType", "ProfileType is empty")
	}
}

func validateICCID(p *Profile, r *ValidationResult, opts *ValidationOptions) {
	iccid := p.GetICCID()
	
	if iccid == "" {
		addCheck(r, "ICCID", false, "ICCID is missing")
		addError(r, "ICCID", "ICCID is required")
		return
	}

	// Check length (18-20 digits)
	if len(iccid) < 18 || len(iccid) > 20 {
		addCheck(r, "ICCID", false, fmt.Sprintf("%s (invalid length: %d)", iccid, len(iccid)))
		addError(r, "ICCID", fmt.Sprintf("ICCID length must be 18-20 digits, got %d", len(iccid)))
		return
	}

	// Check format (all digits)
	for _, c := range iccid {
		if c < '0' || c > '9' {
			addCheck(r, "ICCID", false, fmt.Sprintf("%s (invalid characters)", iccid))
			addError(r, "ICCID", "ICCID must contain only digits")
			return
		}
	}

	// Luhn checksum
	if !opts.SkipLuhn {
		if !luhnCheck(iccid) {
			addCheck(r, "ICCID", false, fmt.Sprintf("%s (Luhn checksum failed)", iccid))
			addWarning(r, "ICCID", "ICCID Luhn checksum validation failed")
		} else {
			addCheck(r, "ICCID", true, fmt.Sprintf("%s (Luhn OK)", iccid))
		}
	} else {
		addCheck(r, "ICCID", true, iccid)
	}
}

func validateIMSI(p *Profile, r *ValidationResult) {
	imsi := p.GetIMSI()
	
	if imsi == "" {
		if p.HasUSIM() {
			addCheck(r, "IMSI", false, "IMSI is missing but USIM is present")
			addError(r, "IMSI", "IMSI is required when USIM is present")
		} else {
			addCheck(r, "IMSI", true, "Not applicable (no USIM)")
		}
		return
	}

	// Check length (15 digits)
	if len(imsi) != 15 {
		addCheck(r, "IMSI", false, fmt.Sprintf("%s (invalid length: %d)", imsi, len(imsi)))
		addError(r, "IMSI", fmt.Sprintf("IMSI must be 15 digits, got %d", len(imsi)))
		return
	}

	// Check format (all digits)
	for _, c := range imsi {
		if c < '0' || c > '9' {
			addCheck(r, "IMSI", false, fmt.Sprintf("%s (invalid characters)", imsi))
			addError(r, "IMSI", "IMSI must contain only digits")
			return
		}
	}

	addCheck(r, "IMSI", true, imsi)
}

func validateAKA(p *Profile, r *ValidationResult) {
	if len(p.AKAParams) == 0 {
		addCheck(r, "AKA", false, "No AKA parameters found")
		addError(r, "AKA", "At least one AKA parameter element is required")
		return
	}

	aka := p.AKAParams[0]
	if aka.AlgoConfig == nil {
		addCheck(r, "AKA", false, "AKA algorithm configuration is missing")
		addError(r, "AKA", "Algorithm configuration is required")
		return
	}

	// Algorithm ID
	algoName := p.GetAlgorithmName()
	
	// Ki validation
	ki := aka.AlgoConfig.Key
	if len(ki) == 0 {
		addCheck(r, "AKA", false, fmt.Sprintf("%s, Ki missing", algoName))
		addError(r, "Ki", "Ki key is required")
		return
	}

	// Ki length (16 or 32 bytes)
	if len(ki) != 16 && len(ki) != 32 {
		addCheck(r, "AKA", false, fmt.Sprintf("%s, Ki invalid length: %d", algoName, len(ki)))
		addError(r, "Ki", fmt.Sprintf("Ki must be 16 or 32 bytes, got %d", len(ki)))
		return
	}

	// OPc validation (optional but recommended for Milenage/TUAK)
	opc := aka.AlgoConfig.OPC
	if aka.AlgoConfig.AlgorithmID == AlgoMilenage || aka.AlgoConfig.AlgorithmID == AlgoTUAK {
		if len(opc) == 0 {
			addWarning(r, "OPc", "OPc is not set, may be required for Milenage/TUAK")
		} else if len(opc) != 16 && len(opc) != 32 {
			addCheck(r, "AKA", false, fmt.Sprintf("%s, OPc invalid length: %d", algoName, len(opc)))
			addError(r, "OPc", fmt.Sprintf("OPc must be 16 or 32 bytes, got %d", len(opc)))
			return
		}
	}

	addCheck(r, "AKA", true, fmt.Sprintf("%s, Ki/OPc present", algoName))
}

func validatePINPUK(p *Profile, r *ValidationResult, opts *ValidationOptions) {
	// PIN1
	pin1 := p.GetPIN1()
	if pin1 == "" && !opts.AllowEmptyPIN {
		addWarning(r, "PIN1", "PIN1 is not set")
	} else if len(pin1) > 0 && (len(pin1) < 4 || len(pin1) > 8) {
		addCheck(r, "PIN/PUK", false, fmt.Sprintf("PIN1 length invalid: %d", len(pin1)))
		addError(r, "PIN1", fmt.Sprintf("PIN1 must be 4-8 digits, got %d", len(pin1)))
		return
	}

	// PUK1
	puk1 := p.GetPUK1()
	if puk1 == "" {
		addWarning(r, "PUK1", "PUK1 is not set")
	} else if len(puk1) != 8 {
		addCheck(r, "PIN/PUK", false, fmt.Sprintf("PUK1 length invalid: %d", len(puk1)))
		addError(r, "PUK1", fmt.Sprintf("PUK1 must be 8 digits, got %d", len(puk1)))
		return
	}

	addCheck(r, "PIN/PUK", true, "PIN/PUK codes valid")
}

func validateApplications(p *Profile, r *ValidationResult, opts *ValidationOptions) {
	if len(p.Applications) == 0 {
		addCheck(r, "Applications", true, "No PE-Application elements (normal for profiles without applets)")
		return
	}

	for i, app := range p.Applications {
		appName := fmt.Sprintf("Application[%d]", i)
		
		// Check LoadBlock
		if app.LoadBlock != nil {
			if len(app.LoadBlock.LoadPackageAID) == 0 {
				addError(r, appName, "LoadBlock.LoadPackageAID is empty")
			} else if !isValidAID(app.LoadBlock.LoadPackageAID) {
				addError(r, appName, fmt.Sprintf("LoadBlock.LoadPackageAID invalid: %s",
					hex.EncodeToString(app.LoadBlock.LoadPackageAID)))
			}
			
			if len(app.LoadBlock.LoadBlockObject) == 0 {
				addError(r, appName, "LoadBlock.LoadBlockObject (CAP file) is empty")
			} else {
				// CRITICAL: Check LoadBlockObject format
				// eUICC requires IJC format, not raw CAP/ZIP
				format := GetLoadBlockFormat(app.LoadBlock.LoadBlockObject)
				if format == "CAP/ZIP" {
					addError(r, appName+".LoadBlockObject",
						"LoadBlockObject is in CAP/ZIP format (starts with 504B) - eUICC requires IJC format. "+
							"Use ConvertCAPToIJC() to convert before embedding.")
				} else if format == "unknown" {
					addWarning(r, appName+".LoadBlockObject",
						fmt.Sprintf("LoadBlockObject format unrecognized (starts with %s). Expected IJC format.",
							hex.EncodeToString(app.LoadBlock.LoadBlockObject[:min(4, len(app.LoadBlock.LoadBlockObject))])))
				}
			}
			
			// Check memory limits - required for eUICC resource allocation
			if len(app.LoadBlock.NonVolatileCodeLimitC6) == 0 {
				addWarning(r, appName+".LoadBlock",
					"NonVolatileCodeLimitC6 (C6) missing - may cause install_failed_due_to_pe_processing_error on eUICC")
			}
			if len(app.LoadBlock.VolatileDataLimitC7) == 0 {
				addWarning(r, appName+".LoadBlock",
					"VolatileDataLimitC7 (C7) missing - may cause install_failed_due_to_pe_processing_error on eUICC")
			}
			if len(app.LoadBlock.NonVolatileDataLimitC8) == 0 {
				addWarning(r, appName+".LoadBlock",
					"NonVolatileDataLimitC8 (C8) missing - may cause install_failed_due_to_pe_processing_error on eUICC")
			}
		}

		// Check instances
		for j, inst := range app.InstanceList {
			instName := fmt.Sprintf("Application[%d].Instance[%d]", i, j)
			
			// Validate AIDs
			if !isValidAID(inst.ApplicationLoadPackageAID) {
				addError(r, instName, fmt.Sprintf("PackageAID invalid: %s",
					hex.EncodeToString(inst.ApplicationLoadPackageAID)))
			}
			if !isValidAID(inst.ClassAID) {
				addError(r, instName, fmt.Sprintf("ClassAID invalid: %s",
					hex.EncodeToString(inst.ClassAID)))
			}
			if !isValidAID(inst.InstanceAID) {
				addError(r, instName, fmt.Sprintf("InstanceAID invalid: %s",
					hex.EncodeToString(inst.InstanceAID)))
			}
			
			// ApplicationPrivileges length check
			// Working profiles use 1 byte, broken profiles often have 3 bytes
			if len(inst.ApplicationPrivileges) != 1 {
				addWarning(r, instName+".ApplicationPrivileges",
					fmt.Sprintf("ApplicationPrivileges length is %d bytes (expected 1 byte). "+
						"This may cause install_failed_due_to_pe_processing_error on some eUICCs.",
						len(inst.ApplicationPrivileges)))
			}
			
			// Check C9 parameter format
			// Correct format: C9 00 or C9 XX (with length)
			// Broken format: 81 00
			if len(inst.ApplicationSpecificParamsC9) >= 2 {
				if inst.ApplicationSpecificParamsC9[0] == 0x81 {
					addWarning(r, instName+".ApplicationSpecificParamsC9",
						"C9 params start with 0x81 (incorrect). Should start with 0xC9 or be empty.")
				}
			}

			// Validate ProcessData APDUs
			if len(inst.ProcessData) > 0 {
				for k, apdu := range inst.ProcessData {
					if !isValidAPDU(apdu) {
						addError(r, instName, fmt.Sprintf("ProcessData[%d] invalid APDU: %s",
							k, hex.EncodeToString(apdu)))
					}
				}
			} else if opts.StrictApplet {
				addWarning(r, instName, "ProcessData is empty (no personalization APDUs)")
			}
		}
	}

	appCount := len(p.Applications)
	instCount := 0
	for _, app := range p.Applications {
		instCount += len(app.InstanceList)
	}
	addCheck(r, "Applications", len(r.Errors) == 0,
		fmt.Sprintf("%d applet(s) found, %d instance(s)", appCount, instCount))
}

func validateSecurityDomains(p *Profile, r *ValidationResult) {
	if len(p.SecurityDomains) == 0 {
		addWarning(r, "SecurityDomains", "No Security Domains found")
		return
	}

	for i, sd := range p.SecurityDomains {
		sdName := fmt.Sprintf("SecurityDomain[%d]", i)
		
		if sd.Instance == nil {
			addError(r, sdName, "Instance is nil")
			continue
		}

		if !isValidAID(sd.Instance.InstanceAID) {
			addError(r, sdName, fmt.Sprintf("Invalid InstanceAID: %s",
				hex.EncodeToString(sd.Instance.InstanceAID)))
		}

		// Check for keys
		if len(sd.KeyList) == 0 {
			addWarning(r, sdName, "No keys defined in Security Domain")
		}
	}

	addCheck(r, "SecurityDomains", true, fmt.Sprintf("%d SD(s) found", len(p.SecurityDomains)))
}

// validateEFContentSizes checks that EF content fits within declared file sizes
func validateEFContentSizes(p *Profile, r *ValidationResult) {
	sizeErrors := 0
	sizeWarnings := 0

	// Check MF EFs
	if p.MF != nil {
		sizeErrors += checkEFSize("MF.EF_ICCID", p.MF.EF_ICCID, r)
		sizeErrors += checkEFSize("MF.EF_DIR", p.MF.EF_DIR, r)
		sizeErrors += checkEFSize("MF.EF_ARR", p.MF.EF_ARR, r)
		sizeErrors += checkEFSize("MF.EF_PL", p.MF.EF_PL, r)
		sizeErrors += checkEFSize("MF.EF_UMPC", p.MF.EF_UMPC, r)
	}

	// Check USIM EFs
	if p.USIM != nil {
		sizeErrors += checkEFSize("USIM.EF_IMSI", p.USIM.EF_IMSI, r)
		sizeErrors += checkEFSize("USIM.EF_Keys", p.USIM.EF_Keys, r)
		sizeErrors += checkEFSize("USIM.EF_KeysPS", p.USIM.EF_KeysPS, r)
		sizeErrors += checkEFSize("USIM.EF_HPPLMN", p.USIM.EF_HPPLMN, r)
		sizeErrors += checkEFSize("USIM.EF_UST", p.USIM.EF_UST, r)
		sizeErrors += checkEFSize("USIM.EF_FDN", p.USIM.EF_FDN, r)
		sizeErrors += checkEFSize("USIM.EF_SMS", p.USIM.EF_SMS, r)
		sizeErrors += checkEFSize("USIM.EF_SMSP", p.USIM.EF_SMSP, r)
		sizeErrors += checkEFSize("USIM.EF_SMSS", p.USIM.EF_SMSS, r)
		sizeErrors += checkEFSize("USIM.EF_SPN", p.USIM.EF_SPN, r)
		sizeErrors += checkEFSize("USIM.EF_EST", p.USIM.EF_EST, r)
		sizeErrors += checkEFSize("USIM.EF_ACC", p.USIM.EF_ACC, r)
		sizeErrors += checkEFSize("USIM.EF_FPLMN", p.USIM.EF_FPLMN, r)
		sizeErrors += checkEFSize("USIM.EF_LOCI", p.USIM.EF_LOCI, r)
		sizeErrors += checkEFSize("USIM.EF_AD", p.USIM.EF_AD, r)
		sizeErrors += checkEFSize("USIM.EF_ECC", p.USIM.EF_ECC, r)
		sizeErrors += checkEFSize("USIM.EF_NETPAR", p.USIM.EF_NETPAR, r)
		sizeErrors += checkEFSize("USIM.EF_EPSLOCI", p.USIM.EF_EPSLOCI, r)
		sizeErrors += checkEFSize("USIM.EF_EPSNSC", p.USIM.EF_EPSNSC, r)
		sizeErrors += checkEFSize("USIM.EF_ARR", p.USIM.EF_ARR, r)
	}

	// Check OptionalUSIM EFs
	if p.OptUSIM != nil {
		sizeErrors += checkEFSize("OptUSIM.EF_LI", p.OptUSIM.EF_LI, r)
		sizeErrors += checkEFSize("OptUSIM.EF_MSISDN", p.OptUSIM.EF_MSISDN, r)
		sizeErrors += checkEFSize("OptUSIM.EF_CBMI", p.OptUSIM.EF_CBMI, r)
		sizeErrors += checkEFSize("OptUSIM.EF_CBMID", p.OptUSIM.EF_CBMID, r)
		sizeErrors += checkEFSize("OptUSIM.EF_SDN", p.OptUSIM.EF_SDN, r)
		sizeErrors += checkEFSize("OptUSIM.EF_PNN", p.OptUSIM.EF_PNN, r)
		sizeErrors += checkEFSize("OptUSIM.EF_OPL", p.OptUSIM.EF_OPL, r)
		sizeErrors += checkEFSize("OptUSIM.EF_EHPLMN", p.OptUSIM.EF_EHPLMN, r)
	}

	// Check ISIM EFs
	if p.ISIM != nil {
		sizeErrors += checkEFSize("ISIM.EF_IMPI", p.ISIM.EF_IMPI, r)
		sizeErrors += checkEFSize("ISIM.EF_IMPU", p.ISIM.EF_IMPU, r)
		sizeErrors += checkEFSize("ISIM.EF_DOMAIN", p.ISIM.EF_DOMAIN, r)
		sizeErrors += checkEFSize("ISIM.EF_IST", p.ISIM.EF_IST, r)
		sizeErrors += checkEFSize("ISIM.EF_AD", p.ISIM.EF_AD, r)
		sizeErrors += checkEFSize("ISIM.EF_ARR", p.ISIM.EF_ARR, r)
	}

	// Check OptionalISIM EFs
	if p.OptISIM != nil {
		sizeErrors += checkEFSize("OptISIM.EF_PCSCF", p.OptISIM.EF_PCSCF, r)
		sizeErrors += checkEFSize("OptISIM.EF_GBABP", p.OptISIM.EF_GBABP, r)
		sizeErrors += checkEFSize("OptISIM.EF_GBANL", p.OptISIM.EF_GBANL, r)
	}

	// Check CSIM EFs
	if p.CSIM != nil {
		sizeErrors += checkEFSize("CSIM.EF_IMSI_M", p.CSIM.EF_IMSI_M, r)
		sizeErrors += checkEFSize("CSIM.EF_IMSI_T", p.CSIM.EF_IMSI_T, r)
		sizeErrors += checkEFSize("CSIM.EF_TMSI", p.CSIM.EF_TMSI, r)
		sizeErrors += checkEFSize("CSIM.EF_AD", p.CSIM.EF_AD, r)
		sizeErrors += checkEFSize("CSIM.EF_ARR", p.CSIM.EF_ARR, r)
	}

	// Check Telecom EFs
	if p.Telecom != nil {
		sizeErrors += checkEFSize("Telecom.EF_ARR", p.Telecom.EF_ARR, r)
		sizeErrors += checkEFSize("Telecom.EF_SUME", p.Telecom.EF_SUME, r)
		sizeErrors += checkEFSize("Telecom.EF_PSISMSC", p.Telecom.EF_PSISMSC, r)
		sizeErrors += checkEFSize("Telecom.EF_IMG", p.Telecom.EF_IMG, r)
		sizeErrors += checkEFSize("Telecom.EF_PBR", p.Telecom.EF_PBR, r)
		sizeErrors += checkEFSize("Telecom.EF_MLPL", p.Telecom.EF_MLPL, r)
		sizeErrors += checkEFSize("Telecom.EF_MSPL", p.Telecom.EF_MSPL, r)
	}

	// Check DF-5GS EFs
	if p.DF5GS != nil {
		sizeErrors += checkEFSize("DF5GS.EF_5GS3GPPLOCI", p.DF5GS.EF_5GS3GPPLOCI, r)
		sizeErrors += checkEFSize("DF5GS.EF_5GSN3GPPLOCI", p.DF5GS.EF_5GSN3GPPLOCI, r)
		sizeErrors += checkEFSize("DF5GS.EF_5GS3GPPNSC", p.DF5GS.EF_5GS3GPPNSC, r)
		sizeErrors += checkEFSize("DF5GS.EF_5GAUTHKEYS", p.DF5GS.EF_5GAUTHKEYS, r)
		sizeErrors += checkEFSize("DF5GS.EF_UAC_AIC", p.DF5GS.EF_UAC_AIC, r)
		sizeErrors += checkEFSize("DF5GS.EF_SUCI_CALC_INFO", p.DF5GS.EF_SUCI_CALC_INFO, r)
		sizeErrors += checkEFSize("DF5GS.EF_OPL5G", p.DF5GS.EF_OPL5G, r)
		sizeErrors += checkEFSize("DF5GS.EF_ROUTING_INDICATOR", p.DF5GS.EF_ROUTING_INDICATOR, r)
	}

	// Check GSM Access EFs
	if p.GSMAccess != nil {
		sizeErrors += checkEFSize("GSMAccess.EF_Kc", p.GSMAccess.EF_Kc, r)
		sizeErrors += checkEFSize("GSMAccess.EF_KcGPRS", p.GSMAccess.EF_KcGPRS, r)
		sizeErrors += checkEFSize("GSMAccess.EF_CPBCCH", p.GSMAccess.EF_CPBCCH, r)
		sizeErrors += checkEFSize("GSMAccess.EF_INVSCAN", p.GSMAccess.EF_INVSCAN, r)
	}

	if sizeErrors > 0 {
		addCheck(r, "EFFileSizes", false, fmt.Sprintf("%d EF(s) have content exceeding declared size", sizeErrors))
	} else if sizeWarnings > 0 {
		addCheck(r, "EFFileSizes", true, fmt.Sprintf("All EF sizes valid (%d warnings)", sizeWarnings))
	} else {
		addCheck(r, "EFFileSizes", true, "All EF content fits within declared sizes")
	}
}

// checkEFSize validates that EF content fits within declared file size
// Returns 1 if error found, 0 otherwise
func checkEFSize(name string, ef *ElementaryFile, r *ValidationResult) int {
	if ef == nil {
		return 0
	}

	// Get declared file size
	declaredSize := 0
	if ef.Descriptor != nil && len(ef.Descriptor.EFFileSize) > 0 {
		declaredSize = decodeFileSize(ef.Descriptor.EFFileSize)
	}

	// Calculate actual content size (considering offsets)
	actualSize := calculateContentSize(ef)

	// If no declared size or no content, skip
	if declaredSize == 0 || actualSize == 0 {
		return 0
	}

	// Check if content exceeds declared size
	if actualSize > declaredSize {
		addError(r, name, fmt.Sprintf("content size (%d bytes) exceeds declared file size (%d bytes)",
			actualSize, declaredSize))
		return 1
	}

	return 0
}

// calculateContentSize calculates the total content size considering offsets
func calculateContentSize(ef *ElementaryFile) int {
	if ef == nil || len(ef.FillContents) == 0 {
		return 0
	}

	maxEnd := 0
	for _, fc := range ef.FillContents {
		end := fc.Offset + len(fc.Content)
		if end > maxEnd {
			maxEnd = end
		}
	}

	return maxEnd
}

func validateAgainstTemplate(p *Profile, template *Profile, r *ValidationResult) {
	validateAgainstTemplateWithOpts(p, template, r, nil)
}

func validateAgainstTemplateWithOpts(p *Profile, template *Profile, r *ValidationResult, opts *ValidationOptions) {
	if opts == nil {
		opts = &ValidationOptions{}
	}

	// Compare element count
	if len(p.Elements) != len(template.Elements) {
		if opts.TemplateStrict {
			addError(r, "Template", fmt.Sprintf("Element count differs: profile has %d, template has %d",
				len(p.Elements), len(template.Elements)))
		} else {
			addWarning(r, "Template", fmt.Sprintf("Element count differs: profile has %d, template has %d",
				len(p.Elements), len(template.Elements)))
		}
	}

	// Compare element order and structure
	for i := 0; i < len(p.Elements) && i < len(template.Elements); i++ {
		if p.Elements[i].Tag != template.Elements[i].Tag {
			if opts.TemplateStrict {
				addError(r, "Template", fmt.Sprintf("Element[%d] tag differs: profile has %s, template has %s",
					i, GetProfileElementName(p.Elements[i].Tag), GetProfileElementName(template.Elements[i].Tag)))
			} else {
				addWarning(r, "Template", fmt.Sprintf("Element[%d] tag differs: profile has %s, template has %s",
					i, GetProfileElementName(p.Elements[i].Tag), GetProfileElementName(template.Elements[i].Tag)))
			}
		}
	}

	// Check field lengths if requested
	if opts.CheckFieldLengths {
		validateFieldLengths(p, template, r, opts.TemplateStrict)
	}

	// Check for missing mandatory elements from template
	templateTags := make(map[int]bool)
	for _, elem := range template.Elements {
		templateTags[elem.Tag] = true
	}

	profileTags := make(map[int]bool)
	for _, elem := range p.Elements {
		profileTags[elem.Tag] = true
	}

	// Check for missing elements
	for tag := range templateTags {
		if !profileTags[tag] {
			elemName := GetProfileElementName(tag)
			if opts.TemplateStrict {
				addError(r, "Template", fmt.Sprintf("Missing element from template: %s", elemName))
			} else {
				addWarning(r, "Template", fmt.Sprintf("Missing element from template: %s", elemName))
			}
		}
	}

	// Check for extra elements not in template
	for tag := range profileTags {
		if !templateTags[tag] {
			elemName := GetProfileElementName(tag)
			addWarning(r, "Template", fmt.Sprintf("Extra element not in template: %s", elemName))
		}
	}

	addCheck(r, "Template", len(r.Errors) == 0, "Template comparison complete")
}

// validateFieldLengths compares EF file sizes between profile and template
func validateFieldLengths(p *Profile, template *Profile, r *ValidationResult, strict bool) {
	// Compare USIM EF sizes
	if p.USIM != nil && template.USIM != nil {
		compareEFSizes("USIM.EF_IMSI", p.USIM.EF_IMSI, template.USIM.EF_IMSI, r, strict)
		compareEFSizes("USIM.EF_Keys", p.USIM.EF_Keys, template.USIM.EF_Keys, r, strict)
		compareEFSizes("USIM.EF_UST", p.USIM.EF_UST, template.USIM.EF_UST, r, strict)
		compareEFSizes("USIM.EF_ACC", p.USIM.EF_ACC, template.USIM.EF_ACC, r, strict)
		compareEFSizes("USIM.EF_FPLMN", p.USIM.EF_FPLMN, template.USIM.EF_FPLMN, r, strict)
		compareEFSizes("USIM.EF_AD", p.USIM.EF_AD, template.USIM.EF_AD, r, strict)
	}

	// Compare ISIM EF sizes
	if p.ISIM != nil && template.ISIM != nil {
		compareEFSizes("ISIM.EF_IMPI", p.ISIM.EF_IMPI, template.ISIM.EF_IMPI, r, strict)
		compareEFSizes("ISIM.EF_IMPU", p.ISIM.EF_IMPU, template.ISIM.EF_IMPU, r, strict)
		compareEFSizes("ISIM.EF_DOMAIN", p.ISIM.EF_DOMAIN, template.ISIM.EF_DOMAIN, r, strict)
		compareEFSizes("ISIM.EF_IST", p.ISIM.EF_IST, template.ISIM.EF_IST, r, strict)
	}

	// Compare MF EF sizes
	if p.MF != nil && template.MF != nil {
		compareEFSizes("MF.EF_ICCID", p.MF.EF_ICCID, template.MF.EF_ICCID, r, strict)
		compareEFSizes("MF.EF_DIR", p.MF.EF_DIR, template.MF.EF_DIR, r, strict)
	}
}

// compareEFSizes compares file sizes and content lengths
func compareEFSizes(name string, pEF, tEF *ElementaryFile, r *ValidationResult, strict bool) {
	if pEF == nil && tEF == nil {
		return
	}

	if pEF == nil && tEF != nil {
		if strict {
			addError(r, "FieldLength", fmt.Sprintf("%s: missing in profile but present in template", name))
		} else {
			addWarning(r, "FieldLength", fmt.Sprintf("%s: missing in profile but present in template", name))
		}
		return
	}

	if pEF != nil && tEF == nil {
		addWarning(r, "FieldLength", fmt.Sprintf("%s: present in profile but missing in template", name))
		return
	}

	// Compare file descriptor sizes if available
	if pEF.Descriptor != nil && tEF.Descriptor != nil {
		if len(pEF.Descriptor.EFFileSize) > 0 && len(tEF.Descriptor.EFFileSize) > 0 {
			pSize := decodeFileSize(pEF.Descriptor.EFFileSize)
			tSize := decodeFileSize(tEF.Descriptor.EFFileSize)
			if pSize != tSize {
				if strict {
					addError(r, "FieldLength", fmt.Sprintf("%s: file size differs (profile: %d, template: %d)", name, pSize, tSize))
				} else {
					addWarning(r, "FieldLength", fmt.Sprintf("%s: file size differs (profile: %d, template: %d)", name, pSize, tSize))
				}
			}
		}
	}

	// Compare content lengths
	pContentLen := 0
	tContentLen := 0

	for _, fc := range pEF.FillContents {
		pContentLen += len(fc.Content)
	}
	for _, fc := range tEF.FillContents {
		tContentLen += len(fc.Content)
	}

	if pContentLen > 0 && tContentLen > 0 && pContentLen != tContentLen {
		// This is informational - content lengths may legitimately differ
		addWarning(r, "FieldLength", fmt.Sprintf("%s: content length differs (profile: %d, template: %d)", name, pContentLen, tContentLen))
	}
}

// decodeFileSize decodes file size from EFFileSize bytes
func decodeFileSize(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	size := 0
	for _, b := range data {
		size = size<<8 | int(b)
	}
	return size
}

// luhnCheck validates Luhn checksum for ICCID
func luhnCheck(s string) bool {
	if len(s) < 2 {
		return false
	}

	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}

	if len(digits) < 2 {
		return false
	}

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

// isValidAID checks if AID has valid format (5-16 bytes)
func isValidAID(aid []byte) bool {
	return len(aid) >= 5 && len(aid) <= 16
}

// isValidAPDU checks if APDU has valid format
func isValidAPDU(apdu []byte) bool {
	// Minimum APDU: CLA INS P1 P2 = 4 bytes
	if len(apdu) < 4 {
		return false
	}
	
	// Case 1: CLA INS P1 P2 (4 bytes)
	if len(apdu) == 4 {
		return true
	}
	
	// Case 2: CLA INS P1 P2 Le (5 bytes)
	if len(apdu) == 5 {
		return true
	}
	
	// Case 3 or 4: CLA INS P1 P2 Lc Data [Le]
	if len(apdu) > 5 {
		lc := int(apdu[4])
		// Case 3: CLA INS P1 P2 Lc Data
		if len(apdu) == 5+lc {
			return true
		}
		// Case 4: CLA INS P1 P2 Lc Data Le
		if len(apdu) == 5+lc+1 {
			return true
		}
	}
	
	return false
}

// FormatValidationResult formats validation result for human-readable output
func (r *ValidationResult) FormatValidationResult() string {
	var sb strings.Builder

	status := "PASSED"
	if !r.Valid {
		status = "FAILED"
	}
	sb.WriteString(fmt.Sprintf("Profile Validation: %s\n\n", status))

	for _, check := range r.Checks {
		symbol := "✓"
		if !check.Passed {
			symbol = "✗"
		}
		sb.WriteString(fmt.Sprintf("%s %s: %s\n", symbol, check.Name, check.Message))
	}

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, e := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s: %s\n", e.Field, e.Message))
		}
	}

	if len(r.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range r.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s: %s\n", w.Field, w.Message))
		}
	}

	return sb.String()
}

