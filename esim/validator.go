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
	Template        *Profile // Optional template to compare against
	SkipLuhn        bool     // Skip ICCID Luhn checksum validation
	AllowEmptyPIN   bool     // Allow empty PIN values
	StrictApplet    bool     // Require all applet instances to have valid ProcessData
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

	// Template comparison (if provided)
	if opts.Template != nil {
		validateAgainstTemplate(p, opts.Template, result)
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

func validateAgainstTemplate(p *Profile, template *Profile, r *ValidationResult) {
	// Compare element count
	if len(p.Elements) != len(template.Elements) {
		addWarning(r, "Template", fmt.Sprintf("Element count differs: profile has %d, template has %d",
			len(p.Elements), len(template.Elements)))
	}

	// Compare element order
	for i := 0; i < len(p.Elements) && i < len(template.Elements); i++ {
		if p.Elements[i].Tag != template.Elements[i].Tag {
			addWarning(r, "Template", fmt.Sprintf("Element[%d] tag differs: profile has %s, template has %s",
				i, GetProfileElementName(p.Elements[i].Tag), GetProfileElementName(template.Elements[i].Tag)))
		}
	}
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

