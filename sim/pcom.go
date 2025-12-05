// Package sim provides .pcom script parser and executor
// Compatible with RuSIM/OX24 personalization scripts
package sim

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sim_reader/card"
	"strconv"
	"strings"
	"unicode"
)

// PcomExecutor executes .pcom personalization scripts
type PcomExecutor struct {
	reader      *card.Reader
	variables   map[string]string // Global variables
	baseDir     string            // Base directory for .CALL
	callStack   []string          // Call stack for debugging
	maxDepth    int               // Max recursion depth
	lastResp    []byte            // Last response data (for W(), R())
	lastSW      uint16            // Last status word
	verbose     bool              // Print each command
	stopOnError bool              // Stop execution on first error
	lineNum     int               // Current line number
	currentFile string            // Current file being executed

	// Statistics
	totalCommands   int
	successCommands int
	failedCommands  int

	// Callbacks
	OnCommand func(file string, line int, apdu string)
	OnResult  func(file string, line int, apdu string, resp []byte, sw uint16, ok bool)
	OnError   func(file string, line int, err error)
}

// PcomResult represents execution result
type PcomResult struct {
	File     string
	Line     int
	Command  string
	APDU     []byte
	Response []byte
	SW       uint16
	Expected string
	Success  bool
	Error    string
}

// NewPcomExecutor creates a new executor
func NewPcomExecutor(reader *card.Reader) *PcomExecutor {
	return &PcomExecutor{
		reader:      reader,
		variables:   make(map[string]string),
		maxDepth:    20,
		stopOnError: false,
		verbose:     true,
	}
}

// SetVerbose enables/disables verbose output
func (e *PcomExecutor) SetVerbose(v bool) {
	e.verbose = v
}

// SetStopOnError enables/disables stop on first error
func (e *PcomExecutor) SetStopOnError(v bool) {
	e.stopOnError = v
}

// SetVariable sets a variable value
func (e *PcomExecutor) SetVariable(name, value string) {
	if !strings.HasPrefix(name, "%") {
		name = "%" + name
	}
	e.variables[name] = value
}

// GetVariable gets a variable value
func (e *PcomExecutor) GetVariable(name string) string {
	if !strings.HasPrefix(name, "%") {
		name = "%" + name
	}
	return e.variables[name]
}

// ExecuteFile executes a .pcom script file
func (e *PcomExecutor) ExecuteFile(filename string) error {
	// Set base directory from first file
	if e.baseDir == "" {
		e.baseDir = filepath.Dir(filename)
	}

	return e.executeFileInternal(filename)
}

// executeFileInternal executes a file with recursion check
func (e *PcomExecutor) executeFileInternal(filename string) error {
	// Resolve path relative to base directory
	fullPath := filename
	if !filepath.IsAbs(filename) {
		fullPath = filepath.Join(e.baseDir, filename)
	}

	// Check recursion depth
	if len(e.callStack) >= e.maxDepth {
		return fmt.Errorf("max call depth (%d) exceeded at %s", e.maxDepth, filename)
	}

	// Check for circular calls
	for _, f := range e.callStack {
		if f == fullPath {
			return fmt.Errorf("circular call detected: %s", filename)
		}
	}

	// Push to call stack
	e.callStack = append(e.callStack, fullPath)
	defer func() {
		e.callStack = e.callStack[:len(e.callStack)-1]
	}()

	// Open file
	file, err := os.Open(fullPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filename, err)
	}
	defer file.Close()

	prevFile := e.currentFile
	e.currentFile = filename
	defer func() { e.currentFile = prevFile }()

	// Read and execute lines
	scanner := bufio.NewScanner(file)
	e.lineNum = 0
	var multiLine strings.Builder

	for scanner.Scan() {
		e.lineNum++
		line := scanner.Text()

		// Handle line continuation with backslash
		trimmed := strings.TrimRightFunc(line, unicode.IsSpace)
		if strings.HasSuffix(trimmed, "\\") {
			multiLine.WriteString(strings.TrimSuffix(trimmed, "\\"))
			multiLine.WriteString(" ")
			continue
		}

		if multiLine.Len() > 0 {
			multiLine.WriteString(line)
			line = multiLine.String()
			multiLine.Reset()
		}

		// Execute line
		err := e.executeLine(line)
		if err != nil {
			if e.OnError != nil {
				e.OnError(e.currentFile, e.lineNum, err)
			}
			if e.stopOnError {
				return fmt.Errorf("%s:%d: %w", filename, e.lineNum, err)
			}
		}
	}

	return scanner.Err()
}

// executeLine executes a single line
func (e *PcomExecutor) executeLine(line string) error {
	// Remove comments (but be careful with ; inside strings)
	line = e.removeComment(line)

	// Trim whitespace
	line = strings.TrimSpace(line)

	// Skip empty lines
	if line == "" {
		return nil
	}

	// Check for directive (starts with .)
	if strings.HasPrefix(line, ".") {
		return e.executeDirective(line)
	}

	// Otherwise it's an APDU command
	return e.executeAPDULine(line)
}

// removeComment removes comment from line
func (e *PcomExecutor) removeComment(line string) string {
	// Find first ; that's not inside brackets [] or parentheses ()
	// Comments can appear after APDU commands like: A0A4 0000 02 3F00 (9000) ;; comment
	bracketDepth := 0
	parenDepth := 0

	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case ';':
			// Only treat as comment if we're not inside brackets or parens
			if bracketDepth == 0 && parenDepth == 0 {
				return line[:i]
			}
		}
	}
	return line
}

// executeDirective executes a directive line
func (e *PcomExecutor) executeDirective(line string) error {
	// Parse directive name and arguments
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	directive := strings.ToUpper(parts[0])

	switch directive {
	case ".DEFINE":
		return e.executeDefine(line)
	case ".CALL":
		return e.executeCall(parts)
	case ".POWER_ON":
		return e.executePowerOn(parts)
	case ".POWER_OFF":
		return e.executePowerOff()
	case ".ALLUNDEFINE":
		e.variables = make(map[string]string)
		return nil
	case ".INSERT":
		// Ignore - card already inserted
		return nil
	case ".STEP_ON", ".STEP_OFF":
		// Ignore - interactive mode not supported
		return nil
	default:
		// Unknown directive - ignore with warning
		if e.verbose {
			fmt.Printf("  [WARN] Unknown directive: %s\n", directive)
		}
		return nil
	}
}

// executeDefine handles .DEFINE directive
func (e *PcomExecutor) executeDefine(line string) error {
	// Format: .DEFINE %NAME value...
	// Find %NAME
	idx := strings.Index(line, "%")
	if idx < 0 {
		return fmt.Errorf("invalid .DEFINE: no variable name")
	}

	// Extract variable name (ends at space or end of line)
	rest := line[idx:]
	endIdx := strings.IndexFunc(rest[1:], func(r rune) bool {
		return unicode.IsSpace(r)
	})

	var name, value string
	if endIdx < 0 {
		// No value, just define empty
		name = rest
		value = ""
	} else {
		name = rest[:endIdx+1]
		value = strings.TrimSpace(rest[endIdx+1:])
	}

	// Handle R(pos;len) function - extract from last response
	value = e.expandRFunction(value)

	// Expand variables in value
	value = e.expandVariables(value)

	// Remove spaces from hex value (but not from the variable name)
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "\t", "")

	e.variables[name] = value

	if e.verbose {
		displayVal := value
		if len(displayVal) > 40 {
			displayVal = displayVal[:40] + "..."
		}
		fmt.Printf("  [DEF] %s = %s\n", name, displayVal)
	}

	return nil
}

// executeCall handles .CALL directive
func (e *PcomExecutor) executeCall(parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf(".CALL requires filename")
	}

	filename := parts[1]
	if e.verbose {
		fmt.Printf("\n  [CALL] %s\n", filename)
	}

	return e.executeFileInternal(filename)
}

// executePowerOn handles .POWER_ON directive
func (e *PcomExecutor) executePowerOn(parts []string) error {
	cold := false
	if len(parts) > 1 && strings.ToUpper(parts[1]) == "/COLD" {
		cold = true
	}

	if e.verbose {
		if cold {
			fmt.Println("  [POWER_ON /COLD]")
		} else {
			fmt.Println("  [POWER_ON]")
		}
	}

	// Reconnect to card
	if e.reader != nil {
		if err := e.reader.Reconnect(cold); err != nil {
			if e.verbose {
				fmt.Printf("  [WARN] Reconnect failed: %v\n", err)
			}
			// Don't fail on reconnect error - card might still work
		}
	}

	return nil
}

// executePowerOff handles .POWER_OFF directive
func (e *PcomExecutor) executePowerOff() error {
	if e.verbose {
		fmt.Println("  [POWER_OFF]")
	}
	return nil
}

// executeAPDULine executes an APDU command line
func (e *PcomExecutor) executeAPDULine(line string) error {
	// Parse APDU and expected response
	// Format: CLA INS P1 P2 [Lc] [DATA] (EXPECTED_SW) [EXPECTED_DATA]

	// Find expected SW in parentheses
	expectedSW := ""
	expectedData := ""

	// Find (SW) pattern
	swMatch := regexp.MustCompile(`\(([0-9A-Fa-fXx]+)\)`).FindStringSubmatch(line)
	if len(swMatch) > 1 {
		expectedSW = swMatch[1]
		// Remove (SW) from line
		line = regexp.MustCompile(`\([0-9A-Fa-fXx]+\)`).ReplaceAllString(line, "")
	}

	// Find [DATA] pattern for expected response data
	dataMatch := regexp.MustCompile(`\[([^\]]+)\]`).FindStringSubmatch(line)
	if len(dataMatch) > 1 {
		expectedData = dataMatch[1]
		// Remove [DATA] from line
		line = regexp.MustCompile(`\[[^\]]+\]`).ReplaceAllString(line, "")
	}

	// Clean up APDU hex string
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	// Expand variables
	line = e.expandVariables(line)

	// Also expand in expected data for comparison
	expectedData = e.expandVariables(expectedData)

	// Remove all spaces
	apduHex := strings.ReplaceAll(line, " ", "")
	apduHex = strings.ReplaceAll(apduHex, "\t", "")

	// Handle W(pos;len) function - get bytes from last response
	apduHex = e.expandWFunction(apduHex)

	// Decode hex to bytes
	apduBytes, err := hex.DecodeString(apduHex)
	if err != nil {
		return fmt.Errorf("invalid APDU hex: %s - %w", apduHex, err)
	}

	if len(apduBytes) < 4 {
		return fmt.Errorf("APDU too short: %d bytes", len(apduBytes))
	}

	// Execute APDU
	e.totalCommands++

	if e.OnCommand != nil {
		e.OnCommand(e.currentFile, e.lineNum, apduHex)
	}

	if e.verbose {
		displayAPDU := apduHex
		if len(displayAPDU) > 60 {
			displayAPDU = displayAPDU[:60] + "..."
		}
		fmt.Printf("  [%s:%d] %s", filepath.Base(e.currentFile), e.lineNum, displayAPDU)
	}

	resp, err := e.reader.SendAPDU(apduBytes)
	if err != nil {
		e.failedCommands++
		if e.verbose {
			fmt.Printf(" → ERROR: %v\n", err)
		}
		return fmt.Errorf("APDU transmit error: %w", err)
	}

	// Handle GET RESPONSE if needed (SW1=61 or SW1=9F for GSM)
	if resp.SW1 == 0x61 || resp.SW1 == 0x9F {
		// Determine which GET RESPONSE to use
		var getResp *card.APDUResponse
		if apduBytes[0] == 0xA0 || resp.SW1 == 0x9F {
			// GSM class
			getResp, _ = e.reader.GetResponseGSM(resp.SW2)
		} else {
			getResp, _ = e.reader.GetResponse(resp.SW2)
		}
		if getResp != nil {
			resp = getResp
		}
	}

	// Store last response
	e.lastResp = resp.Data
	e.lastSW = resp.SW()

	// Check expected SW
	ok := true
	if expectedSW != "" {
		ok = e.matchSW(resp.SW(), expectedSW)
	}

	// Check expected data
	if ok && expectedData != "" {
		ok = e.matchData(resp.Data, expectedData)
	}

	if ok {
		e.successCommands++
	} else {
		e.failedCommands++
	}

	if e.OnResult != nil {
		e.OnResult(e.currentFile, e.lineNum, apduHex, resp.Data, resp.SW(), ok)
	}

	if e.verbose {
		swStr := fmt.Sprintf("%04X", resp.SW())
		if ok {
			fmt.Printf(" → %s ✓\n", swStr)
		} else {
			fmt.Printf(" → %s ✗ (expected %s)\n", swStr, expectedSW)
		}
	}

	if !ok && e.stopOnError {
		return fmt.Errorf("SW mismatch: got %04X, expected %s", resp.SW(), expectedSW)
	}

	return nil
}

// expandVariables replaces %VAR with their values
func (e *PcomExecutor) expandVariables(s string) string {
	// Find all %NAME patterns and replace
	result := s
	for name, value := range e.variables {
		result = strings.ReplaceAll(result, name, value)
	}
	return result
}

// expandWFunction handles W(pos;len) - extract bytes from last response
func (e *PcomExecutor) expandWFunction(s string) string {
	// Pattern: W(pos;len)
	re := regexp.MustCompile(`W\((\d+);(\d+)\)`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		pos, _ := strconv.Atoi(parts[1])
		length, _ := strconv.Atoi(parts[2])

		if pos >= len(e.lastResp) {
			return "00"
		}
		end := pos + length
		if end > len(e.lastResp) {
			end = len(e.lastResp)
		}

		return strings.ToUpper(hex.EncodeToString(e.lastResp[pos:end]))
	})
}

// expandRFunction handles R(pos;len) for .DEFINE - same as W()
func (e *PcomExecutor) expandRFunction(s string) string {
	return e.expandWFunction(s)
}

// matchSW checks if SW matches expected pattern (supports X wildcards)
func (e *PcomExecutor) matchSW(sw uint16, expected string) bool {
	expected = strings.ToUpper(expected)
	actual := fmt.Sprintf("%04X", sw)

	if len(expected) != 4 {
		// Pad with zeros
		expected = fmt.Sprintf("%04s", expected)
	}

	for i := 0; i < 4 && i < len(expected); i++ {
		if expected[i] == 'X' {
			continue // Wildcard
		}
		if i >= len(actual) || expected[i] != actual[i] {
			return false
		}
	}
	return true
}

// matchData checks if response data matches expected pattern
func (e *PcomExecutor) matchData(data []byte, expected string) bool {
	// Remove spaces
	expected = strings.ReplaceAll(expected, " ", "")
	expected = strings.ToUpper(expected)

	actual := strings.ToUpper(hex.EncodeToString(data))

	// Check length
	if len(expected) > len(actual) {
		return false
	}

	// Compare with wildcard support (X)
	for i := 0; i < len(expected); i++ {
		if expected[i] == 'X' {
			continue // Wildcard
		}
		if i >= len(actual) || expected[i] != actual[i] {
			return false
		}
	}

	return true
}

// GetStatistics returns execution statistics
func (e *PcomExecutor) GetStatistics() (total, success, failed int) {
	return e.totalCommands, e.successCommands, e.failedCommands
}

// GetCallStack returns current call stack
func (e *PcomExecutor) GetCallStack() []string {
	result := make([]string, len(e.callStack))
	copy(result, e.callStack)
	return result
}

// Reset resets executor state
func (e *PcomExecutor) Reset() {
	e.variables = make(map[string]string)
	e.callStack = nil
	e.lastResp = nil
	e.lastSW = 0
	e.totalCommands = 0
	e.successCommands = 0
	e.failedCommands = 0
}
