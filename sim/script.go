package sim

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"sim_reader/card"
	"strings"
)

// ScriptResult represents the result of a single APDU command
type ScriptResult struct {
	LineNum  int
	Command  string
	APDU     string
	Response string
	SW       string
	Success  bool
	Error    string
}

// RunScript executes APDU commands from a script file
// Supports:
//   - Lines starting with # are comments
//   - Lines starting with "apdu " followed by hex APDU
//   - Empty lines are ignored
func RunScript(reader *card.Reader, filename string) ([]ScriptResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open script file: %w", err)
	}
	defer file.Close()

	var results []ScriptResult
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse APDU command
		if strings.HasPrefix(strings.ToLower(line), "apdu ") {
			apduHex := strings.TrimSpace(line[5:])
			result := executeAPDU(reader, lineNum, line, apduHex)
			results = append(results, result)
		} else {
			// Unknown command
			results = append(results, ScriptResult{
				LineNum: lineNum,
				Command: line,
				Success: false,
				Error:   "Unknown command (expected 'apdu <hex>')",
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("error reading script: %w", err)
	}

	return results, nil
}

// executeAPDU executes a single APDU command
func executeAPDU(reader *card.Reader, lineNum int, command, apduHex string) ScriptResult {
	result := ScriptResult{
		LineNum: lineNum,
		Command: command,
		APDU:    apduHex,
	}

	// Remove spaces from hex string
	apduHex = strings.ReplaceAll(apduHex, " ", "")

	// Decode hex
	apduBytes, err := hex.DecodeString(apduHex)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Invalid hex: %v", err)
		return result
	}

	if len(apduBytes) < 4 {
		result.Success = false
		result.Error = "APDU too short (min 4 bytes: CLA INS P1 P2)"
		return result
	}

	// Send APDU
	resp, err := reader.SendAPDU(apduBytes)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Transmit error: %v", err)
		return result
	}

	// Handle GET RESPONSE if needed (SW1=61)
	if resp.HasMoreData() {
		getResp, err := reader.GetResponse(resp.SW2)
		if err == nil {
			resp = getResp
		}
	}

	result.Response = fmt.Sprintf("%X", resp.Data)
	result.SW = fmt.Sprintf("%04X", resp.SW())
	result.Success = resp.IsOK()

	if !result.Success {
		result.Error = card.SWToString(resp.SW())
	}

	return result
}

// RunAPDUInteractive runs a single APDU command from string
func RunAPDUInteractive(reader *card.Reader, apduHex string) (*card.APDUResponse, error) {
	// Remove spaces
	apduHex = strings.ReplaceAll(apduHex, " ", "")

	// Decode hex
	apduBytes, err := hex.DecodeString(apduHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	if len(apduBytes) < 4 {
		return nil, fmt.Errorf("APDU too short (min 4 bytes)")
	}

	// Send APDU
	resp, err := reader.SendAPDU(apduBytes)
	if err != nil {
		return nil, fmt.Errorf("transmit error: %w", err)
	}

	// Handle GET RESPONSE if needed
	if resp.HasMoreData() {
		getResp, err := reader.GetResponse(resp.SW2)
		if err == nil {
			resp = getResp
		}
	}

	return resp, nil
}

