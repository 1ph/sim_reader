package esim

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
)

// ConvertCAPToIJC converts a Java Card CAP file (ZIP format) to IJC format
// suitable for eSIM PE-Application loadBlockObject.
//
// CAP files are ZIP archives containing multiple .cap component files.
// IJC (Internal JavaCard) format concatenates these components in a specific order.
//
// IJC format starts with: 01 00 11 DE CA FF ED (magic + version)
// followed by component files in order.
func ConvertCAPToIJC(capData []byte) ([]byte, error) {
	// Check if already IJC format (starts with DECAFFED signature)
	if len(capData) >= 4 && capData[0] == 0x01 && capData[1] == 0x00 {
		// Could already be IJC, check for DECAFFED
		if len(capData) >= 7 && bytes.Equal(capData[2:7], []byte{0x11, 0xDE, 0xCA, 0xFF, 0xED}) {
			// Already IJC format
			return capData, nil
		}
	}

	// Check if it's a ZIP file (CAP format)
	if len(capData) < 4 || !bytes.Equal(capData[:4], []byte{0x50, 0x4B, 0x03, 0x04}) {
		return nil, fmt.Errorf("not a valid CAP file (expected ZIP signature PK, got %02X%02X)", capData[0], capData[1])
	}

	// Open as ZIP
	reader, err := zip.NewReader(bytes.NewReader(capData), int64(len(capData)))
	if err != nil {
		return nil, fmt.Errorf("open CAP as ZIP: %w", err)
	}

	// Find all .cap component files
	components := make(map[string][]byte)
	var basePath string

	for _, file := range reader.File {
		ext := strings.ToLower(path.Ext(file.Name))
		if ext == ".cap" {
			// Extract component name from path
			name := strings.ToLower(path.Base(file.Name))
			name = strings.TrimSuffix(name, ".cap")

			// Remember base path for proper ordering
			if basePath == "" {
				basePath = path.Dir(file.Name)
			}

			// Read file content
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("open %s: %w", file.Name, err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", file.Name, err)
			}

			components[name] = data
		}
	}

	if len(components) == 0 {
		return nil, fmt.Errorf("no .cap components found in CAP file")
	}

	// IJC component order (per Java Card specs and GlobalPlatform)
	// Components MUST be concatenated in this specific order for many eUICC
	componentOrder := []string{
		"header",
		"directory",
		"import",
		"applet",
		"class",
		"method",
		"staticfield",
		"export",
		"constantpool",
		"reflocation",
		"descriptor",
	}

	// Build IJC output
	var ijc bytes.Buffer

	for _, compName := range componentOrder {
		if data, ok := components[compName]; ok {
			ijc.Write(data)
		}
	}

	// Add any other components that might be present (e.g. debug)
	for name, data := range components {
		// Check if name is already in componentOrder
		found := false
		for _, stdName := range componentOrder {
			if name == stdName {
				found = true
				break
			}
		}
		if !found {
			ijc.Write(data)
		}
	}

	result := ijc.Bytes()
	if len(result) == 0 {
		return nil, fmt.Errorf("failed to build IJC: no component data")
	}

	return result, nil
}

// IsIJCFormat checks if the data is in IJC format (starts with proper header)
func IsIJCFormat(data []byte) bool {
	// IJC typically starts with component tag 01 (Header component)
	// followed by component size and DECAFFED magic
	if len(data) < 10 {
		return false
	}

	// Header component starts with tag 01
	if data[0] != 0x01 {
		return false
	}

	// Look for DECAFFED magic (0xDECAFFED) within first 20 bytes
	for i := 0; i < len(data)-4 && i < 20; i++ {
		if data[i] == 0xDE && data[i+1] == 0xCA && data[i+2] == 0xFF && data[i+3] == 0xED {
			return true
		}
	}

	return false
}

// IsCAPFormat checks if the data is in CAP (ZIP) format
func IsCAPFormat(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// ZIP signature: PK (50 4B 03 04)
	return bytes.Equal(data[:4], []byte{0x50, 0x4B, 0x03, 0x04})
}

// GetLoadBlockFormat returns the format of loadBlockObject data
func GetLoadBlockFormat(data []byte) string {
	if IsIJCFormat(data) {
		return "IJC"
	}
	if IsCAPFormat(data) {
		return "CAP/ZIP"
	}
	if len(data) == 0 {
		return "empty"
	}
	return "unknown"
}

