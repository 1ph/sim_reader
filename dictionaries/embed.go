// Package dictionaries provides embedded dictionary data for ATR and MCC/MNC lookups.
// Files are embedded at compile time using Go's embed directive.
package dictionaries

import (
	"embed"
)

//go:embed smartcard_list.txt mcc-mnc.csv
var content embed.FS

// GetSmartcardList returns the raw content of smartcard_list.txt
func GetSmartcardList() ([]byte, error) {
	return content.ReadFile("smartcard_list.txt")
}

// GetMCCMNCData returns the raw content of mcc-mnc.csv
func GetMCCMNCData() ([]byte, error) {
	return content.ReadFile("mcc-mnc.csv")
}

