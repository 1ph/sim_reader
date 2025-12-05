package dictionaries

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
	"sync"
)

// ATREntry represents a single ATR pattern with its descriptions
type ATREntry struct {
	Pattern      string         // Original pattern from file
	Regex        *regexp.Regexp // Compiled regex for matching
	Descriptions []string       // Card descriptions
}

var (
	atrEntries     []ATREntry
	atrInitOnce    sync.Once
	atrInitialized bool
)

// initATRDatabase parses the smartcard_list.txt file and builds the lookup database
func initATRDatabase() {
	atrInitOnce.Do(func() {
		data, err := GetSmartcardList()
		if err != nil {
			return
		}
		atrEntries = parseSmartcardList(data)
		atrInitialized = true
	})
}

// parseSmartcardList parses the smartcard_list.txt format:
// - Lines starting with # are comments
// - ATR pattern is a hex string with spaces, .. means any byte
// - Lines starting with \t are descriptions for the previous ATR
// - Empty lines separate entries
func parseSmartcardList(data []byte) []ATREntry {
	var entries []ATREntry
	var currentEntry *ATREntry

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Empty line - finalize current entry
		if strings.TrimSpace(line) == "" {
			if currentEntry != nil && len(currentEntry.Descriptions) > 0 {
				entries = append(entries, *currentEntry)
			}
			currentEntry = nil
			continue
		}

		// Description line (starts with tab)
		if strings.HasPrefix(line, "\t") {
			if currentEntry != nil {
				desc := strings.TrimSpace(line)
				if desc != "" {
					currentEntry.Descriptions = append(currentEntry.Descriptions, desc)
				}
			}
			continue
		}

		// ATR pattern line
		pattern := strings.TrimSpace(line)
		if pattern != "" {
			regex := atrPatternToRegex(pattern)
			if regex != nil {
				currentEntry = &ATREntry{
					Pattern:      pattern,
					Regex:        regex,
					Descriptions: nil,
				}
			}
		}
	}

	// Don't forget the last entry
	if currentEntry != nil && len(currentEntry.Descriptions) > 0 {
		entries = append(entries, *currentEntry)
	}

	return entries
}

// atrPatternToRegex converts ATR pattern to regex
// Pattern format: "3B 02 14 50" or "3B .. .. 41" where .. is wildcard
func atrPatternToRegex(pattern string) *regexp.Regexp {
	// Remove spaces and convert to uppercase
	pattern = strings.ToUpper(strings.ReplaceAll(pattern, " ", ""))

	// Replace .. with [0-9A-F]{2} for any byte
	var regexStr strings.Builder
	regexStr.WriteString("^")

	i := 0
	for i < len(pattern) {
		if i+1 < len(pattern) && pattern[i] == '.' && pattern[i+1] == '.' {
			regexStr.WriteString("[0-9A-F]{2}")
			i += 2
		} else {
			// Escape special regex characters if needed
			c := pattern[i]
			if c == '.' || c == '*' || c == '+' || c == '?' || c == '[' || c == ']' || c == '(' || c == ')' || c == '{' || c == '}' || c == '|' || c == '^' || c == '$' || c == '\\' {
				regexStr.WriteByte('\\')
			}
			regexStr.WriteByte(c)
			i++
		}
	}

	regexStr.WriteString("$")

	regex, err := regexp.Compile(regexStr.String())
	if err != nil {
		return nil
	}
	return regex
}

// LookupATR looks up an ATR in the database and returns matching descriptions
// Returns nil if no match found
func LookupATR(atr string) []string {
	initATRDatabase()

	// Normalize ATR: uppercase, no spaces
	atr = strings.ToUpper(strings.ReplaceAll(atr, " ", ""))

	for _, entry := range atrEntries {
		if entry.Regex != nil && entry.Regex.MatchString(atr) {
			return entry.Descriptions
		}
	}

	return nil
}

// LookupATRFirst looks up an ATR and returns the first description
// Returns empty string if no match found
func LookupATRFirst(atr string) string {
	descriptions := LookupATR(atr)
	if len(descriptions) > 0 {
		return descriptions[0]
	}
	return ""
}

// IsATRDatabaseLoaded returns true if the ATR database was successfully loaded
func IsATRDatabaseLoaded() bool {
	initATRDatabase()
	return atrInitialized
}

// GetATREntryCount returns the number of ATR entries in the database
func GetATREntryCount() int {
	initATRDatabase()
	return len(atrEntries)
}

