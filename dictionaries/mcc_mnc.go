package dictionaries

import (
	"bufio"
	"bytes"
	"strings"
	"sync"
)

// OperatorInfo contains information about a mobile operator
type OperatorInfo struct {
	MCC      string
	MNC      string
	PLMN     string
	Region   string
	Country  string
	ISO      string
	Operator string
	Brand    string
	TADIG    string
	Bands    string
}

var (
	// mccCountries maps MCC to country name
	mccCountries map[string]string
	// mccMNCOperators maps MCC+MNC to operator info
	mccMNCOperators map[string]*OperatorInfo
	// mccMNCInitOnce ensures initialization happens only once
	mccMNCInitOnce    sync.Once
	mccMNCInitialized bool
)

// initMCCMNCDatabase parses the mcc-mnc.csv file and builds lookup maps
func initMCCMNCDatabase() {
	mccMNCInitOnce.Do(func() {
		data, err := GetMCCMNCData()
		if err != nil {
			return
		}
		mccCountries, mccMNCOperators = parseMCCMNCCSV(data)
		mccMNCInitialized = true
	})
}

// parseMCCMNCCSV parses the CSV file with MCC/MNC data
// Format: csvbase_row_id,MCC,MNC,PLMN,Region,Country,ISO,Operator,Brand,TADIG,Bands
func parseMCCMNCCSV(data []byte) (map[string]string, map[string]*OperatorInfo) {
	countries := make(map[string]string)
	operators := make(map[string]*OperatorInfo)

	scanner := bufio.NewScanner(bytes.NewReader(data))

	// Skip header line (may contain BOM)
	if scanner.Scan() {
		// Header: csvbase_row_id,MCC,MNC,PLMN,Region,Country,ISO,Operator,Brand,TADIG,Bands
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := parseCSVLine(line)

		if len(fields) < 9 {
			continue
		}

		// Fields: 0=csvbase_row_id, 1=MCC, 2=MNC, 3=PLMN, 4=Region, 5=Country, 6=ISO, 7=Operator, 8=Brand, 9=TADIG, 10=Bands
		mcc := strings.TrimSpace(fields[1])
		mnc := strings.TrimSpace(fields[2])

		if mcc == "" {
			continue
		}

		info := &OperatorInfo{
			MCC:      mcc,
			MNC:      mnc,
			PLMN:     getField(fields, 3),
			Region:   getField(fields, 4),
			Country:  getField(fields, 5),
			ISO:      getField(fields, 6),
			Operator: getField(fields, 7),
			Brand:    getField(fields, 8),
			TADIG:    getField(fields, 9),
			Bands:    getField(fields, 10),
		}

		// Map MCC to country (first occurrence wins)
		if _, exists := countries[mcc]; !exists && info.Country != "" {
			countries[mcc] = info.Country
		}

		// Map MCC+MNC to operator info
		key := mcc + mnc
		operators[key] = info
	}

	return countries, operators
}

// parseCSVLine parses a single CSV line, handling quoted fields
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuotes = !inQuotes
		} else if c == ',' && !inQuotes {
			fields = append(fields, current.String())
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}
	fields = append(fields, current.String())

	return fields
}

// getField safely gets a field from slice, returns empty string if index out of bounds
func getField(fields []string, index int) string {
	if index < len(fields) {
		return strings.TrimSpace(fields[index])
	}
	return ""
}

// GetCountry returns the country name for a given MCC
func GetCountry(mcc string) string {
	initMCCMNCDatabase()

	// Normalize MCC (remove leading zeros for lookup, but also try with them)
	if country, ok := mccCountries[mcc]; ok {
		return country
	}

	return ""
}

// GetOperator returns operator and brand names for a given MCC and MNC
func GetOperator(mcc, mnc string) (operator, brand string) {
	initMCCMNCDatabase()

	key := mcc + mnc
	if info, ok := mccMNCOperators[key]; ok {
		return info.Operator, info.Brand
	}

	return "", ""
}

// GetOperatorInfo returns full operator information for a given MCC and MNC
func GetOperatorInfo(mcc, mnc string) *OperatorInfo {
	initMCCMNCDatabase()

	key := mcc + mnc
	if info, ok := mccMNCOperators[key]; ok {
		return info
	}

	return nil
}

// GetOperatorName returns the operator name (brand if available, otherwise operator)
func GetOperatorName(mcc, mnc string) string {
	operator, brand := GetOperator(mcc, mnc)
	if brand != "" {
		return brand
	}
	return operator
}

// IsMCCMNCDatabaseLoaded returns true if the MCC/MNC database was successfully loaded
func IsMCCMNCDatabaseLoaded() bool {
	initMCCMNCDatabase()
	return mccMNCInitialized
}

// GetMCCCountryCount returns the number of unique MCCs in the database
func GetMCCCountryCount() int {
	initMCCMNCDatabase()
	return len(mccCountries)
}

// GetOperatorCount returns the number of operators in the database
func GetOperatorCount() int {
	initMCCMNCDatabase()
	return len(mccMNCOperators)
}

