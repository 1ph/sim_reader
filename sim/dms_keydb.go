package sim

import (
	"fmt"
	"os"
	"strings"
)

// DMSKeyDB is a very small parser for "var_out:" key dump files like DMS72100_decr.out.
// Format:
//
//	var_out: FIELD1/FIELD2/FIELD3/...
//	<row values separated by whitespace>
type DMSKeyDB struct {
	Fields []string
	Rows   []map[string]string
}

func LoadDMSKeyDB(path string) (*DMSKeyDB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")

	var fields []string
	start := -1
	for i, ln := range lines {
		s := strings.TrimSpace(ln)
		if strings.HasPrefix(s, "var_out:") {
			rest := strings.TrimSpace(strings.TrimPrefix(s, "var_out:"))
			if rest == "" {
				return nil, fmt.Errorf("var_out line has no fields")
			}
			fields = strings.Split(rest, "/")
			for j := range fields {
				fields[j] = strings.TrimSpace(fields[j])
			}
			start = i + 1
			break
		}
	}
	if start < 0 || len(fields) == 0 {
		return nil, fmt.Errorf("failed to find var_out header in %s", path)
	}

	db := &DMSKeyDB{Fields: fields}
	for i := start; i < len(lines); i++ {
		ln := strings.TrimSpace(lines[i])
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "var_out:") {
			// support multiple sections; stop at the next header
			break
		}
		cols := strings.Fields(ln)
		if len(cols) < len(fields) {
			// Not enough columns; skip lines that don't look like data rows
			continue
		}
		if len(cols) > len(fields) {
			// Extra columns are unexpected; treat as an error to avoid shifting fields silently.
			return nil, fmt.Errorf("row %d: column count mismatch: got %d values, expected %d", i+1, len(cols), len(fields))
		}
		row := make(map[string]string, len(fields))
		for j, f := range fields {
			row[f] = cols[j]
		}
		db.Rows = append(db.Rows, row)
	}

	if len(db.Rows) == 0 {
		return nil, fmt.Errorf("no rows parsed from %s", path)
	}
	return db, nil
}

func (db *DMSKeyDB) FindByICCID(iccid string) (map[string]string, error) {
	iccid = strings.TrimSpace(iccid)
	if iccid == "" {
		return nil, fmt.Errorf("empty ICCID")
	}
	for _, r := range db.Rows {
		if r["ICCID"] == iccid {
			return r, nil
		}
	}
	return nil, fmt.Errorf("ICCID %s not found in DMS key DB", iccid)
}

func (db *DMSKeyDB) FindByIMSI(imsi string) (map[string]string, error) {
	imsi = strings.TrimSpace(imsi)
	if imsi == "" {
		return nil, fmt.Errorf("empty IMSI")
	}
	for _, r := range db.Rows {
		if r["IMSI"] == imsi {
			return r, nil
		}
	}
	return nil, fmt.Errorf("IMSI %s not found in DMS key DB", imsi)
}

// GPKeysFromDMS extracts a GlobalPlatform SCP keyset from a parsed DMS row.
//
// Supported keyset values:
// - "cm":    ENC=CM_KIC, MAC=CM_KID, DEK=CM_KIK
// - "psk40": ENC=MAC=PSK40_ISD, DEK=PSK40_ISD_DEK
// - "psk41": ENC=MAC=PSK41_ISD, DEK=PSK41_ISD_DEK
// - "a".."h": ENC=KIC_X, MAC=KID_X, DEK=KIK_X (vendor-specific, often OTA but sometimes reused)
func GPKeysFromDMS(row map[string]string, keyset string) (enc []byte, mac []byte, dek []byte, err error) {
	if row == nil {
		return nil, nil, nil, fmt.Errorf("nil row")
	}
	ks := strings.ToLower(strings.TrimSpace(keyset))
	if ks == "" {
		ks = "cm"
	}

	get := func(name string) (string, error) {
		v, ok := row[name]
		if !ok {
			return "", fmt.Errorf("field %s not present in DMS row", name)
		}
		v = strings.TrimSpace(v)
		if v == "" {
			return "", fmt.Errorf("field %s is empty", name)
		}
		return v, nil
	}

	switch ks {
	case "cm":
		encS, e := get("CM_KIC")
		if e != nil {
			return nil, nil, nil, e
		}
		macS, e := get("CM_KID")
		if e != nil {
			return nil, nil, nil, e
		}
		dekS, e := get("CM_KIK")
		if e != nil {
			return nil, nil, nil, e
		}
		enc, err = ParseHexBytes(encS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("CM_KIC: %w", err)
		}
		mac, err = ParseHexBytes(macS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("CM_KID: %w", err)
		}
		dek, err = ParseHexBytes(dekS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("CM_KIK: %w", err)
		}
		return enc, mac, dek, nil

	case "psk40", "40":
		pskS, e := get("PSK40_ISD")
		if e != nil {
			return nil, nil, nil, e
		}
		dekS, e := get("PSK40_ISD_DEK")
		if e != nil {
			return nil, nil, nil, e
		}
		psk, err := ParseHexBytes(pskS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("PSK40_ISD: %w", err)
		}
		dek, err = ParseHexBytes(dekS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("PSK40_ISD_DEK: %w", err)
		}
		return psk, psk, dek, nil

	case "psk41", "41":
		pskS, e := get("PSK41_ISD")
		if e != nil {
			return nil, nil, nil, e
		}
		dekS, e := get("PSK41_ISD_DEK")
		if e != nil {
			return nil, nil, nil, e
		}
		psk, err := ParseHexBytes(pskS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("PSK41_ISD: %w", err)
		}
		dek, err = ParseHexBytes(dekS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("PSK41_ISD_DEK: %w", err)
		}
		return psk, psk, dek, nil

	case "a", "b", "c", "d", "e", "f", "g", "h":
		suf := strings.ToUpper(ks)
		kicS, e := get("KIC_" + suf)
		if e != nil {
			return nil, nil, nil, e
		}
		kidS, e := get("KID_" + suf)
		if e != nil {
			return nil, nil, nil, e
		}
		kikS, e := get("KIK_" + suf)
		if e != nil {
			return nil, nil, nil, e
		}
		enc, err = ParseHexBytes(kicS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("KIC_%s: %w", suf, err)
		}
		mac, err = ParseHexBytes(kidS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("KID_%s: %w", suf, err)
		}
		dek, err = ParseHexBytes(kikS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("KIK_%s: %w", suf, err)
		}
		return enc, mac, dek, nil
	}

	return nil, nil, nil, fmt.Errorf("unknown DMS GP keyset %q (use: cm, psk40, psk41, a..h)", keyset)
}
