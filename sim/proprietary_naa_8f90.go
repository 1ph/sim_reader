package sim

import (
	"errors"
	"fmt"

	"sim_reader/card"
)

// ErrNotSupported is returned when a proprietary operation is not supported by the current card.
var ErrNotSupported = errors.New("not supported by this card")

// Proprietary USIM security (OX24/RuSIM style) files used in this profile:
//   - EF 8F90: Authentication algorithm selector (NAA)
//     0x1F = MILENAGE, 0x2E = S3G-128, 0x3D = TUAK, 0x4C = S3G-256
const (
	NAA_MILENAGE byte = 0x1F
	NAA_S3G_128  byte = 0x2E
	NAA_TUAK     byte = 0x3D
	NAA_S3G_256  byte = 0x4C
)

// SupportsProprietaryNAA returns true if this card type is expected to support EF 8F90.
// We intentionally keep this conservative to avoid touching unrelated vendor cards.
func SupportsProprietaryNAA(atrHex string) bool {
	// Today we treat "proprietary" == OX24/RuSIM-like family used in these profiles.
	// If you later add new families, extend this check with additional ATR prefixes.
	return IsProprietaryCard(atrHex)
}

// USIMAuthAlgoName maps algorithm byte to a human-readable name.
func USIMAuthAlgoName(b byte) string {
	switch b {
	case NAA_MILENAGE:
		return "milenage"
	case NAA_S3G_128:
		return "s3g-128"
	case NAA_TUAK:
		return "tuak"
	case NAA_S3G_256:
		return "s3g-256"
	default:
		return fmt.Sprintf("unknown(0x%02X)", b)
	}
}

// ParseUSIMAuthAlgo parses algorithm name to NAA byte.
func ParseUSIMAuthAlgo(s string) (byte, error) {
	switch toLower(trimSpace(s)) {
	case "milenage", "naa_milenage", "1f", "0x1f":
		return NAA_MILENAGE, nil
	case "s3g-128", "s3g128", "s3g_128", "naa_s3g_128", "2e", "0x2e":
		return NAA_S3G_128, nil
	case "tuak", "naa_tuak", "3d", "0x3d":
		return NAA_TUAK, nil
	case "s3g-256", "s3g256", "s3g_256", "naa_s3g_256", "4c", "0x4c":
		return NAA_S3G_256, nil
	default:
		return 0, fmt.Errorf("unknown algorithm: %s (use: milenage, s3g-128, tuak, s3g-256)", s)
	}
}

// ReadUSIMAuthAlgorithm reads EF 8F90 (NAA algorithm selector) from USIM ADF.
// This is a proprietary extension used by OX24/RuSIM-like cards.
func ReadUSIMAuthAlgorithm(reader *card.Reader) (byte, error) {
	if reader == nil {
		return 0, fmt.Errorf("nil reader")
	}
	if !SupportsProprietaryNAA(reader.ATRHex()) {
		return 0, ErrNotSupported
	}

	// Select USIM with proper fallback and re-auth
	if _, err := SelectUSIMWithAuth(reader); err != nil {
		return 0, err
	}

	// Select EF 8F90
	var resp *card.APDUResponse
	var err error
	if UseGSMCommands {
		resp, err = reader.SelectGSM([]byte{0x8F, 0x90})
	} else {
		resp, err = reader.Select([]byte{0x8F, 0x90})
	}
	if err != nil {
		return 0, fmt.Errorf("select EF 8F90 failed: %w", err)
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		return 0, fmt.Errorf("select EF 8F90 failed: %s", card.SWToString(resp.SW()))
	}

	// Read 1 byte
	if UseGSMCommands {
		resp, err = reader.ReadBinaryGSM(0, 1)
	} else {
		resp, err = reader.ReadBinary(0, 1)
	}
	if err != nil {
		return 0, fmt.Errorf("read EF 8F90 failed: %w", err)
	}
	if !resp.IsOK() {
		return 0, fmt.Errorf("read EF 8F90 failed: %s", card.SWToString(resp.SW()))
	}
	if len(resp.Data) < 1 {
		return 0, fmt.Errorf("read EF 8F90 returned empty data")
	}
	return resp.Data[0], nil
}

// SetUSIMAuthAlgorithm writes EF 8F90 (NAA algorithm selector) in USIM ADF.
// Requires sufficient ADM access for this EF on the target card.
// This is a proprietary extension used by OX24/RuSIM-like cards.
func SetUSIMAuthAlgorithm(reader *card.Reader, algo byte) error {
	if reader == nil {
		return fmt.Errorf("nil reader")
	}
	if !SupportsProprietaryNAA(reader.ATRHex()) {
		return ErrNotSupported
	}

	// Select USIM with proper fallback and re-auth
	if _, err := SelectUSIMWithAuth(reader); err != nil {
		return err
	}

	// Select EF 8F90
	var resp *card.APDUResponse
	var err error
	if UseGSMCommands {
		resp, err = reader.SelectGSM([]byte{0x8F, 0x90})
	} else {
		resp, err = reader.Select([]byte{0x8F, 0x90})
	}
	if err != nil {
		return fmt.Errorf("select EF 8F90 failed: %w", err)
	}
	if !resp.IsOK() && !resp.HasMoreData() {
		return fmt.Errorf("select EF 8F90 failed: %s", card.SWToString(resp.SW()))
	}

	// Write 1 byte at offset 0
	if UseGSMCommands {
		resp, err = reader.UpdateBinaryGSM(0, []byte{algo})
	} else {
		resp, err = reader.UpdateBinary(0, []byte{algo})
	}
	if err != nil {
		return fmt.Errorf("update EF 8F90 failed: %w", err)
	}
	if !resp.IsOK() {
		return fmt.Errorf("update EF 8F90 failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

// SetUSIMAuthAlgorithmFromString parses and sets EF 8F90.
func SetUSIMAuthAlgorithmFromString(reader *card.Reader, algoName string) (byte, error) {
	algo, err := ParseUSIMAuthAlgo(algoName)
	if err != nil {
		return 0, err
	}
	if err := SetUSIMAuthAlgorithm(reader, algo); err != nil {
		return 0, err
	}
	return algo, nil
}
