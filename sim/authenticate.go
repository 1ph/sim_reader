package sim

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"sim_reader/algorithms"
	"sim_reader/card"
)

// AlgorithmType represents the authentication algorithm type
type AlgorithmType string

const (
	AlgorithmMilenage AlgorithmType = "milenage"
	AlgorithmTUAK     AlgorithmType = "tuak"
)

// AuthConfig contains authentication parameters
type AuthConfig struct {
	// Input parameters
	K         []byte        // Subscriber key (16 or 32 bytes)
	OP        []byte        // Operator key (for computing OPc)
	OPc       []byte        // Precomputed OPc (if OP not provided)
	SQN       []byte        // Sequence number (6 bytes)
	AMF       []byte        // Authentication Management Field (2 bytes)
	RAND      []byte        // Random challenge (16 bytes) - auto-generated if nil
	Algorithm AlgorithmType // Algorithm type (milenage or tuak)
	MCC       int           // Mobile Country Code (for KASME)
	MNC       int           // Mobile Network Code (for KASME)

	// Pre-computed values (from dump, skip calculation)
	AUTN []byte // Pre-computed AUTN (16 bytes) - skip calculation if provided
	AUTS []byte // AUTS from SIM card (for SQN resync) - 14, 22 or 38 bytes

	// TUAK specific parameters
	Iterations int // Number of Keccak iterations (default: 1)
	MACLen     int // MAC length in bits (64, 128, 256)
	RESLen     int // RES length in bits (32, 64, 128, 256)
	CKLen      int // CK length in bits (128, 256)
	IKLen      int // IK length in bits (128, 256)
}

// AuthResult contains authentication results
type AuthResult struct {
	// Input echo
	K    string `json:"k"`
	OP   string `json:"op,omitempty"` // OP if provided (before computing OPc)
	OPc  string `json:"opc"`
	RAND string `json:"rand"`
	SQN  string `json:"sqn"`
	AMF  string `json:"amf"`

	// Mode indicators
	CardOnlyMode bool `json:"card_only_mode,omitempty"` // AUTN provided without K - just send to card
	AUTNFromDump bool `json:"autn_from_dump,omitempty"` // AUTN was provided, not calculated
	AUTSFromDump bool `json:"auts_from_dump,omitempty"` // AUTS was provided for resync

	// Computed values (network side)
	MACA string `json:"mac_a"`
	XRES string `json:"xres"`
	CK   string `json:"ck"`
	IK   string `json:"ik"`
	AK   string `json:"ak"`
	AUTN string `json:"autn"`

	// SIM card response
	RES      string `json:"res,omitempty"`
	CardCK   string `json:"card_ck,omitempty"`
	CardIK   string `json:"card_ik,omitempty"`
	AUTS     string `json:"auts,omitempty"`
	SyncFail bool   `json:"sync_fail,omitempty"`

	// Resync results (if AUTS received)
	SQNms string `json:"sqn_ms,omitempty"`
	MACS  string `json:"mac_s,omitempty"`
	AKF5  string `json:"ak_f5,omitempty"`

	// Derived keys
	KASME string `json:"kasme,omitempty"`
	SRES  string `json:"sres,omitempty"` // 2G triplet
	Kc    string `json:"kc,omitempty"`   // 2G triplet

	// Verification
	MACMatch bool   `json:"mac_match,omitempty"`
	RESMatch bool   `json:"res_match,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ParseAuthConfig parses authentication parameters from command line strings
func ParseAuthConfig(
	kStr, opStr, opcStr, sqnStr, amfStr, randStr string,
	autnStr, autsStr string,
	algorithm string,
	mcc, mnc int,
) (*AuthConfig, error) {
	cfg := &AuthConfig{
		Algorithm:  AlgorithmType(strings.ToLower(algorithm)),
		MCC:        mcc,
		MNC:        mnc,
		Iterations: 1,
		MACLen:     algorithms.MACLen64,
		RESLen:     algorithms.RESLen64,
		CKLen:      algorithms.CKLen128,
		IKLen:      algorithms.IKLen128,
	}

	// Parse K (optional if AUTN is provided - card-only mode)
	if kStr != "" {
		k, err := algorithms.ValidateKi(kStr)
		if err != nil {
			return nil, fmt.Errorf("invalid K format: %w", err)
		}
		cfg.K = k
	}

	// Parse OP or OPc (optional if AUTN is provided - card-only mode)
	if opStr != "" {
		op, err := algorithms.ValidateOPc(opStr) // OP has same format as OPc/Ki
		if err != nil {
			return nil, fmt.Errorf("invalid OP format: %w", err)
		}
		cfg.OP = op
	}
	if opcStr != "" {
		opc, err := algorithms.ValidateOPc(opcStr)
		if err != nil {
			return nil, fmt.Errorf("invalid OPc format: %w", err)
		}
		cfg.OPc = opc
	}

	// Parse SQN (required, 6 bytes or 12 hex chars)
	if sqnStr == "" {
		// Default SQN
		cfg.SQN = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	} else {
		sqn, err := hex.DecodeString(strings.ReplaceAll(sqnStr, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("invalid SQN format: %w", err)
		}
		if len(sqn) != 6 {
			return nil, fmt.Errorf("SQN must be 6 bytes, got %d", len(sqn))
		}
		cfg.SQN = sqn
	}

	// Parse AMF (optional, default 0x8000 for LTE)
	if amfStr == "" {
		cfg.AMF = []byte{0x80, 0x00} // Default for LTE
	} else {
		amf, err := hex.DecodeString(strings.ReplaceAll(amfStr, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("invalid AMF format: %w", err)
		}
		if len(amf) != 2 {
			return nil, fmt.Errorf("AMF must be 2 bytes, got %d", len(amf))
		}
		cfg.AMF = amf
	}

	// Parse RAND (optional, auto-generate if not provided)
	if randStr != "" {
		randBytes, err := hex.DecodeString(strings.ReplaceAll(randStr, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("invalid RAND format: %w", err)
		}
		if len(randBytes) != 16 {
			return nil, fmt.Errorf("RAND must be 16 bytes, got %d", len(randBytes))
		}
		cfg.RAND = randBytes
	}

	// Parse AUTN (optional, use pre-computed AUTN instead of calculating)
	if autnStr != "" {
		autn, err := hex.DecodeString(strings.ReplaceAll(autnStr, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("invalid AUTN format: %w", err)
		}
		if len(autn) != 16 {
			return nil, fmt.Errorf("AUTN must be 16 bytes, got %d", len(autn))
		}
		cfg.AUTN = autn
	}

	// Parse AUTS (optional, for SQN resynchronization from dump)
	if autsStr != "" {
		auts, err := hex.DecodeString(strings.ReplaceAll(autsStr, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("invalid AUTS format: %w", err)
		}
		// AUTS length: 14 (64-bit MAC-S), 22 (128-bit), or 38 (256-bit)
		if len(auts) != 14 && len(auts) != 22 && len(auts) != 38 {
			return nil, fmt.Errorf("AUTS must be 14, 22 or 38 bytes, got %d", len(auts))
		}
		cfg.AUTS = auts
	}

	// Validation: either K+OP/OPc for full mode, or AUTN for card-only mode
	cardOnlyMode := len(cfg.AUTN) == 16 && len(cfg.K) == 0
	if !cardOnlyMode {
		// Full mode requires K and OP/OPc
		if len(cfg.K) == 0 {
			return nil, fmt.Errorf("K (subscriber key) is required (or provide -auth-autn for card-only mode)")
		}
		if cfg.OP == nil && cfg.OPc == nil {
			return nil, fmt.Errorf("either OP or OPc is required (or provide -auth-autn for card-only mode)")
		}
	}

	return cfg, nil
}

// GenerateRAND generates a cryptographically secure 16-byte random value
func GenerateRAND() ([]byte, error) {
	randBytes := make([]byte, 16)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RAND: %w", err)
	}
	return randBytes, nil
}

// runCardOnlyAuth handles card-only mode: send RAND+AUTN to card without K
// This mode is used when you have pre-captured RAND and AUTN from a dump
// and just want to send them to the card to get the response
func runCardOnlyAuth(reader *card.Reader, cfg *AuthConfig) (*AuthResult, error) {
	result := &AuthResult{
		CardOnlyMode: true,
		RAND:         strings.ToUpper(hex.EncodeToString(cfg.RAND)),
		AUTN:         strings.ToUpper(hex.EncodeToString(cfg.AUTN)),
	}

	if reader == nil {
		return nil, fmt.Errorf("card-only mode requires a card reader (remove -auth-no-card)")
	}

	// Select USIM ADF first
	if err := selectUSIMADF(reader); err != nil {
		result.Error = fmt.Sprintf("Failed to select USIM: %v", err)
		return result, nil
	}

	// Send AUTHENTICATE command
	authResult, err := reader.Authenticate(cfg.RAND, cfg.AUTN, card.AUTH_CONTEXT_3G)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	if len(authResult.AUTS) > 0 {
		// Sync failure
		result.SyncFail = true
		result.AUTS = strings.ToUpper(hex.EncodeToString(authResult.AUTS))
	} else if authResult.Success {
		// Success - store card response
		result.RES = strings.ToUpper(hex.EncodeToString(authResult.RES))
		if authResult.CK != nil {
			result.CardCK = strings.ToUpper(hex.EncodeToString(authResult.CK))
		}
		if authResult.IK != nil {
			result.CardIK = strings.ToUpper(hex.EncodeToString(authResult.IK))
		}
	}

	return result, nil
}

// RunAuthentication performs the complete authentication flow
func RunAuthentication(reader *card.Reader, cfg *AuthConfig) (*AuthResult, error) {
	result := &AuthResult{}

	// Check for card-only mode (AUTN provided without K)
	cardOnlyMode := len(cfg.AUTN) == 16 && len(cfg.K) == 0
	if cardOnlyMode {
		return runCardOnlyAuth(reader, cfg)
	}

	// Generate RAND if not provided
	if cfg.RAND == nil {
		randBytes, err := GenerateRAND()
		if err != nil {
			return nil, err
		}
		cfg.RAND = randBytes
	}

	// Initialize algorithm variables
	v := &algorithms.Variables{
		K:    cfg.K,
		RAND: cfg.RAND,
		SQN:  cfg.SQN,
		AMF:  cfg.AMF,
	}

	// Set TUAK-specific parameters
	if cfg.Algorithm == AlgorithmTUAK {
		v.Iter = cfg.Iterations
		if v.Iter == 0 {
			v.Iter = 1
		}
		v.MACLen = cfg.MACLen
		if v.MACLen == 0 {
			v.MACLen = algorithms.MACLen64
		}
		v.RESLen = cfg.RESLen
		if v.RESLen == 0 {
			v.RESLen = algorithms.RESLen64
		}
		v.CKLen = cfg.CKLen
		if v.CKLen == 0 {
			v.CKLen = algorithms.CKLen128
		}
		v.IKLen = cfg.IKLen
		if v.IKLen == 0 {
			v.IKLen = algorithms.IKLen128
		}
	}

	// Get algorithm implementation
	var algo algorithms.AlgorithmSet
	switch cfg.Algorithm {
	case AlgorithmTUAK:
		algo = algorithms.NewTUAK()
		// Set TOP/TOPC for TUAK (32 bytes)
		if cfg.OPc != nil {
			if len(cfg.OPc) != 32 {
				return nil, fmt.Errorf("TUAK OPc must be 32 bytes, got %d", len(cfg.OPc))
			}
			v.TOPC = cfg.OPc
		} else if cfg.OP != nil {
			if len(cfg.OP) != 32 {
				return nil, fmt.Errorf("TUAK OP must be 32 bytes, got %d", len(cfg.OP))
			}
			v.TOP = cfg.OP
			if err := algo.ComputeTOPC(v); err != nil {
				return nil, fmt.Errorf("failed to compute TOPc: %w", err)
			}
		}
	default:
		algo = algorithms.NewMilenage()
		// Set OP/OPc for Milenage (16 bytes)
		if cfg.OPc != nil {
			if len(cfg.OPc) != 16 {
				return nil, fmt.Errorf("Milenage OPc must be 16 bytes, got %d", len(cfg.OPc))
			}
			v.TOPC = cfg.OPc
		} else if cfg.OP != nil {
			if len(cfg.OP) != 16 {
				return nil, fmt.Errorf("Milenage OP must be 16 bytes, got %d", len(cfg.OP))
			}
			v.TOP = cfg.OP
			if err := algo.ComputeTOPC(v); err != nil {
				return nil, fmt.Errorf("failed to compute OPc: %w", err)
			}
		}
	}

	// Store input values in result
	result.K = strings.ToUpper(hex.EncodeToString(v.K))
	if len(cfg.OP) > 0 {
		result.OP = strings.ToUpper(hex.EncodeToString(cfg.OP))
	}
	result.OPc = strings.ToUpper(hex.EncodeToString(v.TOPC))
	result.RAND = strings.ToUpper(hex.EncodeToString(v.RAND))
	result.SQN = strings.ToUpper(hex.EncodeToString(v.SQN))
	result.AMF = strings.ToUpper(hex.EncodeToString(v.AMF))

	// Check if we have AUTS from dump to process (resync mode)
	if len(cfg.AUTS) > 0 {
		result.AUTSFromDump = true
		result.SyncFail = true
		result.AUTS = strings.ToUpper(hex.EncodeToString(cfg.AUTS))

		// Compute f5* to get AK*
		if err := algo.ComputeF5s(v); err != nil {
			return nil, fmt.Errorf("failed to compute f5*: %w", err)
		}
		result.AKF5 = strings.ToUpper(hex.EncodeToString(v.AKF5))

		// Extract SQNms from AUTS
		v.AUTS = cfg.AUTS
		if err := v.ComputeSQNms(); err != nil {
			return nil, fmt.Errorf("failed to extract SQNms: %w", err)
		}
		result.SQNms = strings.ToUpper(hex.EncodeToString(v.SQNms))
		result.MACS = strings.ToUpper(hex.EncodeToString(v.MACS))

		// Also compute f2345 for derived keys
		if err := algo.ComputeF2345(v); err != nil {
			return nil, fmt.Errorf("failed to compute f2345: %w", err)
		}
		result.CK = strings.ToUpper(hex.EncodeToString(v.CK))
		result.IK = strings.ToUpper(hex.EncodeToString(v.IK))

		return result, nil
	}

	// Check if we have pre-computed AUTN from dump (skip calculation)
	usePrecomputedAUTN := len(cfg.AUTN) == 16

	if !usePrecomputedAUTN {
		// Compute f1 (MAC-A)
		if err := algo.ComputeF1(v); err != nil {
			return nil, fmt.Errorf("failed to compute f1 (MAC-A): %w", err)
		}
		result.MACA = strings.ToUpper(hex.EncodeToString(v.MACA))
	}

	// Compute f2, f3, f4, f5 (RES, CK, IK, AK)
	if err := algo.ComputeF2345(v); err != nil {
		return nil, fmt.Errorf("failed to compute f2345: %w", err)
	}
	result.XRES = strings.ToUpper(hex.EncodeToString(v.RES))
	result.CK = strings.ToUpper(hex.EncodeToString(v.CK))
	result.IK = strings.ToUpper(hex.EncodeToString(v.IK))
	result.AK = strings.ToUpper(hex.EncodeToString(v.AK))

	// Use pre-computed AUTN or compute it
	if usePrecomputedAUTN {
		result.AUTNFromDump = true
		v.AUTN = cfg.AUTN
		result.AUTN = strings.ToUpper(hex.EncodeToString(cfg.AUTN))
		// Extract components from pre-computed AUTN using GenerateUSIM
		if err := v.GenerateUSIM(); err != nil {
			return nil, fmt.Errorf("failed to parse AUTN: %w", err)
		}
		result.MACA = strings.ToUpper(hex.EncodeToString(v.MACA))
		result.SQN = strings.ToUpper(hex.EncodeToString(v.SQN))
		result.AMF = strings.ToUpper(hex.EncodeToString(v.AMF))
	} else {
		// Compute AUTN
		if err := v.ComputeAUTN(); err != nil {
			return nil, fmt.Errorf("failed to compute AUTN: %w", err)
		}
		result.AUTN = strings.ToUpper(hex.EncodeToString(v.AUTN))
	}

	// If we have a reader, send AUTHENTICATE to the card
	if reader != nil {
		// Select USIM ADF first
		if err := selectUSIMADF(reader); err != nil {
			result.Error = fmt.Sprintf("Failed to select USIM: %v", err)
		} else {
			// Send AUTHENTICATE command
			authResult, err := reader.Authenticate(v.RAND, v.AUTN, card.AUTH_CONTEXT_3G)
			if err != nil {
				result.Error = err.Error()
			} else if len(authResult.AUTS) > 0 {
				// Sync failure - need to process AUTS
				result.SyncFail = true
				result.AUTS = strings.ToUpper(hex.EncodeToString(authResult.AUTS))

				// Compute f5* to get AK*
				if err := algo.ComputeF5s(v); err != nil {
					result.Error = fmt.Sprintf("Failed to compute f5*: %v", err)
				} else {
					result.AKF5 = strings.ToUpper(hex.EncodeToString(v.AKF5))

					// Extract SQNms from AUTS
					v.AUTS = authResult.AUTS
					if err := v.ComputeSQNms(); err != nil {
						result.Error = fmt.Sprintf("Failed to extract SQNms: %v", err)
					} else {
						result.SQNms = strings.ToUpper(hex.EncodeToString(v.SQNms))
						result.MACS = strings.ToUpper(hex.EncodeToString(v.MACS))
					}
				}
			} else if authResult.Success {
				// Success - store card response
				result.RES = strings.ToUpper(hex.EncodeToString(authResult.RES))
				if authResult.CK != nil {
					result.CardCK = strings.ToUpper(hex.EncodeToString(authResult.CK))
				}
				if authResult.IK != nil {
					result.CardIK = strings.ToUpper(hex.EncodeToString(authResult.IK))
				}

				// Verify RES matches XRES
				result.RESMatch = (result.RES == result.XRES)
			}
		}
	}

	// Compute KASME for LTE
	if cfg.MCC > 0 && cfg.MNC >= 0 {
		kasme, err := v.ComputeKASME(cfg.MCC, cfg.MNC)
		if err == nil {
			result.KASME = strings.ToUpper(hex.EncodeToString(kasme))
		}
	}

	// Generate 2G triplets
	sres, kc := v.GenerateTriplets()
	if len(sres) > 0 {
		result.SRES = strings.ToUpper(hex.EncodeToString(sres))
	}
	if len(kc) > 0 {
		result.Kc = strings.ToUpper(hex.EncodeToString(kc))
	}

	return result, nil
}

// selectUSIMADF selects the USIM application
func selectUSIMADF(reader *card.Reader) error {
	// Try to use detected AID first
	aid := GetUSIMAID()
	if aid != nil {
		resp, err := reader.Select(aid)
		if err != nil {
			return err
		}
		if resp.IsOK() || resp.HasMoreData() {
			return nil
		}
	}

	// Try standard USIM AID
	standardAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x89}
	resp, err := reader.Select(standardAID[:7]) // Try partial AID
	if err != nil {
		return err
	}
	if resp.IsOK() || resp.HasMoreData() {
		return nil
	}

	return fmt.Errorf("failed to select USIM application")
}

// IncrementSQN increments the SQN value by 1
func IncrementSQN(sqn []byte) []byte {
	if len(sqn) != 6 {
		return sqn
	}

	// Convert to uint64, increment, convert back
	sqnVal := uint64(0)
	for i := 0; i < 6; i++ {
		sqnVal = (sqnVal << 8) | uint64(sqn[i])
	}
	sqnVal++

	newSQN := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		newSQN[i] = byte(sqnVal & 0xFF)
		sqnVal >>= 8
	}
	return newSQN
}

// SQNToUint64 converts 6-byte SQN to uint64
func SQNToUint64(sqn []byte) uint64 {
	if len(sqn) != 6 {
		return 0
	}
	var result uint64
	for i := 0; i < 6; i++ {
		result = (result << 8) | uint64(sqn[i])
	}
	return result
}

// Uint64ToSQN converts uint64 to 6-byte SQN
func Uint64ToSQN(val uint64) []byte {
	sqn := make([]byte, 6)
	binary.BigEndian.PutUint16(sqn[0:2], uint16(val>>32))
	binary.BigEndian.PutUint32(sqn[2:6], uint32(val))
	return sqn
}

// IncrementSQNHex increments a hex-encoded SQN string by 1
func IncrementSQNHex(sqnHex string) string {
	sqn, err := hex.DecodeString(sqnHex)
	if err != nil || len(sqn) != 6 {
		return sqnHex
	}
	newSQN := IncrementSQN(sqn)
	return strings.ToUpper(hex.EncodeToString(newSQN))
}

// ProcessAUTS handles AUTS resynchronization
// Returns the new SQN value from the SIM card
func ProcessAUTS(cfg *AuthConfig, auts []byte) (*AuthResult, error) {
	result := &AuthResult{
		SyncFail: true,
		AUTS:     strings.ToUpper(hex.EncodeToString(auts)),
	}

	// Initialize algorithm
	v := &algorithms.Variables{
		K:    cfg.K,
		RAND: cfg.RAND,
		AUTS: auts,
	}

	var algo algorithms.AlgorithmSet
	switch cfg.Algorithm {
	case AlgorithmTUAK:
		algo = algorithms.NewTUAK()
		v.TOPC = cfg.OPc
		v.Iter = cfg.Iterations
		v.MACLen = cfg.MACLen
		v.RESLen = cfg.RESLen
		v.CKLen = cfg.CKLen
		v.IKLen = cfg.IKLen
	default:
		algo = algorithms.NewMilenage()
		v.TOPC = cfg.OPc
	}

	// Compute f5* to get AK*
	if err := algo.ComputeF5s(v); err != nil {
		return nil, fmt.Errorf("failed to compute f5*: %w", err)
	}
	result.AKF5 = strings.ToUpper(hex.EncodeToString(v.AKF5))

	// Extract SQNms from AUTS
	if err := v.ComputeSQNms(); err != nil {
		return nil, fmt.Errorf("failed to extract SQNms: %w", err)
	}
	result.SQNms = strings.ToUpper(hex.EncodeToString(v.SQNms))
	result.MACS = strings.ToUpper(hex.EncodeToString(v.MACS))

	return result, nil
}
