package algorithms

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// Field size constants (in bytes)
const (
	KeyLen128    = 16
	KeyLen256    = 32
	RandLen      = 16
	SQNLen       = 6
	AMFLen       = 2
	AKLen        = 6
	BlockSize128 = 16
	BlockSize256 = 32
	AUTNLen      = 16
)

// Field size constants (in bits) for TUAK
const (
	MACLen64  = 64
	MACLen128 = 128
	MACLen256 = 256

	RESLen32  = 32
	RESLen64  = 64
	RESLen128 = 128
	RESLen256 = 256

	CKLen128 = 128
	CKLen256 = 256

	IKLen128 = 128
	IKLen256 = 256
)

// Validation errors
var (
	ErrInvalidKeyLength  = fmt.Errorf("invalid K length: must be 16 or 32 bytes")
	ErrInvalidTOPLength  = fmt.Errorf("invalid TOP/OP length")
	ErrInvalidTOPCLength = fmt.Errorf("invalid TOPC/OPc length")
	ErrInvalidRANDLength = fmt.Errorf("invalid RAND length: must be 16 bytes")
	ErrInvalidSQNLength  = fmt.Errorf("invalid SQN length: must be 6 bytes")
	ErrInvalidAMFLength  = fmt.Errorf("invalid AMF length: must be 2 bytes")
	ErrInvalidMACLength  = fmt.Errorf("invalid MAC length: must be 64, 128 or 256 bits")
	ErrInvalidRESLength  = fmt.Errorf("invalid RES length: must be 32, 64, 128 or 256 bits")
	ErrInvalidCKLength   = fmt.Errorf("invalid CK length: must be 128 or 256 bits")
	ErrInvalidIKLength   = fmt.Errorf("invalid IK length: must be 128 or 256 bits")
	ErrInvalidAKLength   = fmt.Errorf("invalid AK length: must be 6 bytes")
	ErrInvalidAKF5Length = fmt.Errorf("invalid AK* (f5*) length: must be 6 bytes")
	ErrInvalidMACALength = fmt.Errorf("invalid MAC-A length: must be 8, 16 or 32 bytes")
	ErrInvalidMACSLength = fmt.Errorf("invalid MAC-S length: must be 8, 16 or 32 bytes")
	ErrInvalidAUTNLength = fmt.Errorf("invalid AUTN length: must be 16 bytes")
	ErrInvalidAUTSLength = fmt.Errorf("invalid AUTS length: must be 14, 22 or 38 bytes")
)

// Variables contains input and output parameters for authentication algorithms
type Variables struct {
	// Input parameters
	K    []byte // Subscriber key (128 or 256 bits)
	TOP  []byte // Operator Variant Algorithm Configuration Field
	TOPC []byte // Derived value from TOP and K
	SQN  []byte // Sequence Number (48 bits)
	AMF  []byte // Authentication Management Field (16 bits)
	RAND []byte // Random Challenge (128 bits)

	// Resynchronization parameters
	SQNms  []byte // Sequence Number from MS
	SQNDec uint64 // Decoded SQN
	SQNInc uint64 // Incremented SQN
	Iter   int    // Number of iterations (for TUAK)
	ADD    uint   // Additional parameter

	// Output parameters
	MACA []byte // Network Authentication Code (f1)
	MACS []byte // Resynchronization Authentication Code (f1*)
	RES  []byte // Response (f2)
	XRES []byte // Expected Response
	CK   []byte // Confidentiality Key (f3)
	IK   []byte // Integrity Key (f4)
	AK   []byte // Anonymity Key (f5)
	AKF5 []byte // Anonymity Key from f5*

	// Composite values
	AUTN []byte // Authentication Token
	AUTS []byte // Re-synchronisation Token

	// Length configuration for TUAK (in bits)
	MACLen int
	RESLen int
	CKLen  int
	IKLen  int
}

// AlgorithmSet is the interface for authentication algorithms (Milenage/TUAK)
type AlgorithmSet interface {
	ComputeTOPC(input *Variables) error
	ComputeF1(input *Variables) error
	ComputeF1s(input *Variables) error
	ComputeF2345(input *Variables) error
	ComputeF5s(input *Variables) error
}

// GenerateUSIM extracts SQN, AMF, MAC-A from AUTN using AK
// Required inputs: AK, AUTN
// Outputs: SQN, AMF, MACA
func (v *Variables) GenerateUSIM() error {
	if len(v.AK) != AKLen {
		return ErrInvalidAKLength
	}
	if len(v.AUTN) != AUTNLen {
		return ErrInvalidAUTNLength
	}

	// SQN = (AUTN[0:6] XOR AK)
	v.SQN = XORBytes(v.AUTN[:6], v.AK)[:SQNLen]

	// AMF = AUTN[6:8]
	v.AMF = make([]byte, AMFLen)
	copy(v.AMF, v.AUTN[6:8])

	// MAC-A = AUTN[8:16]
	v.MACA = make([]byte, 8)
	copy(v.MACA, v.AUTN[8:])

	return nil
}

// ComputeAUTN calculates AUTN = (SQN ⊕ AK) || AMF || MAC-A
// Required inputs: SQN, AK, AMF, MACA
// Output: AUTN (16 bytes)
func (v *Variables) ComputeAUTN() error {
	if len(v.SQN) != SQNLen {
		return ErrInvalidSQNLength
	}
	if len(v.AK) != AKLen {
		return ErrInvalidAKLength
	}
	if len(v.AMF) != AMFLen {
		return ErrInvalidAMFLength
	}
	// MAC-A: 64-bit, 128-bit or 256-bit
	if len(v.MACA) != 8 && len(v.MACA) != 16 && len(v.MACA) != 32 {
		return ErrInvalidMACALength
	}

	// AUTN = (SQN XOR AK) || AMF || MAC-A
	auth := XORBytes(v.SQN, v.AK)
	v.AUTN = make([]byte, 0, AUTNLen)
	v.AUTN = append(v.AUTN, auth[:SQNLen]...)
	v.AUTN = append(v.AUTN, v.AMF...)
	v.AUTN = append(v.AUTN, v.MACA[:8]...)

	return nil
}

// ComputeAUTS calculates AUTS = (SQN ⊕ AK*) || MAC-S for resynchronization
// Required inputs: SQN, AKF5 (AK*), MACS
// Output: AUTS (14, 22 or 38 bytes depending on MAC-S length)
func (v *Variables) ComputeAUTS() error {
	if len(v.SQN) != SQNLen {
		return ErrInvalidSQNLength
	}
	if len(v.AKF5) != AKLen {
		return ErrInvalidAKF5Length
	}
	// MAC-S: 64-bit, 128-bit or 256-bit
	if len(v.MACS) != 8 && len(v.MACS) != 16 && len(v.MACS) != 32 {
		return ErrInvalidMACSLength
	}

	// AUTS = (SQN XOR AK*) || MAC-S
	auts := XORBytes(v.SQN, v.AKF5)
	v.AUTS = make([]byte, 0, SQNLen+len(v.MACS))
	v.AUTS = append(v.AUTS, auts[:SQNLen]...)
	v.AUTS = append(v.AUTS, v.MACS...)

	return nil
}

// ComputeSQNms extracts SQN and MAC-S from AUTS using AK* (f5*)
// Required inputs: AKF5 (computed by ComputeF5s), AUTS (from SIM card)
// Outputs: SQNms, MACS
func (v *Variables) ComputeSQNms() error {
	if len(v.AKF5) != AKLen {
		return ErrInvalidAKF5Length
	}
	// AUTS length: 14 (64-bit MAC-S), 22 (128-bit), or 38 (256-bit)
	if len(v.AUTS) != 14 && len(v.AUTS) != 22 && len(v.AUTS) != 38 {
		return ErrInvalidAUTSLength
	}

	// SQNms = AUTS[0:6] XOR AK*
	sqn := v.AUTS[:SQNLen]
	v.SQNms = XORBytes(sqn, v.AKF5)[:SQNLen]

	// MAC-S = AUTS[6:]
	v.MACS = make([]byte, len(v.AUTS)-SQNLen)
	copy(v.MACS, v.AUTS[SQNLen:])

	return nil
}

// ComputeKASME calculates LTE KASME according to 3GPP TS 33.401
// KASME = KDF(CK||IK, FC || SN_ID || L0 || SQN⊕AK || L1)
// where FC = 0x10, SN_ID = PLMN ID (3 bytes), L0 = 0x0003, L1 = 0x0006
// Required inputs: CK, IK, SQN, AK (or AUTN)
func (v *Variables) ComputeKASME(mcc, mnc int) ([]byte, error) {
	if len(v.CK) != KeyLen128 {
		return nil, fmt.Errorf("CK must be 16 bytes, got %d", len(v.CK))
	}
	if len(v.IK) != KeyLen128 {
		return nil, fmt.Errorf("IK must be 16 bytes, got %d", len(v.IK))
	}

	// Build key: CK || IK
	key := make([]byte, 0, 32)
	key = append(key, v.CK...)
	key = append(key, v.IK...)

	// FC = 0x10 (Key derivation for KASME)
	fc := []byte{0x10}

	// P0 = SN_ID (PLMN ID encoded in 3 bytes)
	p0 := encodePLMNInt(mcc, mnc)

	// L0 = length of SN_ID = 0x0003
	l0 := []byte{0x00, 0x03}

	// P1 = SQN XOR AK (use AUTN[0:6] if available, otherwise compute)
	var p1 []byte
	if len(v.AUTN) >= SQNLen {
		p1 = v.AUTN[:SQNLen]
	} else if len(v.SQN) == SQNLen && len(v.AK) == AKLen {
		p1 = XORBytes(v.SQN, v.AK)[:SQNLen]
	} else {
		return nil, fmt.Errorf("either AUTN or both SQN and AK must be set")
	}

	// L1 = length of SQN XOR AK = 0x0006
	l1 := []byte{0x00, 0x06}

	// S = FC || P0 || L0 || P1 || L1
	message := make([]byte, 0, 14)
	message = append(message, fc...)
	message = append(message, p0...)
	message = append(message, l0...)
	message = append(message, p1...)
	message = append(message, l1...)

	// KASME = HMAC-SHA256(CK||IK, S)
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

// Reset clears computed values for reuse
func (v *Variables) Reset() {
	v.MACA = nil
	v.MACS = nil
	v.RES = nil
	v.XRES = nil
	v.CK = nil
	v.IK = nil
	v.AK = nil
	v.AKF5 = nil
	v.AUTN = nil
	v.AUTS = nil
	v.SQNms = nil
}

// encodePLMNInt encodes MCC and MNC into 3-byte PLMN ID format
func encodePLMNInt(mcc, mnc int) []byte {
	plmn := make([]byte, 3)

	// MCC digit 1 (hundreds), digit 2 (tens), digit 3 (ones)
	mccD1 := byte((mcc / 100) % 10)
	mccD2 := byte((mcc / 10) % 10)
	mccD3 := byte(mcc % 10)

	// MNC handling: 2-digit or 3-digit
	var mncD1, mncD2, mncD3 byte
	if mnc == 0 {
		mncD1 = 0
		mncD2 = 0
		mncD3 = 0x0F // filler for 2-digit MNC
	} else if mnc < 100 {
		// 2-digit MNC
		mncD1 = byte(mnc / 10)
		mncD2 = byte(mnc % 10)
		mncD3 = 0x0F // filler
	} else {
		// 3-digit MNC
		mncD1 = byte((mnc / 100) % 10)
		mncD2 = byte((mnc / 10) % 10)
		mncD3 = byte(mnc % 10)
	}

	// PLMN ID encoding: MCC2|MCC1, MNC3|MCC3, MNC2|MNC1
	plmn[0] = (mccD2 << 4) | mccD1
	plmn[1] = (mncD3 << 4) | mccD3
	plmn[2] = (mncD2 << 4) | mncD1

	return plmn
}

// XORBytes performs XOR of two byte slices and returns the result
func XORBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	dst := make([]byte, n)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}

// reverseBytes returns a copy of the slice in reverse order
func reverseBytes(src []byte) []byte {
	n := len(src)
	dst := make([]byte, n)
	for i := 0; i < n; i++ {
		dst[i] = src[n-1-i]
	}
	return dst
}

// xorBytes performs XOR of two byte slices (internal use)
func xorBytes(a, b []byte) []byte {
	return XORBytes(a, b)
}

// GenerateTriplets generates 2G triplets (SRES, Kc) from 3G/4G quintuplets
// This is used for backward compatibility with GSM/2G networks
// According to 3GPP TS 33.102 Annex C
//
// SRES (4 bytes) is derived from RES by XORing 4-byte blocks
// Kc (8 bytes) is derived from CK and IK by XORing 8-byte blocks
//
// Required inputs: RES (4-16 bytes), CK (16 bytes), IK (16 bytes)
// Outputs: SRES (4 bytes), Kc (8 bytes)
func (v *Variables) GenerateTriplets() (sres []byte, kc []byte) {
	// Derive SRES from RES
	// SRES = RES[0:4] XOR RES[4:8] XOR RES[8:12] XOR RES[12:16]
	switch {
	case len(v.RES) <= 4:
		sres = make([]byte, len(v.RES))
		copy(sres, v.RES)
	case len(v.RES) <= 8:
		sres = XORBytes(v.RES[:4], v.RES[4:])
	case len(v.RES) <= 12:
		sres = XORBytes(XORBytes(v.RES[:4], v.RES[4:8]), v.RES[8:])
	default:
		sres = XORBytes(XORBytes(XORBytes(v.RES[:4], v.RES[4:8]), v.RES[8:12]), v.RES[12:])
	}

	// Derive Kc from CK and IK
	// Kc = CK[0:8] XOR CK[8:16] XOR IK[0:8] XOR IK[8:16]
	if len(v.CK) == KeyLen128 && len(v.IK) == KeyLen128 {
		kc = XORBytes(
			XORBytes(XORBytes(v.CK[:8], v.CK[8:]), v.IK[:8]),
			v.IK[8:],
		)
	}

	// Ensure correct output lengths
	if len(sres) >= 4 {
		sres = sres[:4]
	}
	if len(kc) >= 8 {
		kc = kc[:8]
	}

	return sres, kc
}
