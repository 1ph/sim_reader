package algorithms

// TUAK algorithm implementation
// Based on 3GPP TS 35.231 version 12.1.0 Release 12
//
// Algorithm parameters:
// AK       - 48-bit anonymity key (output of f5 or f5*)
// AMF      - 16-bit authentication management field (input to f1 and f1*)
// CK       - 128-bit or 256-bit confidentiality key (output of f3)
// IK       - 128-bit or 256-bit integrity key (output of f4)
// K        - 128-bit or 256-bit subscriber key
// MAC-A    - 64-bit, 128-bit or 256-bit network authentication code (output of f1)
// MAC-S    - 64-bit, 128-bit or 256-bit resynchronisation authentication code (output of f1*)
// RAND     - 128-bit random challenge
// RES      - 32-bit, 64-bit, 128-bit or 256-bit signed response (output of f2)
// SQN      - 48-bit sequence number (input to f1 and f1*)
// TOP      - 256-bit Operator Variant Algorithm Configuration Field
// TOPC     - 256-bit derived value from TOP and K
// INSTANCE - 8-bit value specifying mode and parameter lengths

/*
typedef unsigned char	uint8;
typedef unsigned long	uint32;

const uint8 Rho[25]	= {0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
const uint8 Pi[25] = {0,6,12,18,24,3,9,10,16,22,1,7,13,19,20,4,5,11,17,23,2,8,14,15,21};
const uint8 Iota[24] = {1,146,218,112,155,33,241,89,138,136,57,42,187,203,217,83,82,192,26,106,241,208,33,120};

void Keccak(uint8 s[200])
{	uint8 t[40], i, j, k, round;

	for(round=0; round<24; ++round)
	{
		for(i=0; i<40; ++i)
			t[i]=s[i]^s[40+i]^s[80+i]^s[120+i]^s[160+i];
		for(i=0; i<200; i+=8)
			for(j = (i+32)%40, k=0; k<8; ++k)
				s[i+k] ^= t[j+k];
		for(i=0; i<40; t[i] = (t[i]<<1)|j, i+=8)
			for(j = t[i+7]>>7, k=7; k; --k)
				t[i+k] = (t[i+k]<<1)|(t[i+k-1]>>7);
		for(i=0; i<200; i+=8)
			for(j = (i+8)%40, k=0; k<8; ++k)
				s[i+k] ^= t[j+k];

		for(i=8; i<200; i+=8)
		{	for(j = Rho[i>>3]>>3, k=0; k<8; ++k)
				t[(k+j)&7] = s[i+k];
			for(j = Rho[i>>3]&7, k=7; k; --k)
				s[i+k] = (t[k]<<j) | (t[k-1]>>(8-j));
			s[i] = (t[0]<<j) | (t[7]>>(8-j));
		}

		for(k=8; k<16; ++k) t[k] = s[k];
			for(i=1; (j=Pi[i])>1; i=j)
				for(k=0; k<8; ++k)
					s[(i<<3)|k] = s[(j<<3)|k];
		for(k=0; k<8; ++k)
			s[(i<<3)|k] = t[k+8];

		for(i=0; i<200; i+=40)
		{	for(j=0; j<40; ++j)
				t[j]=(~s[i+(j+8)%40]) & s[i+(j+16)%40];
			for(j=0; j<40; ++j)	s[i+j]^=t[j];
		}

		k = Iota[round];
		s[0] ^= k & 0x8B;
		s[1] ^= (k<<3)&0x80;
		s[3] ^= (k<<2)&0x80;
		s[7] ^= (k<<1)&0x80;
	}
}

*/
import "C"

import (
	"unsafe"
)

// TUAK constants
const (
	tuakStateSize = 200 // Keccak state size (1600 bits)
)

// TUAK ALGONAME constants
var (
	// tuakAlgoNameRev is "0.1KAUT" (reversed) for TOPc computation
	tuakAlgoNameRev = []byte{48, 46, 49, 75, 65, 85, 84}

	// tuakPadding is the padding to fill up to 200 bytes
	tuakPadding = []byte{
		31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0,
	}
)

// TUAK implements the 3GPP TUAK authentication algorithm
type TUAK struct{}

// NewTUAK creates a new TUAK instance
func NewTUAK() *TUAK {
	return &TUAK{}
}

// Keccak calls the C function keccak_f[1600] from the specification
func Keccak(in []byte) []byte {
	C.Keccak((*C.uint8)(unsafe.Pointer(&in[0])))
	return in
}

// keccakIterations performs the specified number of Keccak iterations
func keccakIterations(state []byte, iterations int) []byte {
	for i := 0; i < iterations; i++ {
		state = Keccak(state)
	}
	return state
}

// appendKeyWithPadding adds key and padding depending on key length
func appendKeyWithPadding(in []byte, key []byte) []byte {
	if len(key) == KeyLen128 {
		// 128-bit key: add key (reversed) + 16 zeros
		in = append(in, reverseBytes(key)...)
		in = append(in, make([]byte, 16)...)
	} else {
		// 256-bit key: add only key (reversed)
		in = append(in, reverseBytes(key)...)
	}
	return in
}

// computeInstanceF1 computes INSTANCE byte for f1 function
func computeInstanceF1(macLen int, keyLen int) byte {
	var instance byte
	switch macLen {
	case MACLen64:
		instance = 8
	case MACLen128:
		instance = 16
	default: // MACLen256
		instance = 32
	}
	if keyLen == KeyLen256 {
		instance++
	}
	return instance
}

// computeInstanceF1s computes INSTANCE byte for f1* function
func computeInstanceF1s(macLen int, keyLen int) byte {
	var instance byte
	switch macLen {
	case MACLen64:
		instance = 136
	case MACLen128:
		instance = 144
	default: // MACLen256
		instance = 160
	}
	if keyLen == KeyLen256 {
		instance++
	}
	return instance
}

// computeInstanceF2345 computes INSTANCE byte for f2, f3, f4, f5 functions
func computeInstanceF2345(resLen, ckLen, ikLen, keyLen int) byte {
	instance := byte(64)
	switch resLen {
	case RESLen64:
		instance += 8
	case RESLen128:
		instance += 16
	case RESLen256:
		instance += 32
	}
	if ckLen == CKLen256 {
		instance += 4
	}
	if ikLen == IKLen256 {
		instance += 2
	}
	if keyLen == KeyLen256 {
		instance++
	}
	return instance
}

// computeInstanceF5s computes INSTANCE byte for f5* function
func computeInstanceF5s(keyLen int) byte {
	instance := byte(192)
	if keyLen == KeyLen256 {
		instance++
	}
	return instance
}

// extractOutput extracts result from output buffer in reverse order
func extractOutput(out []byte, length int) []byte {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = out[length-1-i]
	}
	return result
}

// extractOutputWithOffset extracts result from output buffer with specified offset
func extractOutputWithOffset(out []byte, length, offset int) []byte {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = out[offset+length-1-i]
	}
	return result
}

// validateTUAKKeyAndTOPC validates key and TOPC
func validateTUAKKeyAndTOPC(v *Variables) error {
	keyLen := len(v.K)
	if keyLen != KeyLen128 && keyLen != KeyLen256 {
		return ErrInvalidKeyLength
	}
	if len(v.TOPC) != KeyLen256 {
		return ErrInvalidTOPCLength
	}
	return nil
}

// validateTUAKCommonParams validates common parameters for TUAK
func validateTUAKCommonParams(v *Variables) error {
	if err := validateTUAKKeyAndTOPC(v); err != nil {
		return err
	}
	if len(v.RAND) != RandLen {
		return ErrInvalidRANDLength
	}
	return nil
}

// setDefaultIterations sets default number of iterations
func setDefaultIterations(v *Variables) {
	if v.Iter == 0 {
		v.Iter = 1
	}
}

// ComputeTOPC computes TOPc for TUAK
// Required inputs: K (16 or 32 bytes), TOP (32 bytes)
// Output: TOPC (32 bytes)
func (t *TUAK) ComputeTOPC(v *Variables) error {
	keyLen := len(v.K)
	if keyLen != KeyLen128 && keyLen != KeyLen256 {
		return ErrInvalidKeyLength
	}
	if len(v.TOP) != KeyLen256 {
		return ErrInvalidTOPLength
	}
	setDefaultIterations(v)

	// Build input buffer
	in := make([]byte, 0, tuakStateSize)

	// TOP in reverse order (32 bytes)
	in = append(in, reverseBytes(v.TOP)...)

	// INSTANCE: 0 for 128-bit K, 1 for 256-bit K
	if keyLen == KeyLen128 {
		in = append(in, 0)
	} else {
		in = append(in, 1)
	}

	// ALGONAME_REV (7 bytes)
	in = append(in, tuakAlgoNameRev...)

	// 24 zero bytes
	in = append(in, make([]byte, 24)...)

	// Key with padding
	in = appendKeyWithPadding(in, v.K)

	// Final padding
	in = append(in, tuakPadding...)

	// Execute Keccak
	out := keccakIterations(in, v.Iter)

	// Extract TOPc (32 bytes in reverse order)
	v.TOPC = extractOutput(out, KeyLen256)

	return nil
}

// ComputeF1 computes MAC-A (Network Authentication Code)
// Required inputs: K, TOPC, RAND, AMF, SQN, MACLen
// Output: MACA (8, 16 or 32 bytes depending on MACLen)
func (t *TUAK) ComputeF1(v *Variables) error {
	if err := validateTUAKCommonParams(v); err != nil {
		return err
	}
	if len(v.AMF) != AMFLen {
		return ErrInvalidAMFLength
	}
	if len(v.SQN) != SQNLen {
		return ErrInvalidSQNLength
	}
	if v.MACLen != MACLen64 && v.MACLen != MACLen128 && v.MACLen != MACLen256 {
		return ErrInvalidMACLength
	}
	setDefaultIterations(v)

	keyLen := len(v.K)
	instance := computeInstanceF1(v.MACLen, keyLen)

	// Build input buffer
	in := make([]byte, 0, tuakStateSize)
	in = append(in, reverseBytes(v.TOPC)...)
	in = append(in, instance)
	in = append(in, tuakAlgoNameRev...)
	in = append(in, reverseBytes(v.RAND)...)
	in = append(in, reverseBytes(v.AMF)...)
	in = append(in, reverseBytes(v.SQN)...)
	in = appendKeyWithPadding(in, v.K)
	in = append(in, tuakPadding...)

	// Execute Keccak
	out := keccakIterations(in, v.Iter)

	// Extract MAC-A
	macBytes := v.MACLen / 8
	v.MACA = extractOutput(out, macBytes)

	return nil
}

// ComputeF1s computes MAC-S (Resynchronisation Authentication Code)
// Required inputs: K, TOPC, RAND, AMF, SQN, MACLen
// Output: MACS (8, 16 or 32 bytes depending on MACLen)
func (t *TUAK) ComputeF1s(v *Variables) error {
	if err := validateTUAKCommonParams(v); err != nil {
		return err
	}
	if len(v.AMF) != AMFLen {
		return ErrInvalidAMFLength
	}
	if len(v.SQN) != SQNLen {
		return ErrInvalidSQNLength
	}
	if v.MACLen != MACLen64 && v.MACLen != MACLen128 && v.MACLen != MACLen256 {
		return ErrInvalidMACLength
	}
	setDefaultIterations(v)

	keyLen := len(v.K)
	instance := computeInstanceF1s(v.MACLen, keyLen)

	// Build input buffer
	in := make([]byte, 0, tuakStateSize)
	in = append(in, reverseBytes(v.TOPC)...)
	in = append(in, instance)
	in = append(in, tuakAlgoNameRev...)
	in = append(in, reverseBytes(v.RAND)...)
	in = append(in, reverseBytes(v.AMF)...)
	in = append(in, reverseBytes(v.SQN)...)
	in = appendKeyWithPadding(in, v.K)
	in = append(in, tuakPadding...)

	// Execute Keccak
	out := keccakIterations(in, v.Iter)

	// Extract MAC-S
	macBytes := v.MACLen / 8
	v.MACS = extractOutput(out, macBytes)

	return nil
}

// ComputeF2345 computes RES (f2), CK (f3), IK (f4), AK (f5)
// Required inputs: K, TOPC, RAND, RESLen, CKLen, IKLen
// Outputs: RES, CK, IK, AK
func (t *TUAK) ComputeF2345(v *Variables) error {
	if err := validateTUAKCommonParams(v); err != nil {
		return err
	}
	if v.RESLen != RESLen32 && v.RESLen != RESLen64 && v.RESLen != RESLen128 && v.RESLen != RESLen256 {
		return ErrInvalidRESLength
	}
	if v.CKLen != CKLen128 && v.CKLen != CKLen256 {
		return ErrInvalidCKLength
	}
	if v.IKLen != IKLen128 && v.IKLen != IKLen256 {
		return ErrInvalidIKLength
	}
	setDefaultIterations(v)

	keyLen := len(v.K)
	instance := computeInstanceF2345(v.RESLen, v.CKLen, v.IKLen, keyLen)

	// Build input buffer
	in := make([]byte, 0, tuakStateSize)
	in = append(in, reverseBytes(v.TOPC)...)
	in = append(in, instance)
	in = append(in, tuakAlgoNameRev...)
	in = append(in, reverseBytes(v.RAND)...)
	in = append(in, make([]byte, 8)...) // 8 zero bytes instead of AMF+SQN
	in = appendKeyWithPadding(in, v.K)
	in = append(in, tuakPadding...)

	// Execute Keccak
	out := keccakIterations(in, v.Iter)

	// Extract RES (offset 0)
	resBytes := v.RESLen / 8
	v.RES = extractOutput(out, resBytes)

	// Extract CK (offset 32)
	ckBytes := v.CKLen / 8
	v.CK = extractOutputWithOffset(out, ckBytes, 32)

	// Extract IK (offset 64)
	ikBytes := v.IKLen / 8
	v.IK = extractOutputWithOffset(out, ikBytes, 64)

	// Extract AK (offset 96, 6 bytes)
	v.AK = extractOutputWithOffset(out, AKLen, 96)

	return nil
}

// ComputeF5s computes AK* (anonymity key for resynchronisation)
// Required inputs: K, TOPC, RAND
// Output: AKF5 (6 bytes)
func (t *TUAK) ComputeF5s(v *Variables) error {
	if err := validateTUAKCommonParams(v); err != nil {
		return err
	}
	setDefaultIterations(v)

	keyLen := len(v.K)
	instance := computeInstanceF5s(keyLen)

	// Build input buffer
	in := make([]byte, 0, tuakStateSize)
	in = append(in, reverseBytes(v.TOPC)...)
	in = append(in, instance)
	in = append(in, tuakAlgoNameRev...)
	in = append(in, reverseBytes(v.RAND)...)
	in = append(in, make([]byte, 8)...) // 8 zero bytes
	in = appendKeyWithPadding(in, v.K)
	in = append(in, tuakPadding...)

	// Execute Keccak
	out := keccakIterations(in, v.Iter)

	// Extract AK* (offset 96, 6 bytes)
	v.AKF5 = extractOutputWithOffset(out, AKLen, 96)

	return nil
}

// Ensure TUAK implements AlgorithmSet
var _ AlgorithmSet = (*TUAK)(nil)
