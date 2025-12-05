package algorithms

// Milenage algorithm implementation
// Based on 3GPP TS 35.206 and 3GPP TS 35.207 V9.0.0 (2009-12)
//
// Algorithm parameters:
// AK     - 48-bit anonymity key (output of f5 or f5*)
// AMF    - 16-bit authentication management field (input to f1 and f1*)
// CK     - 128-bit confidentiality key (output of f3)
// IK     - 128-bit integrity key (output of f4)
// K      - 128-bit subscriber key (input to all functions)
// MAC-A  - 64-bit network authentication code (output of f1)
// MAC-S  - 64-bit resynchronisation authentication code (output of f1*)
// OP     - 128-bit Operator Variant Algorithm Configuration Field
// OPc    - 128-bit derived value from OP and K
// RAND   - 128-bit random challenge (input to all functions)
// RES    - 64-bit signed response (output of f2)
// SQN    - 48-bit sequence number (input to f1 and f1*)
//
// c1..c5 - 128-bit constants XORed onto intermediate variables
// r1..r5 - rotation amounts (0-127 bits)

import (
	"crypto/aes"
	"crypto/cipher"
)

// Milenage rotation constants
const (
	milenageR1 = 8
	milenageR2 = 0
	milenageR3 = 4
	milenageR4 = 8
	milenageR5 = 12
)

// Milenage c1..c5 constants (all zeros except last byte)
var (
	milenageC1 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00}
	milenageC2 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	milenageC3 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	milenageC4 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04}
	milenageC5 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08}
)

// Milenage implements the 3GPP Milenage authentication algorithm
type Milenage struct{}

// NewMilenage creates a new Milenage instance
func NewMilenage() *Milenage {
	return &Milenage{}
}

// rotate performs cyclic rotation of 128-bit value by r bytes to the left
// rot(x, r): y = x[r] || x[r+1] || ... || x[127] || x[0] || x[1] || ... || x[r-1]
func rotate(data []byte, r int) []byte {
	if r == 0 || len(data) == 0 {
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}
	r = r % len(data)
	result := make([]byte, len(data))
	copy(result, data[r:])
	copy(result[len(data)-r:], data[:r])
	return result
}

// aesEncrypt encrypts data using AES-128 in CBC mode with zero IV
func aesEncrypt(plaintext, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	iv := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize)

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

// validateMilenageCommonParams validates common parameters for Milenage
func validateMilenageCommonParams(v *Variables) error {
	if len(v.K) != KeyLen128 {
		return ErrInvalidKeyLength
	}
	if len(v.TOPC) != KeyLen128 {
		return ErrInvalidTOPCLength
	}
	if len(v.RAND) != RandLen {
		return ErrInvalidRANDLength
	}
	return nil
}

// validateF1Params validates parameters for f1/f1*
func validateF1Params(v *Variables) error {
	if err := validateMilenageCommonParams(v); err != nil {
		return err
	}
	if len(v.AMF) != AMFLen {
		return ErrInvalidAMFLength
	}
	if len(v.SQN) != SQNLen {
		return ErrInvalidSQNLength
	}
	return nil
}

// ComputeTOPC computes OPc = AES_K(OP) XOR OP
// Required inputs: K (16 bytes), TOP (16 bytes)
// Output: TOPC (16 bytes)
func (m *Milenage) ComputeTOPC(v *Variables) error {
	if len(v.K) != KeyLen128 {
		return ErrInvalidKeyLength
	}
	if len(v.TOP) != KeyLen128 {
		return ErrInvalidTOPLength
	}

	encrypted := aesEncrypt(v.TOP, v.K)
	v.TOPC = xorBytes(encrypted, v.TOP)
	return nil
}

// ComputeF1 computes MAC-A (Network Authentication Code)
// f1(K, RAND, SQN, AMF) = MAC-A
// Required inputs: K, TOPC, RAND, SQN, AMF
// Output: MACA (8 bytes)
func (m *Milenage) ComputeF1(v *Variables) error {
	if err := validateF1Params(v); err != nil {
		return err
	}

	// IN1 = SQN || AMF || SQN || AMF
	in1 := make([]byte, KeyLen128)
	copy(in1[0:6], v.SQN)
	copy(in1[6:8], v.AMF)
	copy(in1[8:14], v.SQN)
	copy(in1[14:16], v.AMF)

	// TEMP = AES_K(RAND XOR OPc)
	temp := aesEncrypt(xorBytes(v.RAND, v.TOPC), v.K)

	// OUT1 = AES_K(rot(TEMP XOR OPc, r1) XOR c1 XOR IN1 XOR OPc) XOR OPc
	rotated := rotate(xorBytes(in1, v.TOPC), milenageR1)
	xored := xorBytes(xorBytes(temp, rotated), milenageC1)
	out1 := xorBytes(aesEncrypt(xored, v.K), v.TOPC)

	// MAC-A = OUT1[0..63]
	v.MACA = make([]byte, 8)
	copy(v.MACA, out1[:8])

	return nil
}

// ComputeF1s computes MAC-S (Resynchronisation Authentication Code)
// f1*(K, RAND, SQN, AMF) = MAC-S
// Required inputs: K, TOPC, RAND, SQN, AMF
// Output: MACS (8 bytes)
func (m *Milenage) ComputeF1s(v *Variables) error {
	if err := validateF1Params(v); err != nil {
		return err
	}

	// IN1 = SQN || AMF || SQN || AMF
	in1 := make([]byte, KeyLen128)
	copy(in1[0:6], v.SQN)
	copy(in1[6:8], v.AMF)
	copy(in1[8:14], v.SQN)
	copy(in1[14:16], v.AMF)

	// TEMP = AES_K(RAND XOR OPc)
	temp := aesEncrypt(xorBytes(v.RAND, v.TOPC), v.K)

	// OUT1 = AES_K(rot(TEMP XOR OPc, r1) XOR c1 XOR IN1 XOR OPc) XOR OPc
	rotated := rotate(xorBytes(in1, v.TOPC), milenageR1)
	xored := xorBytes(xorBytes(temp, rotated), milenageC1)
	out1 := xorBytes(aesEncrypt(xored, v.K), v.TOPC)

	// MAC-S = OUT1[64..127]
	v.MACS = make([]byte, 8)
	copy(v.MACS, out1[8:16])

	return nil
}

// ComputeF2345 computes RES (f2), CK (f3), IK (f4), AK (f5)
// Required inputs: K, TOPC, RAND
// Outputs: RES (8 bytes), CK (16 bytes), IK (16 bytes), AK (6 bytes)
func (m *Milenage) ComputeF2345(v *Variables) error {
	if err := validateMilenageCommonParams(v); err != nil {
		return err
	}

	// TEMP = AES_K(RAND XOR OPc)
	temp := aesEncrypt(xorBytes(v.RAND, v.TOPC), v.K)
	tempXorOPc := xorBytes(temp, v.TOPC)

	// f2 and f5: OUT2 = AES_K(rot(TEMP XOR OPc, r2) XOR c2) XOR OPc
	rotated2 := rotate(tempXorOPc, milenageR2)
	out2 := xorBytes(aesEncrypt(xorBytes(rotated2, milenageC2), v.K), v.TOPC)

	// RES = OUT2[64..127]
	v.RES = make([]byte, 8)
	copy(v.RES, out2[8:16])
	v.XRES = make([]byte, 8)
	copy(v.XRES, out2[8:16])

	// AK = OUT2[0..47]
	v.AK = make([]byte, 6)
	copy(v.AK, out2[:6])

	// f3: OUT3 = AES_K(rot(TEMP XOR OPc, r3) XOR c3) XOR OPc
	rotated3 := rotate(tempXorOPc, milenageR3)
	out3 := xorBytes(aesEncrypt(xorBytes(rotated3, milenageC3), v.K), v.TOPC)

	// CK = OUT3[0..127]
	v.CK = make([]byte, KeyLen128)
	copy(v.CK, out3)

	// f4: OUT4 = AES_K(rot(TEMP XOR OPc, r4) XOR c4) XOR OPc
	rotated4 := rotate(tempXorOPc, milenageR4)
	out4 := xorBytes(aesEncrypt(xorBytes(rotated4, milenageC4), v.K), v.TOPC)

	// IK = OUT4[0..127]
	v.IK = make([]byte, KeyLen128)
	copy(v.IK, out4)

	return nil
}

// ComputeF5s computes AK* (anonymity key for resynchronisation)
// f5*(K, RAND) = AK*
// Required inputs: K, TOPC, RAND
// Output: AKF5 (6 bytes)
func (m *Milenage) ComputeF5s(v *Variables) error {
	if err := validateMilenageCommonParams(v); err != nil {
		return err
	}

	// TEMP = AES_K(RAND XOR OPc)
	temp := aesEncrypt(xorBytes(v.RAND, v.TOPC), v.K)

	// OUT5 = AES_K(rot(TEMP XOR OPc, r5) XOR c5) XOR OPc
	rotated := rotate(xorBytes(temp, v.TOPC), milenageR5)
	out5 := xorBytes(aesEncrypt(xorBytes(rotated, milenageC5), v.K), v.TOPC)

	// AK* = OUT5[0..47]
	v.AKF5 = make([]byte, 6)
	copy(v.AKF5, out5[:6])

	return nil
}

// Ensure Milenage implements AlgorithmSet
var _ AlgorithmSet = (*Milenage)(nil)
