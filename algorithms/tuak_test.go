package algorithms_test

import (
	"encoding/hex"
	"testing"

	"sim_reader/algorithms"
)

// TestKeccak_StateSize verifies that Keccak operates on 200-byte (1600-bit) state
func TestKeccak_StateSize(t *testing.T) {
	// Keccak-f[1600] requires exactly 200 bytes input
	state := make([]byte, 200)
	result := algorithms.Keccak(state)

	if len(result) != 200 {
		t.Errorf("Keccak output size mismatch: got %d, want 200", len(result))
	}
}

// TestKeccak_ZeroState tests Keccak with all-zero input
func TestKeccak_ZeroState(t *testing.T) {
	state := make([]byte, 200)
	result := algorithms.Keccak(state)

	// After one round of Keccak-f[1600] on zero state, result should not be all zeros
	allZeros := true
	for _, b := range result {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Keccak on zero state should not produce all zeros")
	}

	t.Logf("Keccak(zeros) = %x...", result[:32])
}

// TestKeccak_SingleBit tests Keccak with single bit set (0x80 at position 0)
func TestKeccak_SingleBit(t *testing.T) {
	// Test vector from 3GPP TS 35.231 / NIST
	state := make([]byte, 200)
	state[0] = 0x80

	expectedHex := "44e0e58ca968975c4c2592a157f53f2124519b010b89e15e301ef58f76501db59cde067f1fde09c0a4b5c210a6a19f06ba4c8f0c6fc868f0fc80a63b2553791e41c82278ad115efc70f71d641ff0774aa5d547b6d9914914022c514c45fceca61cb66b0f0313e34988ae0d36737e2c0529907fe653fc4e185d07f3961f826bb88031af844d9e7d9876170363fde76786c58ccbcf5c3a01bb914c1b0208a27c7be3bbbbbb9976e040317afc2afbfadc7ba7fc237235c65551aa3139641fa8db2e6483f28740b31b61"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatal(err)
	}

	result := algorithms.Keccak(state)

	if hex.EncodeToString(result) != expectedHex {
		t.Errorf("Keccak single bit test failed\ngot:  %x\nwant: %x", result, expected)
	}
}

// TestKeccak_3GPP_TestVector1 tests against 3GPP TS 35.233 test vector
func TestKeccak_3GPP_TestVector1(t *testing.T) {
	inputHex := "2476d2dac59e2e9349df3255a9dab1b69eb5c208f151c7309e8c8f17db456d0b5eb0afb6c73e37ce8ccccf20b79d8a67294149174809e429709330c4ad231d3e5211ae0bd80520c43ad4b436625792a76c52089d0f739271151a37594df66de4429f3c970a3456b6ce2c78cd1128717f4bdb731a4c97dbe5eb7353fe81e37c33ac60b82122eac611a98e0e7442b99964752293e4f9c696ba05f07a21451f90730c9678c645ad4be44c4d2d981a3412081c9c6b05c993ff1c561a0d242b4706d501c34765b37a0b50"
	expectedHex := "2fdc58d4d94a884c1cb03a8e63acab8375e856b561ba3a0625e830acdb55734286646f87189b435425b5d6654e228228b697b81cbead655b71aaccc25e3d7e51b5cb5ac227f67f2ad8a062976782b08a7ec3f1b538d6008c0babef83da64366b62a53f88a3dc0629bded795f3220f3c65c76bdd01243e88f63d6912e5fb5cda167b71f9baaa742dc193ff78c1767a38a1c96408cce169239b077f2903a07b8c46a048d66318e595ea4bb92992c7c2d3dcd381975b6e05f85ba18152096cc30ed22140ff3b6711ea7"

	input, err := hex.DecodeString(inputHex)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatal(err)
	}

	result := algorithms.Keccak(input)

	if hex.EncodeToString(result) != expectedHex {
		t.Errorf("Keccak 3GPP test vector 1 failed\ngot:  %x\nwant: %x", result, expected)
	}
}

// TestKeccak_3GPP_TestVector2 tests against second 3GPP test vector (0x80 at start)
func TestKeccak_3GPP_TestVector2(t *testing.T) {
	inputHex := "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	expectedHex := "44e0e58ca968975c4c2592a157f53f2124519b010b89e15e301ef58f76501db59cde067f1fde09c0a4b5c210a6a19f06ba4c8f0c6fc868f0fc80a63b2553791e41c82278ad115efc70f71d641ff0774aa5d547b6d9914914022c514c45fceca61cb66b0f0313e34988ae0d36737e2c0529907fe653fc4e185d07f3961f826bb88031af844d9e7d9876170363fde76786c58ccbcf5c3a01bb914c1b0208a27c7be3bbbbbb9976e040317afc2afbfadc7ba7fc237235c65551aa3139641fa8db2e6483f28740b31b61"

	input, err := hex.DecodeString(inputHex)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatal(err)
	}

	result := algorithms.Keccak(input)

	if hex.EncodeToString(result) != expectedHex {
		t.Errorf("Keccak 3GPP test vector 2 failed\ngot:  %x\nwant: %x", result, expected)
	}
}

// TestKeccak_Deterministic verifies that Keccak is deterministic
func TestKeccak_Deterministic(t *testing.T) {
	input1, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7")
	input2, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7")

	result1 := algorithms.Keccak(input1)
	result2 := algorithms.Keccak(input2)

	if hex.EncodeToString(result1) != hex.EncodeToString(result2) {
		t.Error("Keccak should be deterministic - same input should produce same output")
	}

	t.Logf("Keccak(sequential) = %x...", result1[:32])
}

// TestKeccak_MultipleIterations tests multiple Keccak iterations (as used in TUAK)
func TestKeccak_MultipleIterations(t *testing.T) {
	state := make([]byte, 200)
	state[0] = 0x01

	// Single iteration
	result1 := make([]byte, 200)
	copy(result1, state)
	algorithms.Keccak(result1)

	// Two iterations
	result2 := make([]byte, 200)
	copy(result2, state)
	algorithms.Keccak(result2)
	algorithms.Keccak(result2)

	// Results should be different
	if hex.EncodeToString(result1) == hex.EncodeToString(result2) {
		t.Error("Multiple Keccak iterations should produce different results")
	}

	t.Logf("Keccak^1 = %x...", result1[:16])
	t.Logf("Keccak^2 = %x...", result2[:16])
}

// TestKeccak_InPlace verifies that Keccak modifies input in place
func TestKeccak_InPlace(t *testing.T) {
	input, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7")
	originalFirst := input[0]

	result := algorithms.Keccak(input)

	// Result should point to same slice as input (in-place modification)
	if &result[0] != &input[0] {
		t.Error("Keccak should modify input in place")
	}

	// First byte should be changed
	if input[0] == originalFirst {
		t.Error("Keccak should modify the input data")
	}
}

// ============================================================================
// TUAK Algorithm Tests
// ============================================================================

func TestTUAK_ComputeTOPC_TestSet1(t *testing.T) {
	var (
		v    algorithms.Variables
		tuak algorithms.TUAK
		err  error
	)

	// Test Set 1 from 3GPP TS 35.233
	v.K, err = hex.DecodeString("abababababababababababababababab")
	if err != nil {
		t.Fatal(err)
	}
	v.RAND, err = hex.DecodeString("42424242424242424242424242424242")
	if err != nil {
		t.Fatal(err)
	}
	v.TOP, err = hex.DecodeString("5555555555555555555555555555555555555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	v.SQN, err = hex.DecodeString("111111111111")
	if err != nil {
		t.Fatal(err)
	}
	v.AMF, err = hex.DecodeString("ffff")
	if err != nil {
		t.Fatal(err)
	}

	v.MACLen = algorithms.MACLen64
	v.RESLen = algorithms.RESLen32
	v.CKLen = algorithms.CKLen128
	v.IKLen = algorithms.IKLen128
	v.Iter = 1

	// Test ComputeTOPC
	err = tuak.ComputeTOPC(&v)
	if err != nil {
		t.Fatal(err)
	}
	expectedTOPC := "bd04d9530e87513c5d837ac2ad954623a8e2330c115305a73eb45d1f40cccbff"
	if hex.EncodeToString(v.TOPC) != expectedTOPC {
		t.Errorf("TOPC mismatch\ngot:  %x\nwant: %s", v.TOPC, expectedTOPC)
	}

	// Test ComputeF1
	err = tuak.ComputeF1(&v)
	if err != nil {
		t.Fatal(err)
	}
	expectedMACA := "f9a54e6aeaa8618d"
	if hex.EncodeToString(v.MACA) != expectedMACA {
		t.Errorf("MACA mismatch\ngot:  %x\nwant: %s", v.MACA, expectedMACA)
	}

	// Test ComputeF1s
	err = tuak.ComputeF1s(&v)
	if err != nil {
		t.Fatal(err)
	}
	expectedMACS := "e94b4dc6c7297df3"
	if hex.EncodeToString(v.MACS) != expectedMACS {
		t.Errorf("MACS mismatch\ngot:  %x\nwant: %s", v.MACS, expectedMACS)
	}

	// Test ComputeF2345
	err = tuak.ComputeF2345(&v)
	if err != nil {
		t.Fatal(err)
	}

	expectedRES := "657acd64"
	if hex.EncodeToString(v.RES) != expectedRES {
		t.Errorf("RES mismatch\ngot:  %x\nwant: %s", v.RES, expectedRES)
	}

	expectedCK := "d71a1e5c6caffe986a26f783e5c78be1"
	if hex.EncodeToString(v.CK) != expectedCK {
		t.Errorf("CK mismatch\ngot:  %x\nwant: %s", v.CK, expectedCK)
	}

	expectedIK := "be849fa2564f869aecee6f62d4337e72"
	if hex.EncodeToString(v.IK) != expectedIK {
		t.Errorf("IK mismatch\ngot:  %x\nwant: %s", v.IK, expectedIK)
	}

	expectedAK := "719f1e9b9054"
	if hex.EncodeToString(v.AK) != expectedAK {
		t.Errorf("AK mismatch\ngot:  %x\nwant: %s", v.AK, expectedAK)
	}

	// Test ComputeF5s
	err = tuak.ComputeF5s(&v)
	if err != nil {
		t.Fatal(err)
	}

	expectedAKF5 := "e7af6b3d0e38"
	if hex.EncodeToString(v.AKF5) != expectedAKF5 {
		t.Errorf("AKF5 mismatch\ngot:  %x\nwant: %s", v.AKF5, expectedAKF5)
	}
}

func TestTUAK_ValidationErrors(t *testing.T) {
	tuak := algorithms.NewTUAK()
	v := &algorithms.Variables{}

	// Test invalid K length
	v.K = []byte{1, 2, 3} // invalid
	err := tuak.ComputeTOPC(v)
	if err == nil {
		t.Error("Expected error for invalid K length")
	}

	// Test invalid TOP length
	v.K = make([]byte, 16)
	v.TOP = []byte{1, 2, 3} // invalid
	err = tuak.ComputeTOPC(v)
	if err == nil {
		t.Error("Expected error for invalid TOP length")
	}
}

// TestTUAK_256BitKey tests TUAK with 256-bit key
func TestTUAK_256BitKey(t *testing.T) {
	var (
		v    algorithms.Variables
		tuak algorithms.TUAK
		err  error
	)

	// 256-bit key
	v.K, err = hex.DecodeString("abababababababababababababababababababababababababababababababab")
	if err != nil {
		t.Fatal(err)
	}
	v.TOP, err = hex.DecodeString("5555555555555555555555555555555555555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	v.RAND, err = hex.DecodeString("42424242424242424242424242424242")
	if err != nil {
		t.Fatal(err)
	}
	v.SQN, err = hex.DecodeString("111111111111")
	if err != nil {
		t.Fatal(err)
	}
	v.AMF, err = hex.DecodeString("ffff")
	if err != nil {
		t.Fatal(err)
	}

	v.MACLen = algorithms.MACLen64
	v.RESLen = algorithms.RESLen64
	v.CKLen = algorithms.CKLen256
	v.IKLen = algorithms.IKLen256
	v.Iter = 1

	// Test ComputeTOPC with 256-bit key
	err = tuak.ComputeTOPC(&v)
	if err != nil {
		t.Fatal(err)
	}

	if len(v.TOPC) != 32 {
		t.Errorf("TOPC length should be 32, got %d", len(v.TOPC))
	}
	t.Logf("TOPC (256-bit K): %x", v.TOPC)

	// Test ComputeF2345 with 256-bit CK/IK
	err = tuak.ComputeF2345(&v)
	if err != nil {
		t.Fatal(err)
	}

	if len(v.CK) != 32 {
		t.Errorf("CK length should be 32 for 256-bit, got %d", len(v.CK))
	}
	if len(v.IK) != 32 {
		t.Errorf("IK length should be 32 for 256-bit, got %d", len(v.IK))
	}
	t.Logf("CK (256-bit): %x", v.CK)
	t.Logf("IK (256-bit): %x", v.IK)
}
