package algorithms_test

import (
	"encoding/hex"
	"testing"

	"sim_reader/algorithms"
)

func TestMilenage_Set1(t *testing.T) {
	var (
		milenage algorithms.Milenage
		v        algorithms.Variables
		err      error
	)

	// Test with real values
	v.K, err = hex.DecodeString("F2464E3293019A7E51ABAA7B1262B7D8")
	if err != nil {
		t.Fatal(err)
	}
	v.RAND, err = hex.DecodeString("7d6af2df993240ba9b191b68f1750c43")
	if err != nil {
		t.Fatal(err)
	}
	v.SQN, err = hex.DecodeString("000000000c80")
	if err != nil {
		t.Fatal(err)
	}
	v.AMF, err = hex.DecodeString("8000")
	if err != nil {
		t.Fatal(err)
	}
	v.TOPC, err = hex.DecodeString("B10B351A0CCD8BE31E0C9F088945A812")
	if err != nil {
		t.Fatal(err)
	}

	// Test ComputeF1
	if err := milenage.ComputeF1(&v); err != nil {
		t.Fatal(err)
	}
	t.Logf("MACA: %x", v.MACA)

	// Test ComputeF1s
	if err := milenage.ComputeF1s(&v); err != nil {
		t.Fatal(err)
	}
	t.Logf("MACS: %x", v.MACS)

	// Test ComputeF2345
	if err := milenage.ComputeF2345(&v); err != nil {
		t.Fatal(err)
	}
	t.Logf("RES: %x", v.RES)
	t.Logf("AK: %x", v.AK)
	t.Logf("CK: %x", v.CK)
	t.Logf("IK: %x", v.IK)

	// Test ComputeF5s
	if err := milenage.ComputeF5s(&v); err != nil {
		t.Fatal(err)
	}
	t.Logf("AKF5: %x", v.AKF5)

	// Test ComputeAUTN
	if err := v.ComputeAUTN(); err != nil {
		t.Fatal(err)
	}
	t.Logf("AUTN: %x", v.AUTN)

	// Test ComputeKASME
	kasme, err := v.ComputeKASME(250, 88)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("KASME: %x", kasme)
}

// TestMilenage_3GPP_TestSet1 tests against 3GPP TS 35.207 specification
func TestMilenage_3GPP_TestSet1(t *testing.T) {
	var (
		milenage algorithms.Milenage
		v        algorithms.Variables
		err      error
	)

	// 3GPP TS 35.207 V9.0.0 (2009-12)
	// 4.3 Test Set 1
	v.K, err = hex.DecodeString("465b5ce8b199b49faa5f0a2ee238a6bc")
	if err != nil {
		t.Fatal(err)
	}
	v.RAND, err = hex.DecodeString("23553cbe9637a89d218ae64dae47bf35")
	if err != nil {
		t.Fatal(err)
	}
	v.SQN, err = hex.DecodeString("ff9bb4d0b607")
	if err != nil {
		t.Fatal(err)
	}
	v.AMF, err = hex.DecodeString("b9b9")
	if err != nil {
		t.Fatal(err)
	}
	v.TOP, err = hex.DecodeString("cdc202d5123e20f62b6d676ac72cb318")
	if err != nil {
		t.Fatal(err)
	}

	// Test ComputeTOPC
	if err := milenage.ComputeTOPC(&v); err != nil {
		t.Fatal(err)
	}
	expectedTOPC := "cd63cb71954a9f4e48a5994e37a02baf"
	if hex.EncodeToString(v.TOPC) != expectedTOPC {
		t.Errorf("TOPC mismatch\ngot:  %x\nwant: %s", v.TOPC, expectedTOPC)
	}

	// Test ComputeF1
	if err := milenage.ComputeF1(&v); err != nil {
		t.Fatal(err)
	}
	expectedMACA := "4a9ffac354dfafb3"
	if hex.EncodeToString(v.MACA) != expectedMACA {
		t.Errorf("MACA mismatch\ngot:  %x\nwant: %s", v.MACA, expectedMACA)
	}

	// Test ComputeF1s
	if err := milenage.ComputeF1s(&v); err != nil {
		t.Fatal(err)
	}
	expectedMACS := "01cfaf9ec4e871e9"
	if hex.EncodeToString(v.MACS) != expectedMACS {
		t.Errorf("MACS mismatch\ngot:  %x\nwant: %s", v.MACS, expectedMACS)
	}

	// Test ComputeF2345
	if err := milenage.ComputeF2345(&v); err != nil {
		t.Fatal(err)
	}

	expectedRES := "a54211d5e3ba50bf"
	if hex.EncodeToString(v.RES) != expectedRES {
		t.Errorf("RES mismatch\ngot:  %x\nwant: %s", v.RES, expectedRES)
	}

	expectedAK := "aa689c648370"
	if hex.EncodeToString(v.AK) != expectedAK {
		t.Errorf("AK mismatch\ngot:  %x\nwant: %s", v.AK, expectedAK)
	}

	expectedCK := "b40ba9a3c58b2a05bbf0d987b21bf8cb"
	if hex.EncodeToString(v.CK) != expectedCK {
		t.Errorf("CK mismatch\ngot:  %x\nwant: %s", v.CK, expectedCK)
	}

	expectedIK := "f769bcd751044604127672711c6d3441"
	if hex.EncodeToString(v.IK) != expectedIK {
		t.Errorf("IK mismatch\ngot:  %x\nwant: %s", v.IK, expectedIK)
	}

	// Test ComputeF5s
	if err := milenage.ComputeF5s(&v); err != nil {
		t.Fatal(err)
	}
	expectedAKF5 := "451e8beca43b"
	if hex.EncodeToString(v.AKF5) != expectedAKF5 {
		t.Errorf("AKF5 mismatch\ngot:  %x\nwant: %s", v.AKF5, expectedAKF5)
	}
}

func TestMilenage_ValidationErrors(t *testing.T) {
	milenage := algorithms.NewMilenage()
	v := &algorithms.Variables{}

	// Test invalid K length
	v.K = []byte{1, 2, 3} // invalid
	err := milenage.ComputeTOPC(v)
	if err == nil {
		t.Error("Expected error for invalid K length")
	}

	// Test invalid TOP length
	v.K = make([]byte, 16)
	v.TOP = []byte{1, 2, 3} // invalid
	err = milenage.ComputeTOPC(v)
	if err == nil {
		t.Error("Expected error for invalid TOP length")
	}
}

func TestVariables_ComputeAUTN(t *testing.T) {
	v := &algorithms.Variables{
		SQN:  []byte{0x00, 0x00, 0x00, 0x00, 0x0c, 0x80},
		AK:   []byte{0xaa, 0x68, 0x9c, 0x64, 0x83, 0x70},
		AMF:  []byte{0x80, 0x00},
		MACA: []byte{0x4a, 0x9f, 0xfa, 0xc3, 0x54, 0xdf, 0xaf, 0xb3},
	}

	err := v.ComputeAUTN()
	if err != nil {
		t.Fatal(err)
	}

	if len(v.AUTN) != 16 {
		t.Errorf("AUTN length should be 16, got %d", len(v.AUTN))
	}

	t.Logf("AUTN: %x", v.AUTN)
}

func TestVariables_ComputeKASME(t *testing.T) {
	v := &algorithms.Variables{
		CK:  make([]byte, 16),
		IK:  make([]byte, 16),
		SQN: make([]byte, 6),
		AK:  make([]byte, 6),
	}

	// Fill with test data
	for i := range v.CK {
		v.CK[i] = byte(i)
	}
	for i := range v.IK {
		v.IK[i] = byte(i + 16)
	}

	kasme, err := v.ComputeKASME(250, 88)
	if err != nil {
		t.Fatal(err)
	}

	if len(kasme) != 32 {
		t.Errorf("KASME length should be 32, got %d", len(kasme))
	}

	t.Logf("KASME: %x", kasme)
}
