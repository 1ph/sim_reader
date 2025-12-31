package esim

import (
	"bytes"
	"testing"

	"sim_reader/sim"
)

func TestApplicationRoundTrip(t *testing.T) {
	// Create an Application with all fields populated
	original := &Application{
		Header: &ElementHeader{
			Mandated:       true,
			Identification: 1,
		},
		LoadBlock: &ApplicationLoadPackage{
			LoadPackageAID:    []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
			SecurityDomainAID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00},
			LoadBlockObject:   []byte{0x01, 0x02, 0x03, 0x04, 0x05}, // Minimal CAP-like data
		},
		InstanceList: []*ApplicationInstance{
			{
				ApplicationLoadPackageAID:   []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
				ClassAID:                    []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01},
				InstanceAID:                 []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01, 0x01},
				ApplicationPrivileges:       []byte{0x00, 0x00, 0x00},
				LifeCycleState:              0x07,
				ApplicationSpecificParamsC9: []byte{0x81, 0x00},
				ProcessData: [][]byte{
					{0x80, 0xE2, 0x00, 0x00, 0x12, 0x01, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
					{0x80, 0xE2, 0x00, 0x00, 0x12, 0x02, 0x10, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
				},
			},
		},
	}

	// Create profile element
	elem := &ProfileElement{
		Tag:   TagApplication,
		Value: original,
	}

	// Encode
	encoded, err := encodeProfileElement(elem)
	if err != nil {
		t.Fatalf("Failed to encode Application: %v", err)
	}

	if len(encoded) == 0 {
		t.Fatal("Encoded data is empty")
	}

	// Verify the tag (0xA8 = context-specific constructed tag 8)
	if encoded[0] != 0xA8 {
		t.Errorf("Expected tag 0xA8, got 0x%02X", encoded[0])
	}
}

func TestApplicationInstanceProcessData(t *testing.T) {
	inst := &ApplicationInstance{
		ApplicationLoadPackageAID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
		ClassAID:                  []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01},
		InstanceAID:               []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01, 0x01},
		ApplicationPrivileges:     []byte{0x00},
		LifeCycleState:            0x07,
		ProcessData: [][]byte{
			{0x80, 0xE2, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04},
			{0x80, 0xE2, 0x00, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
	}

	// Encode instance
	encoded := encodeApplicationInstance(inst)

	if len(encoded) == 0 {
		t.Fatal("Encoded instance is empty")
	}

	// Check that ProcessData is present (look for SEQUENCE tag 0x30)
	hasSequence := false
	for i := 0; i < len(encoded)-1; i++ {
		if encoded[i] == 0x30 {
			hasSequence = true
			break
		}
	}

	if !hasSequence {
		t.Error("Expected SEQUENCE tag for ProcessData not found")
	}
}

func TestApplicationLoadPackageEncode(t *testing.T) {
	pkg := &ApplicationLoadPackage{
		LoadPackageAID:         []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
		SecurityDomainAID:      []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00},
		NonVolatileCodeLimitC6: []byte{0x00, 0x10, 0x00},
		VolatileDataLimitC7:    []byte{0x00, 0x08, 0x00},
		NonVolatileDataLimitC8: []byte{0x00, 0x04, 0x00},
		LoadBlockObject:        []byte{0xCA, 0xFE, 0xBA, 0xBE}, // CAP header signature
	}

	encoded := encodeApplicationLoadPackage(pkg)

	if len(encoded) == 0 {
		t.Fatal("Encoded LoadPackage is empty")
	}

	// Verify APPLICATION 15 tag (0x4F) appears for LoadPackageAID
	if !bytes.Contains(encoded, []byte{0x4F}) {
		t.Error("Expected APPLICATION 15 tag (0x4F) not found")
	}

	// Verify PRIVATE 4 tag (0xC4) for LoadBlockObject
	if !bytes.Contains(encoded, []byte{0xC4}) {
		t.Error("Expected PRIVATE 4 tag (0xC4) not found")
	}
}

func TestApplicationValidation(t *testing.T) {
	tests := []struct {
		name    string
		app     *Application
		wantErr bool
	}{
		{
			name: "valid application with load block and instance",
			app: &Application{
				LoadBlock: &ApplicationLoadPackage{
					LoadPackageAID:  []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
					LoadBlockObject: make([]byte, 100),
				},
				InstanceList: []*ApplicationInstance{
					{
						ApplicationLoadPackageAID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
						ClassAID:                  []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01},
						InstanceAID:               []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01, 0x01},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "instance only (pre-loaded package reference)",
			app: &Application{
				InstanceList: []*ApplicationInstance{
					{
						ApplicationLoadPackageAID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
						ClassAID:                  []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01},
						InstanceAID:               []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01, 0x01},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid - AID too short",
			app: &Application{
				LoadBlock: &ApplicationLoadPackage{
					LoadPackageAID:  []byte{0xA0, 0x00}, // too short
					LoadBlockObject: make([]byte, 100),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &Profile{
				Header: &ProfileHeader{
					MajorVersion: 2,
					MinorVersion: 3,
					ICCID:        []byte{0x89, 0x70, 0x15, 0x01, 0x07, 0x80, 0x00, 0x00, 0x68, 0x14},
				},
				MF:           &MasterFile{},
				End:          &EndElement{},
				Applications: []*Application{tt.app},
				AKAParams: []*AKAParameter{
					{
						AlgoConfig: &AlgoConfiguration{
							AlgorithmID: AlgoMilenage,
							Key:         make([]byte, 16),
						},
					},
				},
			}

			result := ValidateProfile(profile, nil)

			hasAppError := false
			for _, err := range result.Errors {
				if len(err.Field) > 11 && err.Field[:11] == "Application" {
					hasAppError = true
					break
				}
			}

			if tt.wantErr && !hasAppError {
				t.Errorf("Expected application error, got none")
			}
			if !tt.wantErr && hasAppError {
				t.Errorf("Did not expect application error, got: %v", result.Errors)
			}
		})
	}
}

func TestBuildMilenageAPDUs(t *testing.T) {
	cfg := &sim.MilenageUSIMPersonalization{
		Ki:  "00112233445566778899AABBCCDDEEFF",
		OPc: "FFEEDDCCBBAA99887766554433221100",
		AMF: "8000",
	}

	apdus, err := buildMilenageAPDUs(cfg)
	if err != nil {
		t.Fatalf("buildMilenageAPDUs failed: %v", err)
	}

	// Should have at least Ki, OPc, and AMF APDUs
	if len(apdus) < 3 {
		t.Errorf("Expected at least 3 APDUs, got %d", len(apdus))
	}

	// Check each APDU has valid format
	for i, apdu := range apdus {
		if len(apdu) < 5 {
			t.Errorf("APDU[%d] too short: %d bytes", i, len(apdu))
		}
		// Check CLA=80, INS=E2 (STORE DATA)
		if apdu[0] != 0x80 || apdu[1] != 0xE2 {
			t.Errorf("APDU[%d] unexpected CLA/INS: %02X %02X", i, apdu[0], apdu[1])
		}
	}
}

func TestBuildMilenageAPDUs_WithOP(t *testing.T) {
	cfg := &sim.MilenageUSIMPersonalization{
		Ki: "00112233445566778899AABBCCDDEEFF",
		OP: "11111111111111111111111111111111", // OP instead of OPc
	}

	apdus, err := buildMilenageAPDUs(cfg)
	if err != nil {
		t.Fatalf("buildMilenageAPDUs failed: %v", err)
	}

	// Should have Ki and OP APDUs (tag 0x03 for OP vs 0x02 for OPc)
	if len(apdus) < 2 {
		t.Errorf("Expected at least 2 APDUs, got %d", len(apdus))
	}
}

func TestBuildMilenageAPDUs_InvalidKi(t *testing.T) {
	cfg := &sim.MilenageUSIMPersonalization{
		Ki:  "00112233", // Too short
		OPc: "FFEEDDCCBBAA99887766554433221100",
	}

	_, err := buildMilenageAPDUs(cfg)
	if err == nil {
		t.Error("Expected error for invalid Ki length")
	}
}
