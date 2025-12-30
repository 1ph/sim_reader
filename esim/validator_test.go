package esim

import (
	"testing"
)

func TestValidateProfile_MinimalValid(t *testing.T) {
	// Create minimal valid profile
	profile := &Profile{
		Header: &ProfileHeader{
			MajorVersion: 2,
			MinorVersion: 3,
			ProfileType:  "test",
			ICCID:        []byte{0x89, 0x70, 0x15, 0x01, 0x07, 0x80, 0x00, 0x00, 0x68, 0x14}, // 89701501078000006814
		},
		MF: &MasterFile{},
		USIM: &USIMApplication{
			EF_IMSI: &ElementaryFile{
				FillContents: []FillContent{
					{Content: []byte{0x08, 0x52, 0x08, 0x88, 0x00, 0x00, 0x00, 0x01, 0x00}}, // 250880000000010
				},
			},
		},
		AKAParams: []*AKAParameter{
			{
				AlgoConfig: &AlgoConfiguration{
					AlgorithmID: AlgoMilenage,
					Key:         make([]byte, 16),
					OPC:         make([]byte, 16),
				},
			},
		},
		PukCodes: &PUKCodes{
			Codes: []PUKCode{
				{KeyReference: 0x01, PUKValue: []byte("12345678")},
			},
		},
		PinCodes: []*PINCodes{
			{
				Configs: []PINConfig{
					{KeyReference: 0x01, PINValue: []byte("1234\xff\xff\xff\xff")},
				},
			},
		},
		End: &EndElement{},
	}

	result := ValidateProfile(profile, nil)

	if !result.Valid {
		t.Errorf("Expected valid profile, got errors: %v", result.Errors)
	}

	// Check that we have expected checks
	checkNames := make(map[string]bool)
	for _, check := range result.Checks {
		checkNames[check.Name] = check.Passed
	}

	expectedChecks := []string{"ProfileHeader", "MasterFile", "ProfileEnd", "ICCID", "IMSI", "AKA", "PIN/PUK"}
	for _, name := range expectedChecks {
		if _, ok := checkNames[name]; !ok {
			t.Errorf("Expected check %s not found", name)
		}
	}
}

func TestValidateProfile_MissingHeader(t *testing.T) {
	profile := &Profile{
		MF:  &MasterFile{},
		End: &EndElement{},
	}

	result := ValidateProfile(profile, nil)

	if result.Valid {
		t.Error("Expected invalid profile for missing header")
	}

	// Check for header error
	hasHeaderError := false
	for _, err := range result.Errors {
		if err.Field == "Header" {
			hasHeaderError = true
			break
		}
	}
	if !hasHeaderError {
		t.Error("Expected error about missing header")
	}
}

func TestValidateProfile_InvalidICCID(t *testing.T) {
	tests := []struct {
		name     string
		iccid    []byte
		wantErr  bool
		errField string
	}{
		{
			name:     "empty ICCID",
			iccid:    nil,
			wantErr:  true,
			errField: "ICCID",
		},
		{
			name:     "too short ICCID",
			iccid:    []byte{0x89, 0x70, 0x15}, // only 6 digits
			wantErr:  true,
			errField: "ICCID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &Profile{
				Header: &ProfileHeader{
					MajorVersion: 2,
					MinorVersion: 3,
					ICCID:        tt.iccid,
				},
				MF:  &MasterFile{},
				End: &EndElement{},
			}

			result := ValidateProfile(profile, nil)

			if tt.wantErr && result.Valid {
				t.Error("Expected validation to fail")
			}

			if tt.wantErr {
				hasError := false
				for _, err := range result.Errors {
					if err.Field == tt.errField {
						hasError = true
						break
					}
				}
				if !hasError {
					t.Errorf("Expected error for field %s", tt.errField)
				}
			}
		})
	}
}

func TestValidateProfile_InvalidAKA(t *testing.T) {
	tests := []struct {
		name    string
		aka     *AKAParameter
		wantErr bool
	}{
		{
			name:    "missing AKA params",
			aka:     nil,
			wantErr: true,
		},
		{
			name: "missing AlgoConfig",
			aka: &AKAParameter{
				AlgoConfig: nil,
			},
			wantErr: true,
		},
		{
			name: "missing Ki",
			aka: &AKAParameter{
				AlgoConfig: &AlgoConfiguration{
					AlgorithmID: AlgoMilenage,
					Key:         nil,
					OPC:         make([]byte, 16),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid Ki length",
			aka: &AKAParameter{
				AlgoConfig: &AlgoConfiguration{
					AlgorithmID: AlgoMilenage,
					Key:         make([]byte, 10), // wrong length
					OPC:         make([]byte, 16),
				},
			},
			wantErr: true,
		},
		{
			name: "valid Milenage",
			aka: &AKAParameter{
				AlgoConfig: &AlgoConfiguration{
					AlgorithmID: AlgoMilenage,
					Key:         make([]byte, 16),
					OPC:         make([]byte, 16),
				},
			},
			wantErr: false,
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
				MF:   &MasterFile{},
				USIM: &USIMApplication{},
				End:  &EndElement{},
			}

			if tt.aka != nil {
				profile.AKAParams = []*AKAParameter{tt.aka}
			}

			result := ValidateProfile(profile, nil)

			hasAKAError := false
			for _, err := range result.Errors {
				if err.Field == "AKA" || err.Field == "Ki" {
					hasAKAError = true
					break
				}
			}

			if tt.wantErr && !hasAKAError {
				t.Error("Expected AKA validation error")
			}
			if !tt.wantErr && hasAKAError {
				t.Error("Did not expect AKA validation error")
			}
		})
	}
}

func TestValidateProfile_Applications(t *testing.T) {
	tests := []struct {
		name    string
		apps    []*Application
		wantErr bool
	}{
		{
			name:    "no applications (valid)",
			apps:    nil,
			wantErr: false,
		},
		{
			name: "valid application",
			apps: []*Application{
				{
					LoadBlock: &ApplicationLoadPackage{
						LoadPackageAID:  []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
						LoadBlockObject: make([]byte, 100),
					},
					InstanceList: []*ApplicationInstance{
						{
							ApplicationLoadPackageAID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
							ClassAID:                  []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01},
							InstanceAID:               []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x01, 0x01},
							ProcessData: [][]byte{
								{0x80, 0xE2, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid AID (too short)",
			apps: []*Application{
				{
					LoadBlock: &ApplicationLoadPackage{
						LoadPackageAID:  []byte{0xA0, 0x00}, // too short
						LoadBlockObject: make([]byte, 100),
					},
					InstanceList: []*ApplicationInstance{
						{
							ApplicationLoadPackageAID: []byte{0xA0, 0x00},
							ClassAID:                  []byte{0xA0, 0x00, 0x00},
							InstanceAID:               []byte{0xA0, 0x00, 0x00, 0x00},
						},
					},
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
				Applications: tt.apps,
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
				t.Errorf("Expected application validation error, got none. Errors: %v", result.Errors)
			}
			if !tt.wantErr && hasAppError {
				t.Errorf("Did not expect application validation error, got: %v", result.Errors)
			}
		})
	}
}

func TestIsValidAID(t *testing.T) {
	tests := []struct {
		name  string
		aid   []byte
		valid bool
	}{
		{"valid 5 bytes", []byte{0xA0, 0x00, 0x00, 0x00, 0x03}, true},
		{"valid 16 bytes", make([]byte, 16), true},
		{"too short 4 bytes", []byte{0xA0, 0x00, 0x00, 0x00}, false},
		{"too long 17 bytes", make([]byte, 17), false},
		{"empty", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidAID(tt.aid)
			if result != tt.valid {
				t.Errorf("isValidAID(%v) = %v, want %v", tt.aid, result, tt.valid)
			}
		})
	}
}

func TestIsValidAPDU(t *testing.T) {
	tests := []struct {
		name  string
		apdu  []byte
		valid bool
	}{
		{"case 1 - 4 bytes", []byte{0x00, 0xA4, 0x00, 0x00}, true},
		{"case 2 - 5 bytes", []byte{0x00, 0xA4, 0x00, 0x00, 0x10}, true},
		{"case 3 - with data", []byte{0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00}, true},
		{"case 4 - data + Le", []byte{0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00, 0x00}, true},
		{"too short", []byte{0x00, 0xA4, 0x00}, false},
		{"empty", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidAPDU(tt.apdu)
			if result != tt.valid {
				t.Errorf("isValidAPDU(%v) = %v, want %v", tt.apdu, result, tt.valid)
			}
		})
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		iccid string
		valid bool
	}{
		{"89701501078000006814", true},  // Test ICCID with valid Luhn
		{"79927398713", true},           // Standard Luhn test number
		{"79927398710", false},          // Invalid Luhn
		{"12345", false},                // Too short
		{"", false},                     // Empty
	}

	for _, tt := range tests {
		t.Run(tt.iccid, func(t *testing.T) {
			result := luhnCheck(tt.iccid)
			if result != tt.valid {
				t.Errorf("luhnCheck(%s) = %v, want %v", tt.iccid, result, tt.valid)
			}
		})
	}
}

