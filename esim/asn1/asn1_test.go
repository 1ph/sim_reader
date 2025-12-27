package asn1

import (
	"encoding/hex"
	"testing"
)

func TestUnmarshalShortTag(t *testing.T) {
	// A0 03 80 01 05 = [0] constructed, length 3, containing [0] primitive value 5
	data, _ := hex.DecodeString("a003800105")
	a := Init(data)

	if !a.Unmarshal() {
		t.Fatal("Unmarshal failed")
	}

	if a.Tag != 0xA0 {
		t.Errorf("Tag: got %02X, want A0", a.Tag)
	}
	if a.TagCode != 0 {
		t.Errorf("TagCode: got %d, want 0", a.TagCode)
	}
	if a.FullTag != 0 {
		t.Errorf("FullTag: got %d, want 0", a.FullTag)
	}
	if a.Class != ClassContextSpecific {
		t.Errorf("Class: got %v, want Context-specific", a.Class)
	}
	if a.Form != FormConstructed {
		t.Errorf("Form: got %v, want Constructed", a.Form)
	}
	if a.Length != 3 {
		t.Errorf("Length: got %d, want 3", a.Length)
	}
	if hex.EncodeToString(a.Data) != "800105" {
		t.Errorf("Data: got %s, want 800105", hex.EncodeToString(a.Data))
	}
}

func TestUnmarshalLongTag(t *testing.T) {
	// BF 3F 05 A0 03 80 01 1F = [63] constructed, length 5
	data, _ := hex.DecodeString("bf3f05a00380011f")
	a := Init(data)

	if !a.Unmarshal() {
		t.Fatal("Unmarshal failed")
	}

	if a.Tag != 0xBF {
		t.Errorf("Tag: got %02X, want BF", a.Tag)
	}
	if a.TagCode != 0x3F {
		t.Errorf("TagCode: got %02X, want 3F", a.TagCode)
	}
	if a.FullTag != 63 {
		t.Errorf("FullTag: got %d, want 63", a.FullTag)
	}
	if a.Class != ClassContextSpecific {
		t.Errorf("Class: got %v, want Context-specific", a.Class)
	}
	if a.Form != FormConstructed {
		t.Errorf("Form: got %v, want Constructed", a.Form)
	}
	if a.Length != 5 {
		t.Errorf("Length: got %d, want 5", a.Length)
	}
}

func TestUnmarshalMultiByteLongTag(t *testing.T) {
	// BF 81 00 03 ... = tag > 127, needs 2 bytes for tag number
	// 0x81 0x00 = (1 << 7) | 0x80 for continuation, then 0x00 = 128
	// Actually: BF 81 00 = [256] but that's not right...
	// Let's use a simpler example: BF 81 00 = continuation bit set on 81
	// 0x81 = 1000 0001 = continuation + 1
	// 0x00 = 0000 0000 = 0
	// Tag = (1 << 7) | 0 = 128

	data, _ := hex.DecodeString("bf810003010203")
	a := Init(data)

	if !a.Unmarshal() {
		t.Fatal("Unmarshal failed")
	}

	if a.FullTag != 128 {
		t.Errorf("FullTag: got %d, want 128", a.FullTag)
	}
	if a.Length != 3 {
		t.Errorf("Length: got %d, want 3", a.Length)
	}
}

func TestUnmarshalLongLength(t *testing.T) {
	// 04 81 80 + 128 bytes of zeros = OCTET STRING, length 128
	data := make([]byte, 3+128)
	data[0] = 0x04 // OCTET STRING
	data[1] = 0x81 // long length, 1 byte follows
	data[2] = 0x80 // length = 128

	a := Init(data)

	if !a.Unmarshal() {
		t.Fatal("Unmarshal failed")
	}

	if a.Tag != 0x04 {
		t.Errorf("Tag: got %02X, want 04", a.Tag)
	}
	if a.Length != 128 {
		t.Errorf("Length: got %d, want 128", a.Length)
	}
	if len(a.Data) != 128 {
		t.Errorf("Data length: got %d, want 128", len(a.Data))
	}
}

func TestMarshal(t *testing.T) {
	tests := []struct {
		name     string
		tag      byte
		padding  []byte
		data     []byte
		expected string
	}{
		{
			name:     "short length",
			tag:      0x80,
			data:     []byte{0x01, 0x02, 0x03},
			expected: "8003010203",
		},
		{
			name:     "zero length",
			tag:      0x80,
			data:     []byte{},
			expected: "8000",
		},
		{
			name:     "long length",
			tag:      0x04,
			data:     make([]byte, 128),
			expected: "048180" + "00000000000000000000000000000000" +
				"00000000000000000000000000000000" +
				"00000000000000000000000000000000" +
				"00000000000000000000000000000000" +
				"00000000000000000000000000000000" +
				"00000000000000000000000000000000" +
				"00000000000000000000000000000000" +
				"00000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Marshal(tt.tag, tt.padding, tt.data...)
			if hex.EncodeToString(result) != tt.expected {
				t.Errorf("Marshal: got %s, want %s",
					hex.EncodeToString(result), tt.expected)
			}
		})
	}
}

func TestMarshalWithFullTag(t *testing.T) {
	tests := []struct {
		name     string
		class    Class
		form     Form
		tagNum   int
		data     []byte
		expected string
	}{
		{
			name:     "short tag 0",
			class:    ClassContextSpecific,
			form:     FormConstructed,
			tagNum:   0,
			data:     []byte{0x01},
			expected: "a00101",
		},
		{
			name:     "short tag 30",
			class:    ClassContextSpecific,
			form:     FormPrimitive,
			tagNum:   30,
			data:     []byte{0x01},
			expected: "9e0101",
		},
		{
			name:     "long tag 31",
			class:    ClassContextSpecific,
			form:     FormConstructed,
			tagNum:   31,
			data:     []byte{0x01},
			expected: "bf1f0101",
		},
		{
			name:     "long tag 63 (End)",
			class:    ClassContextSpecific,
			form:     FormConstructed,
			tagNum:   63,
			data:     []byte{0x01, 0x02, 0x03},
			expected: "bf3f03010203",
		},
		{
			name:     "long tag 128",
			class:    ClassContextSpecific,
			form:     FormConstructed,
			tagNum:   128,
			data:     []byte{0x01},
			expected: "bf81000101",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MarshalWithFullTag(tt.class, tt.form, tt.tagNum, tt.data)
			if hex.EncodeToString(result) != tt.expected {
				t.Errorf("MarshalWithFullTag: got %s, want %s",
					hex.EncodeToString(result), tt.expected)
			}
		})
	}
}

func TestEncodeLength(t *testing.T) {
	tests := []struct {
		length   int
		expected string
	}{
		{0, "00"},
		{1, "01"},
		{127, "7f"},
		{128, "8180"},
		{255, "81ff"},
		{256, "820100"},
		{65535, "82ffff"},
	}

	for _, tt := range tests {
		result := encodeLength(tt.length)
		if hex.EncodeToString(result) != tt.expected {
			t.Errorf("encodeLength(%d): got %s, want %s",
				tt.length, hex.EncodeToString(result), tt.expected)
		}
	}
}

func TestEncodeTagNumber(t *testing.T) {
	tests := []struct {
		tagNum   int
		expected string
	}{
		{0, "00"},
		{31, "1f"},
		{63, "3f"},
		{127, "7f"},
		{128, "8100"},
		{256, "8200"},
		{16383, "ff7f"},
	}

	for _, tt := range tests {
		result := encodeTagNumber(tt.tagNum)
		if hex.EncodeToString(result) != tt.expected {
			t.Errorf("encodeTagNumber(%d): got %s, want %s",
				tt.tagNum, hex.EncodeToString(result), tt.expected)
		}
	}
}

func TestUnmarshalMultipleElements(t *testing.T) {
	// Two elements: 80 01 01 and 81 02 02 03
	data, _ := hex.DecodeString("80010181020203")
	a := Init(data)

	// First element
	if !a.Unmarshal() {
		t.Fatal("First Unmarshal failed")
	}
	if a.Tag != 0x80 || a.Length != 1 {
		t.Errorf("First element: Tag=%02X Len=%d", a.Tag, a.Length)
	}

	// Second element
	if !a.Unmarshal() {
		t.Fatal("Second Unmarshal failed")
	}
	if a.Tag != 0x81 || a.Length != 2 {
		t.Errorf("Second element: Tag=%02X Len=%d", a.Tag, a.Length)
	}

	// No more elements
	if a.Unmarshal() {
		t.Error("Should not have more elements")
	}
}

func TestAtoi(t *testing.T) {
	tests := []struct {
		data     []byte
		expected uint32
	}{
		{[]byte{}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0xFF}, 255},
		{[]byte{0x01, 0x00}, 256},
		{[]byte{0xFF, 0xFF}, 65535},
		{[]byte{0x01, 0x00, 0x00}, 65536},
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF}, 4294967295},
	}

	for _, tt := range tests {
		a := &ASN1{Data: tt.data}
		result := a.Atoi()
		if result != tt.expected {
			t.Errorf("Atoi(%v): got %d, want %d",
				tt.data, result, tt.expected)
		}
	}
}

func TestClassString(t *testing.T) {
	tests := []struct {
		class    Class
		expected string
	}{
		{ClassUniversal, "Universal"},
		{ClassApplication, "Application-wide"},
		{ClassContextSpecific, "Context-specific"},
		{ClassPrivate, "Private use"},
	}

	for _, tt := range tests {
		if tt.class.String() != tt.expected {
			t.Errorf("Class.String(): got %s, want %s", tt.class.String(), tt.expected)
		}
	}
}

func TestFormString(t *testing.T) {
	tests := []struct {
		form     Form
		expected string
	}{
		{FormPrimitive, "Primitive"},
		{FormConstructed, "Constructor"},
	}

	for _, tt := range tests {
		if tt.form.String() != tt.expected {
			t.Errorf("Form.String(): got %s, want %s", tt.form.String(), tt.expected)
		}
	}
}

