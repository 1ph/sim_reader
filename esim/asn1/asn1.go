package asn1

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// +---------------------------------------------------------------+
// |   H   |   G   |   F   |   E   |   D   |   C   |   B   |   A   |
// +---------------------------------------------------------------+
// |     Class     | Form  |               Tag Code                |
// +---------------------------------------------------------------+

// Class represents ASN.1 tag class
type Class byte

const (
	ClassUniversal       Class = 0
	ClassApplication     Class = 1
	ClassContextSpecific Class = 2
	ClassPrivate         Class = 3
)

func (c Class) String() string {
	switch c {
	case 0:
		return "Universal"
	case 1:
		return "Application-wide"
	case 2:
		return "Context-specific"
	case 3:
		return "Private use"
	}
	return ""
}

// Form represents ASN.1 tag form (primitive or constructed)
type Form byte

const (
	FormPrimitive   Form = 0
	FormConstructed Form = 1
)

func (f Form) String() string {
	switch f {
	case 0:
		return "Primitive"
	case 1:
		return "Constructor"
	}
	return ""
}

// ASN1 represents an ASN.1 TLV structure for parsing and marshaling
type ASN1 struct {
	Packet  []byte // raw data to be parsed
	Tag     byte   // first byte of tag
	Class   Class  // tag class
	Form    Form   // tag form
	TagCode byte   // tag code (for short tags) or low byte (for long tags)
	FullTag int    // full tag number for CHOICE > 30
	Length  int    // content length
	HLength int    // header length (tag + length bytes)
	Data    []byte // encapsulated data
	Padding []byte // end-of-content marker (00 00) for indefinite length
	EOF     bool   // no more data following this packet
}

var paddingBytes = []byte{0, 0}

// Init initializes ASN1 structure for parsing
func Init(b []byte) *ASN1 { return &ASN1{Packet: b} }

// DataLen returns length of parsed data
func (a *ASN1) DataLen() int { return len(a.Data) }

// PacketLen returns remaining packet length
func (a *ASN1) PacketLen() int { return len(a.Packet) }

// FullLen returns total length of parsed element (header + data + padding)
func (a *ASN1) FullLen() int { return a.HLength + len(a.Data) + len(a.Padding) }

// Unmarshal parses the next ASN.1 element from the packet
func (a *ASN1) Unmarshal() bool {
	lenPacket := len(a.Packet)
	a.HLength = 0
	a.Length = 0
	a.Data = []byte{}
	a.Padding = []byte{}
	a.FullTag = 0
	if lenPacket > 0 {
		a.Tag = a.Packet[0]
		a.HLength++
	}
	if lenPacket >= 2 { // normal size packet
		a.Form = Form(a.Tag >> 5 & 1)
		a.Class = Class(a.Tag >> 6 & 3)

		if a.Tag&0x1F == 0x1F { // long tag form (tag >= 31)
			// multi-byte long tag support
			tagCode := 0
			for a.HLength < lenPacket {
				b := a.Packet[a.HLength]
				a.HLength++
				tagCode = (tagCode << 7) | int(b&0x7F)
				if b&0x80 == 0 {
					break
				}
			}
			a.TagCode = byte(tagCode & 0xFF)
			a.FullTag = tagCode
		} else { // short tag form
			a.TagCode = a.Tag & 31
			a.FullTag = int(a.TagCode)
		}
		a.HLength++ // account for length byte
		// try to determine length
		if len(a.Packet) > a.HLength-1 { // protection against malformed packets
			a.Length = int(a.Packet[a.HLength-1])
			if a.Length > 128 { // long length form
				codedLen := 0
				lenCodedLen := a.Length & 0x7F
				if lenCodedLen > lenPacket-a.HLength { // protection against panic
					lenCodedLen = lenPacket - a.HLength
				}
				for i := 0; i < lenCodedLen; i++ {
					codedLen = 256*codedLen + int(a.Packet[a.HLength])
					a.HLength++
				}
				a.Length = codedLen
				if a.Length < 0 {
					a.Data = a.Packet
					a.Packet = []byte{}
					return true
				}
			} else if a.Length == 0 {
				if len(a.Packet) >= a.HLength {
					a.Packet = a.Packet[a.HLength:]
				}
				return true
			} else if a.Length == 128 { // indefinite length
				var (
					eop               = true
					undefLenPacket    = 0
					paddingStartPoint = 0
					b                 = Init(a.Packet[a.HLength:])
				)
				for eop {
					b.Unmarshal()
					if b.Tag == 0 {
						paddingStartPoint = undefLenPacket
						eop = false

					} else if len(b.Packet) < 2 { // protection against 1-byte packet
						eop = false

					} else if len(b.Packet) == 2 && b.Packet[1] != 0 { // protection against malformed packet
						eop = false

					} else {
						undefLenPacket += b.FullLen()
						b = Init(b.Packet)
					}
				}
				if lenPacket > a.HLength+paddingStartPoint {
					a.Data = a.Packet[a.HLength : a.HLength+paddingStartPoint]
					a.Length = len(a.Data)
					a.Padding = paddingBytes
					if lenPacket > a.HLength+paddingStartPoint+2 {
						a.Packet = a.Packet[a.HLength+paddingStartPoint+2:]
					} else {
						a.Packet = []byte{}
					}
					return true
				}

			}
			if lenPacket >= a.HLength {
				if lenPacket >= a.Length+a.HLength {
					a.Data = a.Packet[a.HLength : a.Length+a.HLength]
					a.Packet = a.Packet[a.Length+a.HLength:]
					return true
				}
				a.Data = a.Packet[a.HLength:]
				a.Packet = []byte{}
				return true
			}
			a.Data = a.Packet
			a.Packet = []byte{}
			return true
		}
	}
	return false
}

// Marshal creates ASN.1 TLV from tag, padding and data
func Marshal(tag byte, padding []byte, data ...byte) (b []byte) {
	if tag == 31 {
		b = append(b, 191)
	}
	b = append(b, tag)
	if len(padding) > 0 {
		b = append(b, 128)
		b = append(b, data...)
		b = append(b, padding...)
		return
	}
	b = append(b, encodeLength(len(data))...)
	b = append(b, data...)
	return
}

// MarshalLong creates ASN.1 TLV with two-byte tag
func MarshalLong(tag1, tag2 byte, padding []byte, data ...byte) (b []byte) {
	b = append(b, tag1)
	b = append(b, tag2)
	if len(padding) > 0 {
		b = append(b, 128)
		b = append(b, data...)
		b = append(b, padding...)
		return
	}
	b = append(b, encodeLength(len(data))...)
	b = append(b, data...)
	return
}

// MarshalWithFullTag creates ASN.1 TLV for tags > 30 (e.g., BF 37)
func MarshalWithFullTag(class Class, form Form, tagNum int, data []byte) []byte {
	var result []byte

	if tagNum <= 30 {
		// short tag
		result = append(result, byte(class)<<6|byte(form)<<5|byte(tagNum))
	} else {
		// long tag
		result = append(result, byte(class)<<6|byte(form)<<5|0x1F)
		// encode tag number in base-128
		result = append(result, encodeTagNumber(tagNum)...)
	}

	// length + data
	result = append(result, encodeLength(len(data))...)
	result = append(result, data...)

	return result
}

// encodeTagNumber encodes tag number in base-128 format
func encodeTagNumber(tagNum int) []byte {
	if tagNum == 0 {
		return []byte{0}
	}

	var tagBytes []byte
	for n := tagNum; n > 0; n >>= 7 {
		tagBytes = append([]byte{byte(n & 0x7F)}, tagBytes...)
	}
	// set continuation bit for all bytes except last
	for i := 0; i < len(tagBytes)-1; i++ {
		tagBytes[i] |= 0x80
	}
	return tagBytes
}

// encodeLength encodes length in DER format
func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}

	var lenBytes []byte
	for l := length; l > 0; l >>= 8 {
		lenBytes = append([]byte{byte(l & 0xFF)}, lenBytes...)
	}

	result := []byte{byte(0x80 | len(lenBytes))}
	result = append(result, lenBytes...)
	return result
}

// Marshal rebuilds the packet from current state
func (a *ASN1) Marshal() {
	a.Packet = append(Marshal(a.Tag, a.Padding, a.Data...), a.Packet...)
}

// Itoa converts uint32 to byte slice of specified size
func Itoa(i uint32, size int) []byte {
	var buff = new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, i)
	b := buff.Bytes()
	if len(b) > size {
		return b[len(b)-size:]
	}
	return b
}

// Uint32ToByte converts uint32 to minimal byte representation
func Uint32ToByte(i uint32) []byte {
	var size int
	if i <= 255 {
		size = 1
	} else if i <= 65535 {
		size = 2
	} else if i <= 16777215 {
		size = 3
	} else {
		size = 4
	}
	var buff = new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, i)
	b := buff.Bytes()
	if len(b) > size {
		return b[len(b)-size:]
	}
	return b
}

// IntToByte converts uint64 to minimal byte representation
func IntToByte(i uint64) []byte {
	var size int
	if i <= 255 {
		size = 1
	} else if i <= 65535 {
		size = 2
	} else if i <= 16777215 {
		size = 3
	} else if i <= 4294967295 {
		size = 4
	} else {
		size = 8
	}
	var buff = new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, i)
	b := buff.Bytes()
	if len(b) > size {
		return b[len(b)-size:]
	}
	return b
}

// Atoi converts Data field to uint32
func (a *ASN1) Atoi() uint32 {
	switch len(a.Data) {
	case 0:
		return 0
	case 1:
		return uint32(a.Data[0])
	case 2:
		return uint32(a.Data[0])<<8 + uint32(a.Data[1])
	case 3:
		return uint32(a.Data[0])<<16 + uint32(a.Data[1])<<8 + uint32(a.Data[2])
	case 4:
		return uint32(a.Data[0])<<24 + uint32(a.Data[1])<<16 + uint32(a.Data[2])<<8 + uint32(a.Data[3])
	default:
		return 0
	}
}

// PrintTree recursively prints ASN.1 structure
func (a *ASN1) PrintTree(o int) {
	for a.Unmarshal() {
		var padding string
		for i := 0; i < o; i++ {
			padding += " | "
		}
		fmt.Printf("{%v Tag:%02x, TagCode:%2v, FullTag:%v, Class:%v, Form:%v, Len:%v, P:%v, D:%v}\n",
			padding, a.Tag, a.TagCode, a.FullTag, a.Class, a.Form, a.Length, hex.EncodeToString(a.Padding), hex.EncodeToString(a.Data))
		if a.Form == 1 {
			b := Init(a.Data)
			b.PrintTree(o + 1)
		}
	}
}

// ASNPrint prints ASN1 structure details
func (a ASN1) ASNPrint() {
	fmt.Println("{")
	fmt.Println("    Tag :", a.Tag)
	fmt.Println("    TagCode :", a.TagCode)
	fmt.Println("    FullTag :", a.FullTag)
	fmt.Println("    Class :", a.Class)
	fmt.Println("    Form :", a.Form)
	fmt.Println("    Length :", a.Length)
	fmt.Println("    Data :", hex.EncodeToString(a.Data))
	fmt.Println("    Actual length :", len(a.Data))
	fmt.Println("    Padding :", hex.EncodeToString(a.Padding))
	fmt.Println("    Packet :", hex.EncodeToString(a.Packet))
	fmt.Println("}")
}
