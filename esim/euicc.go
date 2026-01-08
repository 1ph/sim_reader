package esim

import (
	"encoding/hex"
	"fmt"
	"sim_reader/card"
	"sim_reader/esim/asn1"
)

const (
	ISD_R_AID = "A0000005591010FFFFFFFF8900000100"
)

type EUICC struct {
	reader  *card.Reader
	channel byte
}

type ProfileInfo struct {
	ICCID           string
	ISDP_AID        string
	State           string // "enabled", "disabled"
	Nickname        string
	ServiceProvider string
	ProfileName     string
	ProfileClass    string
}

func NewEUICC(reader *card.Reader) *EUICC {
	return &EUICC{
		reader: reader,
	}
}

func (e *EUICC) Init() error {
	// 1. Open logical channel
	channel, err := e.reader.LogicChannelOpen()
	if err != nil {
		return fmt.Errorf("failed to open logical channel: %w", err)
	}
	e.channel = channel

	// 2. Select ISD-R
	aid, _ := hex.DecodeString(ISD_R_AID)
	resp, err := e.reader.SelectOnChannel(aid, e.channel)
	if err != nil {
		e.reader.LogicChannelClose(e.channel)
		return fmt.Errorf("failed to select ISD-R: %w", err)
	}
	if !resp.IsOK() {
		e.reader.LogicChannelClose(e.channel)
		return fmt.Errorf("ISD-R selection failed: %s", card.SWToString(resp.SW()))
	}

	return nil
}

func (e *EUICC) Close() {
	if e.channel != 0 {
		e.reader.LogicChannelClose(e.channel)
		e.channel = 0
	}
}

// TransmitES10x sends a command to eUICC using Store Data (80 E2)
// and handles segmentation/response assembly.
func (e *EUICC) TransmitES10x(data []byte) ([]byte, error) {
	var fullResponse []byte
	
	mss := 120 
	offset := 0
	seq := byte(0)
	
	for offset < len(data) {
		remaining := len(data) - offset
		chunkSize := mss
		p1 := byte(0x11) 
		
		if remaining <= mss {
			chunkSize = remaining
			p1 = byte(0x91) 
		}
		
		apdu := make([]byte, 5+chunkSize)
		apdu[0] = 0x80 | e.channel
		apdu[1] = 0xE2 
		apdu[2] = p1
		apdu[3] = seq
		apdu[4] = byte(chunkSize)
		copy(apdu[5:], data[offset:offset+chunkSize])
		
		resp, err := e.reader.SendAPDU(apdu)
		if err != nil {
			return nil, err
		}
		
		for {
			if len(resp.Data) > 0 {
				fullResponse = append(fullResponse, resp.Data...)
			}
			
			if resp.HasMoreData() {
				resp, err = e.reader.GetResponseOnChannel(resp.SW2, e.channel)
				if err != nil {
					return nil, err
				}
				continue
			}
			
			if resp.IsOK() {
				break
			}
			
			return nil, fmt.Errorf("eUICC command failed: %s", card.SWToString(resp.SW()))
		}
		
		offset += chunkSize
		seq++
	}
	
	return fullResponse, nil
}

// ListProfiles retrieves profile information from the eUICC
func (e *EUICC) ListProfiles() ([]ProfileInfo, error) {
	// ProfileInfoListRequest [BF2D]
	cmd := asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 0x2D, nil)
	
	respData, err := e.TransmitES10x(cmd)
	if err != nil {
		return nil, err
	}
	
	a := asn1.Init(respData)
	if !a.Unmarshal() || a.FullTag != 0x2D {
		return nil, fmt.Errorf("unexpected response tag: %02X", a.Tag)
	}
	
	// Response is a CHOICE. 0xA0 is profileInfoListOk
	b := asn1.Init(a.Data)
	if !b.Unmarshal() || b.FullTag != 0 { 
		return nil, fmt.Errorf("failed to parse profileInfoListOk")
	}
	
	var profiles []ProfileInfo
	c := asn1.Init(b.Data)
	for c.Unmarshal() {
		if c.Tag != 0xE3 { 
			continue
		}
		
		info := ProfileInfo{}
		d := asn1.Init(c.Data)
		for d.Unmarshal() {
			switch d.Tag {
			case 0x5A: // iccid
				info.ICCID = decodeSwappedBCD(d.Data)
			case 0x90: // profileNickname
				info.Nickname = string(d.Data)
			case 0x91: // serviceProviderName
				info.ServiceProvider = string(d.Data)
			case 0x92: // profileName
				info.ProfileName = string(d.Data)
			case 0x4F: // isdpAid
				info.ISDP_AID = hex.EncodeToString(d.Data)
			default:
				switch d.FullTag {
				case 0x70: // 0x9F70 profileState
					state := decodeInteger(d.Data)
					if state == 1 {
						info.State = "enabled"
					} else {
						info.State = "disabled"
					}
				case 0x15: // 0x95 profileClass
					class := decodeInteger(d.Data)
					switch class {
					case 0: info.ProfileClass = "test"
					case 1: info.ProfileClass = "provisioning"
					case 2: info.ProfileClass = "operational"
					}
				}
			}
		}
		profiles = append(profiles, info)
	}
	
	return profiles, nil
}

// EnableProfile enables a profile by ICCID
func (e *EUICC) EnableProfile(iccid string) error {
	return e.profileAction(0x31, iccid) // EnableProfileRequest [BF31]
}

// DisableProfile disables a profile by ICCID
func (e *EUICC) DisableProfile(iccid string) error {
	return e.profileAction(0x32, iccid) // DisableProfileRequest [BF32]
}

// DeleteProfile deletes a profile by ICCID
func (e *EUICC) DeleteProfile(iccid string) error {
	return e.profileAction(0x33, iccid) // DeleteProfileRequest [BF33]
}

// GetEuiccInfo1 retrieves EUICCInfo1 from the eUICC
func (e *EUICC) GetEuiccInfo1() ([]byte, error) {
	// GetEuiccInfo1Request [BF20]
	cmd := asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 0x20, nil)
	return e.TransmitES10x(cmd)
}

// GetEuiccChallenge retrieves a challenge from the eUICC
func (e *EUICC) GetEuiccChallenge() ([]byte, error) {
	// GetEuiccChallengeRequest [BF2E]
	tagNum := 0x2E
	cmd := asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, tagNum, nil)
	resp, err := e.TransmitES10x(cmd)
	if err != nil {
		return nil, err
	}

	a := asn1.Init(resp)
	if !a.Unmarshal() || a.FullTag != tagNum {
		return nil, fmt.Errorf("unexpected response tag for challenge: %02X (expected %02X)", a.Tag, 0xBF)
	}

	// Response is a CHOICE. 0x80 is euiccChallenge (Context-specific tag 0)
	b := asn1.Init(a.Data)
	if !b.Unmarshal() || b.Class != asn1.ClassContextSpecific || b.FullTag != 0 {
		return nil, fmt.Errorf("failed to parse euiccChallenge")
	}

	return b.Data, nil
}

// AuthenticateServer sends the server authentication response to the eUICC
func (e *EUICC) AuthenticateServer(authenticateServerResponse []byte) ([]byte, error) {
	// AuthenticateServerRequest [BF38]
	cmd := asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 0x38, authenticateServerResponse)
	return e.TransmitES10x(cmd)
}

// PrepareDownload sends the prepare download response to the eUICC
func (e *EUICC) PrepareDownload(prepareDownloadResponse []byte) ([]byte, error) {
	// PrepareDownloadRequest [BF21]
	cmd := asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 0x21, prepareDownloadResponse)
	return e.TransmitES10x(cmd)
}

// LoadBoundProfilePackage installs the BPP on the eUICC
func (e *EUICC) LoadBoundProfilePackage(bpp []byte) error {
	// This command is special as it can be very large and uses multiple segments
	// but e.TransmitES10x already handles segmentation.
	// Tag is [BF36]
	cmd := asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 0x36, bpp)
	_, err := e.TransmitES10x(cmd)
	return err
}

func (e *EUICC) profileAction(tagNum int, iccid string) error {
	// 1. Encode ICCID to Swapped BCD (10 bytes)
	iccidBytes := encodeSwappedBCD(iccid)
	for len(iccidBytes) < 10 {
		iccidBytes = append(iccidBytes, 0xFF)
	}
	if len(iccidBytes) > 10 {
		iccidBytes = iccidBytes[:10]
	}

	// 2. Build Profile Identifier (Tag 0x5A)
	iccidTagged := asn1.Marshal(0x5A, nil, iccidBytes...)

	// 3. Build the payload according to lpac structure
	var payload []byte
	
	if tagNum == 0x31 || tagNum == 0x32 { // Enable or Disable
		// Wrap iccid in A0 container (profileIdentifier CHOICE)
		profileIdChoice := asn1.Marshal(0xA0, nil, iccidTagged...)
		
		// refreshFlag [1] with value 0x00 (default) or 0xFF (force refresh)
		// lpac uses 0x00 for normal disable
		refresh := []byte{0x81, 0x01, 0x00}
		
		payload = append(profileIdChoice, refresh...)
	} else {
		// Delete (BF33): just the ICCID without wrapper
		payload = iccidTagged
	}

	// 4. Wrap in the command tag
	cmd := asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, tagNum, payload)

	respData, err := e.TransmitES10x(cmd)
	if err != nil {
		return err
	}

	if len(respData) == 0 {
		return fmt.Errorf("empty response from card")
	}

	a := asn1.Init(respData)
	if !a.Unmarshal() {
		return fmt.Errorf("failed to unmarshal response")
	}

	// Parse response: look for result code [0] or error [1]
	b := asn1.Init(a.Data)
	for b.Unmarshal() {
		if b.Class == asn1.ClassContextSpecific {
			if b.FullTag == 0 {
				// Success code [0]
				result := decodeInteger(b.Data)
				if result != 0 {
					return fmt.Errorf("operation failed with code: %d", result)
				}
				return nil
			} else if b.FullTag == 1 {
				// Error code [1]
				errCode := decodeInteger(b.Data)
				return fmt.Errorf("profile management error: %d (0x%X)", errCode, errCode)
			}
		}
	}

	return nil
}
