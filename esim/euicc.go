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

	mss := 120 // Maximum Segment Size, default from lpac
	offset := 0
	seq := byte(0)

	for offset < len(data) {
		remaining := len(data) - offset
		chunkSize := mss
		p1 := byte(0x11) // More fragments

		if remaining <= mss {
			chunkSize = remaining
			p1 = byte(0x91) // Last fragment
		}

		apdu := make([]byte, 5+chunkSize)
		apdu[0] = 0x80 | e.channel
		apdu[1] = 0xE2 // Store Data
		apdu[2] = p1
		apdu[3] = seq
		apdu[4] = byte(chunkSize)
		copy(apdu[5:], data[offset:offset+chunkSize])

		resp, err := e.reader.SendAPDU(apdu)
		if err != nil {
			return nil, err
		}

		// Handle response assembly
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
	if !a.Unmarshal() || a.FullTag != 0xBF2D {
		return nil, fmt.Errorf("unexpected response tag: %02X", a.Tag)
	}

	// Response is a CHOICE. 0xA0 is profileInfoListOk
	b := asn1.Init(a.Data)
	if !b.Unmarshal() || b.FullTag != 0 { // Context-specific tag 0
		return nil, fmt.Errorf("failed to parse profileInfoListOk")
	}

	var profiles []ProfileInfo
	c := asn1.Init(b.Data)
	for c.Unmarshal() {
		if c.FullTag != 0xE3 { // ProfileInfo tag
			continue
		}

		info := ProfileInfo{}
		d := asn1.Init(c.Data)
		for d.Unmarshal() {
			switch d.FullTag {
			case 0x5A: // iccid
				info.ICCID = decodeBCD(d.Data)
			case 0x90: // profileNickname
				info.Nickname = string(d.Data)
			case 0x91: // serviceProviderName
				info.ServiceProvider = string(d.Data)
			case 0x92: // profileName
				info.ProfileName = string(d.Data)
			case 0x9F70: // profileState
				state := decodeInteger(d.Data)
				if state == 1 {
					info.State = "enabled"
				} else {
					info.State = "disabled"
				}
			case 0x4F: // isdpAid
				info.ISDP_AID = hex.EncodeToString(d.Data)
			case 0x95: // profileClass
				class := decodeInteger(d.Data)
				switch class {
				case 0:
					info.ProfileClass = "test"
				case 1:
					info.ProfileClass = "provisioning"
				case 2:
					info.ProfileClass = "operational"
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
	cmd := asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, 0x2E, nil)
	resp, err := e.TransmitES10x(cmd)
	if err != nil {
		return nil, err
	}

	a := asn1.Init(resp)
	if !a.Unmarshal() || a.FullTag != 0xBF2E {
		return nil, fmt.Errorf("unexpected response tag for challenge: %02X", a.Tag)
	}

	// Response is a CHOICE. 0x80 is euiccChallenge
	b := asn1.Init(a.Data)
	if !b.Unmarshal() || b.FullTag != 0 {
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
	// Build request: CHOICE { iccid [0] OCTET STRING }
	iccidBytes := encodeBCD(iccid)
	iccidChoice := asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormPrimitive, 0, iccidBytes)

	var cmd []byte
	if tagNum == 0x31 { // Enable
		// EnableProfileRequest ::= [BF31] SEQUENCE { profileIdentifier Choice, refreshFlag BOOLEAN }
		refresh := asn1.Marshal(byte(asn1.ClassUniversal)<<6|byte(asn1.FormPrimitive)<<5|0x01, nil, 0x01) // TRUE
		cmd = asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, tagNum, append(iccidChoice, refresh...))
	} else {
		cmd = asn1.MarshalWithFullTag(asn1.ClassContextSpecific, asn1.FormConstructed, tagNum, iccidChoice)
	}

	respData, err := e.TransmitES10x(cmd)
	if err != nil {
		return err
	}

	a := asn1.Init(respData)
	if !a.Unmarshal() {
		return fmt.Errorf("failed to unmarshal response")
	}

	// Check for error code in response
	b := asn1.Init(a.Data)
	if b.Unmarshal() && b.FullTag == 1 { // profileManagementError
		errCode := decodeInteger(b.Data)
		return fmt.Errorf("profile management error: %d", errCode)
	}

	return nil
}
