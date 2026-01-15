package sim

import (
	"encoding/hex"
	"fmt"
	"strings"

	"sim_reader/card"
)

// ARA-M (Access Rule Application Master) default AID (commonly used on UICC).
var GP_ARAM_AID = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00}

// GPARAMRule is a minimal representation of a single access rule to be stored into ARA-M.
//
// This is based on the REF-AR-DO / AR-DO structure described in GP/SE Access Control
// documentation and commonly used by Android Carrier Privileges workflows.
type GPARAMRule struct {
	// TargetAID is the AID the rule applies to. Use FFFFFFFFFFFF to match any AID (wildcard).
	TargetAID []byte
	// CertHash is the SHA-1 (20 bytes) or SHA-256 (32 bytes) hash of the Android app signing certificate.
	CertHash []byte
	// Perm is PERM-AR-DO (DB) value. Commonly 8 bytes.
	Perm []byte
	// ApduRule is APDU-AR-DO (D0) value. 0x01 means ALWAYS allow (common).
	ApduRule byte
}

// GPARAMParsedRule is a parsed ARA-M rule from GET DATA [ALL].
type GPARAMParsedRule struct {
	AID          string
	DeviceAppID  string
	PackageName  string
	ApduRule     string
	NfcRule      string
	Permissions  string
	RawApduRule  []byte
	RawNfcRule   []byte
	RawPerms     []byte
	RawDeviceApp []byte
	RawAID       []byte
}

func tlv(tag byte, value []byte) []byte {
	out := make([]byte, 0, 2+len(value))
	out = append(out, tag, byte(len(value)))
	out = append(out, value...)
	return out
}

// buildARAMStoreData builds a single-block STORE DATA payload for adding one ARA-M rule:
// E2 (REF-AR-DO) { E1 (REF-DO) { 4F (AID-REF-DO), C1 (DeviceAppID-REF-DO) } , E3 (AR-DO) { D0, DB } }
func buildARAMStoreData(rule GPARAMRule) ([]byte, error) {
	if len(rule.TargetAID) == 0 {
		return nil, fmt.Errorf("empty TargetAID")
	}
	if len(rule.CertHash) != 20 && len(rule.CertHash) != 32 {
		return nil, fmt.Errorf("CertHash must be 20 (SHA-1) or 32 (SHA-256) bytes, got %d", len(rule.CertHash))
	}
	if len(rule.Perm) == 0 {
		return nil, fmt.Errorf("empty Perm")
	}

	refDo := make([]byte, 0, 2+len(rule.TargetAID)+2+len(rule.CertHash))
	refDo = append(refDo, tlv(0x4F, rule.TargetAID)...) // AID-REF-DO
	refDo = append(refDo, tlv(0xC1, rule.CertHash)...)  // DeviceAppID-REF-DO

	arDo := make([]byte, 0, 2+1+2+len(rule.Perm))
	arDo = append(arDo, tlv(0xD0, []byte{rule.ApduRule})...) // APDU-AR-DO
	arDo = append(arDo, tlv(0xDB, rule.Perm)...)             // PERM-AR-DO

	e1 := tlv(0xE1, refDo)
	e3 := tlv(0xE3, arDo)

	payload := make([]byte, 0, 2+len(e1)+len(e3))
	payload = append(payload, e1...)
	payload = append(payload, e3...)

	return tlv(0xE2, payload), nil
}

func gpStoreData(sess card.GPSession, p1, p2 byte, data []byte) (*card.APDUResponse, error) {
	le := byte(0x00)
	return sess.WrapAndSend(0x80, 0xE2, p1, p2, data, &le)
}

func aramSendAPDU(reader *card.Reader, cla, ins, p1, p2 byte, data []byte, le *byte) (*card.APDUResponse, error) {
	if reader == nil {
		return nil, fmt.Errorf("nil reader")
	}
	if len(data) > 255 {
		return nil, fmt.Errorf("data too long for short APDU: %d bytes", len(data))
	}

	apdu := make([]byte, 0, 5+len(data)+1)
	apdu = append(apdu, cla, ins, p1, p2, byte(len(data)))
	if len(data) > 0 {
		apdu = append(apdu, data...)
	}
	if le != nil {
		apdu = append(apdu, *le)
	}

	resp, err := reader.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}
	if resp.HasMoreData() {
		return reader.GetResponse(resp.SW2)
	}
	return resp, nil
}

func aramSelect(reader *card.Reader, aid []byte) error {
	if len(aid) == 0 {
		aid = GP_ARAM_AID
	}
	resp, err := reader.Select(aid)
	if err != nil {
		return err
	}
	if resp == nil || !resp.IsOK() {
		if resp != nil {
			return fmt.Errorf("ARA-M SELECT failed: %s (SW=%04X)", card.SWToString(resp.SW()), resp.SW())
		}
		return fmt.Errorf("ARA-M SELECT failed: no response")
	}
	return nil
}

func aramSendWithFallback(reader *card.Reader, cla, ins, p1, p2 byte, data []byte, le *byte) (*card.APDUResponse, error) {
	resp, err := aramSendAPDU(reader, cla, ins, p1, p2, data, le)
	if err != nil {
		return nil, err
	}
	if resp != nil && (resp.SW() == card.SW_CLA_NOT_SUPPORTED || resp.SW() == card.SW_INS_NOT_SUPPORTED) && cla != 0x00 {
		return aramSendAPDU(reader, 0x00, ins, p1, p2, data, le)
	}
	return resp, nil
}

// GPAramGetAll retrieves all stored access rules from ARA-M without SCP.
func GPAramGetAll(reader *card.Reader, aramAID []byte) ([]byte, error) {
	if err := aramSelect(reader, aramAID); err != nil {
		return nil, err
	}
	le := byte(0x00)
	resp, err := aramSendWithFallback(reader, 0x80, 0xCA, 0xFF, 0x40, nil, &le)
	if err != nil {
		return nil, err
	}
	if resp == nil || !resp.IsOK() {
		if resp != nil {
			return nil, fmt.Errorf("ARA-M GET ALL failed: %s (SW=%04X)", card.SWToString(resp.SW()), resp.SW())
		}
		return nil, fmt.Errorf("ARA-M GET ALL failed: no response")
	}
	return resp.Data, nil
}

// GPAramGetConfig retrieves ARA-M configuration using device interface version 0.0.1.
func GPAramGetConfig(reader *card.Reader, aramAID []byte) ([]byte, error) {
	if err := aramSelect(reader, aramAID); err != nil {
		return nil, err
	}
	// DeviceConfigDO (E4) -> DeviceInterfaceVersionDO (E6) with major/minor/patch.
	version := []byte{0x00, 0x00, 0x01}
	deviceIface := tlv(0xE6, version)
	deviceConfig := tlv(0xE4, deviceIface)

	le := byte(0x00)
	resp, err := aramSendWithFallback(reader, 0x80, 0xCA, 0xDF, 0x21, deviceConfig, &le)
	if err != nil {
		return nil, err
	}
	if resp == nil || !resp.IsOK() {
		if resp != nil {
			return nil, fmt.Errorf("ARA-M GET CONFIG failed: %s (SW=%04X)", card.SWToString(resp.SW()), resp.SW())
		}
		return nil, fmt.Errorf("ARA-M GET CONFIG failed: no response")
	}
	return resp.Data, nil
}

// GPAramAddRuleRaw stores one ARA-M rule using STORE DATA without SCP.
func GPAramAddRuleRaw(reader *card.Reader, aramAID []byte, rule GPARAMRule) error {
	if reader == nil {
		return fmt.Errorf("nil reader")
	}
	if err := aramSelect(reader, aramAID); err != nil {
		return err
	}
	payload, err := buildARAMStoreData(rule)
	if err != nil {
		return err
	}
	if len(payload) > 255 {
		return fmt.Errorf("STORE DATA payload too long: %d bytes", len(payload))
	}

	le := byte(0x00)
	var lastErr error
	for _, p1 := range []byte{0x80, 0x90, 0xA0} {
		resp, err := aramSendWithFallback(reader, 0x80, 0xE2, p1, 0x00, payload, &le)
		if err != nil {
			lastErr = err
			continue
		}
		if resp != nil && resp.IsOK() {
			return nil
		}
		if resp != nil {
			lastErr = fmt.Errorf("STORE DATA failed: %s (SW=%04X)", card.SWToString(resp.SW()), resp.SW())
		}
	}
	return lastErr
}

type tlvNode struct {
	Tag      []byte
	Value    []byte
	Children []tlvNode
}

func parseTLV(data []byte) ([]tlvNode, error) {
	var nodes []tlvNode
	idx := 0
	for idx < len(data) {
		if data[idx] == 0x00 {
			idx++
			continue
		}
		start := idx
		tag := []byte{data[idx]}
		idx++
		if tag[0]&0x1F == 0x1F {
			for {
				if idx >= len(data) {
					return nodes, fmt.Errorf("truncated tag at %d", start)
				}
				b := data[idx]
				tag = append(tag, b)
				idx++
				if b&0x80 == 0 {
					break
				}
			}
		}
		if idx >= len(data) {
			return nodes, fmt.Errorf("missing length at %d", start)
		}
		lb := data[idx]
		idx++
		var length int
		if lb < 0x80 {
			length = int(lb)
		} else if lb == 0x80 {
			return nodes, fmt.Errorf("indefinite length not supported at %d", start)
		} else {
			n := int(lb & 0x7F)
			if n == 0 || idx+n > len(data) {
				return nodes, fmt.Errorf("invalid length at %d", start)
			}
			length = 0
			for i := 0; i < n; i++ {
				length = (length << 8) | int(data[idx+i])
			}
			idx += n
		}
		if idx+length > len(data) {
			return nodes, fmt.Errorf("length overflow at %d", start)
		}
		val := data[idx : idx+length]
		idx += length

		node := tlvNode{Tag: tag, Value: val}
		if tag[0]&0x20 != 0 {
			children, err := parseTLV(val)
			if err == nil {
				node.Children = children
			}
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func findAllNodesByTag(nodes []tlvNode, tagHex string) []tlvNode {
	var out []tlvNode
	for _, n := range nodes {
		if strings.EqualFold(hex.EncodeToString(n.Tag), tagHex) {
			out = append(out, n)
		}
		if len(n.Children) > 0 {
			out = append(out, findAllNodesByTag(n.Children, tagHex)...)
		}
	}
	return out
}

func findFirstChildByTag(nodes []tlvNode, tagHex string) *tlvNode {
	for i := range nodes {
		if strings.EqualFold(hex.EncodeToString(nodes[i].Tag), tagHex) {
			return &nodes[i]
		}
	}
	return nil
}

func parseAramRule(node tlvNode) GPARAMParsedRule {
	rule := GPARAMParsedRule{}
	refNode := findFirstChildByTag(node.Children, "E1")
	arNode := findFirstChildByTag(node.Children, "E3")

	if refNode != nil {
		aidNode := findFirstChildByTag(refNode.Children, "4F")
		if aidNode != nil {
			rule.RawAID = aidNode.Value
			rule.AID = strings.ToUpper(hex.EncodeToString(aidNode.Value))
		}
		aidEmpty := findFirstChildByTag(refNode.Children, "C0")
		if aidEmpty != nil && rule.AID == "" {
			rule.AID = "ANY"
		}
		devNode := findFirstChildByTag(refNode.Children, "C1")
		if devNode != nil {
			rule.RawDeviceApp = devNode.Value
			rule.DeviceAppID = strings.ToUpper(hex.EncodeToString(devNode.Value))
		}
		pkgNode := findFirstChildByTag(refNode.Children, "CA")
		if pkgNode != nil {
			rule.PackageName = string(pkgNode.Value)
		}
	}

	if arNode != nil {
		apduNode := findFirstChildByTag(arNode.Children, "D0")
		if apduNode != nil {
			rule.RawApduRule = apduNode.Value
			rule.ApduRule = decodeSimpleRule(apduNode.Value, "APDU")
		}
		nfcNode := findFirstChildByTag(arNode.Children, "D1")
		if nfcNode != nil {
			rule.RawNfcRule = nfcNode.Value
			rule.NfcRule = decodeSimpleRule(nfcNode.Value, "NFC")
		}
		permNode := findFirstChildByTag(arNode.Children, "DB")
		if permNode != nil {
			rule.RawPerms = permNode.Value
			rule.Permissions = strings.ToUpper(hex.EncodeToString(permNode.Value))
		}
	}

	return rule
}

func decodeSimpleRule(value []byte, label string) string {
	if len(value) == 1 {
		switch value[0] {
		case 0x00:
			return label + ": NEVER"
		case 0x01:
			return label + ": ALWAYS"
		}
	}
	if len(value) == 0 {
		return ""
	}
	return label + ": " + strings.ToUpper(hex.EncodeToString(value))
}

// ParseAramGetAll parses GET DATA ALL response TLV into rule list.
func ParseAramGetAll(data []byte) ([]GPARAMParsedRule, error) {
	nodes, err := parseTLV(data)
	if err != nil {
		return nil, err
	}
	ruleNodes := findAllNodesByTag(nodes, "E2")
	if len(ruleNodes) == 0 {
		return nil, fmt.Errorf("no REF-AR-DO (E2) found")
	}
	var rules []GPARAMParsedRule
	for _, rn := range ruleNodes {
		rules = append(rules, parseAramRule(rn))
	}
	return rules, nil
}

// GPAramAddRule stores one ARA-M rule using GP STORE DATA over an established secure channel.
//
// Note: Different cards expect different STORE DATA P1 values (data format hints).
// We try a small set of common P1 values for compatibility.
func GPAramAddRule(reader *card.Reader, cfg GPConfig, aramAID []byte, rule GPARAMRule) error {
	if reader == nil {
		return fmt.Errorf("nil reader")
	}
	if len(aramAID) == 0 {
		aramAID = GP_ARAM_AID
	}

	sess, err := OpenGPSessionAuto(reader, cfg)
	if err != nil {
		return err
	}

	// Best-effort SELECT of ARA-M (some setups expect it). If it fails, continue and rely on STORE DATA routing.
	// Note: ISO SELECT after opening a secure channel may invalidate SCP on some cards; therefore we do not fail
	// hard here. If STORE DATA fails, caller can retry.
	_, _ = reader.Select(aramAID)

	payload, err := buildARAMStoreData(rule)
	if err != nil {
		return err
	}

	// Common P1 values seen in the wild:
	// - 0x80: last block, no encryption, no special structure hint
	// - 0x90: last block + vendor-specific structure hint (seen in some GPPro scripts)
	// - 0xA0: last block + BER-TLV structure hint
	for _, p1 := range []byte{0x80, 0x90, 0xA0} {
		resp, e := gpStoreData(sess, p1, 0x00, payload)
		if e != nil {
			err = e
			continue
		}
		if resp != nil && resp.IsOK() {
			return nil
		}
		if resp != nil {
			err = fmt.Errorf("STORE DATA failed: %s (SW=%04X)", card.SWToString(resp.SW()), resp.SW())
			continue
		}
	}
	return err
}
