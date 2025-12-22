package sim

import (
	"fmt"

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
