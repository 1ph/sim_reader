package card

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Minimal GlobalPlatform SCP03 (AES-CMAC, optional C-ENC not implemented here).
// This is enough for listing / deleting / loading applets on cards that report SCP03 in INITIALIZE UPDATE.

// GPSession is a common interface implemented by SCP02Session and SCP03Session.
type GPSession interface {
	WrapAndSend(cla, ins, p1, p2 byte, data []byte, le *byte) (*APDUResponse, error)
}

type SCP03Session struct {
	Reader *Reader

	KVN byte
	Sec GPSecurityLevel

	// Static keys
	StaticEnc []byte // AES key
	StaticMac []byte // AES key
	StaticDek []byte // AES key (optional)

	// Derived session keys
	SENC  []byte // AES key
	SMAC  []byte // AES key
	SRMAC []byte // AES key (unused)

	// challenges
	HostChallenge []byte
	CardChallenge []byte

	// security mode (S8 or S16). We use S8 by default.
	sMode int

	// C-MAC chaining value (16 bytes)
	macChaining []byte
}

func expandAESKey(k []byte) ([]byte, error) {
	// For now: AES-128 only (16 bytes).
	if len(k) != 16 {
		return nil, fmt.Errorf("AES key must be 16 bytes (SCP03 AES-128), got %d", len(k))
	}
	out := make([]byte, 16)
	copy(out, k)
	return out, nil
}

func leftShiftOneBit128(in []byte) []byte {
	out := make([]byte, 16)
	var carry byte
	for i := 15; i >= 0; i-- {
		b := in[i]
		out[i] = (b << 1) | carry
		carry = (b >> 7) & 0x01
	}
	return out
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func pad80Block16(in []byte) []byte {
	out := make([]byte, len(in), len(in)+16)
	copy(out, in)
	out = append(out, 0x80)
	for len(out)%16 != 0 {
		out = append(out, 0x00)
	}
	return out
}

func aesECBEncryptBlock(key []byte, block16 []byte) ([]byte, error) {
	if len(block16) != 16 {
		return nil, fmt.Errorf("block must be 16 bytes, got %d", len(block16))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	b.Encrypt(out, block16)
	return out, nil
}

// aesCMAC computes AES-CMAC (NIST SP 800-38B) with 16-byte output.
func aesCMAC(key []byte, msg []byte) ([]byte, error) {
	k, err := expandAESKey(key)
	if err != nil {
		return nil, err
	}
	zero := make([]byte, 16)
	L, err := aesECBEncryptBlock(k, zero)
	if err != nil {
		return nil, err
	}
	const rb = 0x87
	K1 := leftShiftOneBit128(L)
	if (L[0] & 0x80) != 0 {
		K1[15] ^= rb
	}
	K2 := leftShiftOneBit128(K1)
	if (K1[0] & 0x80) != 0 {
		K2[15] ^= rb
	}

	var n int
	if len(msg) == 0 {
		n = 1
	} else {
		n = (len(msg) + 15) / 16
	}

	complete := len(msg) != 0 && (len(msg)%16 == 0)

	var last []byte
	if complete {
		start := (n - 1) * 16
		last = xorBytes(msg[start:start+16], K1)
	} else {
		padded := pad80Block16(msg)
		start := (n - 1) * 16
		last = xorBytes(padded[start:start+16], K2)
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	cbc := cipher.NewCBCEncrypter(block, iv)
	buf := make([]byte, n*16)
	if len(msg) >= 16 {
		copy(buf, msg[:(n-1)*16])
	}
	copy(buf[(n-1)*16:], last)
	cbc.CryptBlocks(buf, buf)
	return buf[len(buf)-16:], nil
}

func scp03KDF(constant byte, context []byte, baseKey []byte, outLen int) ([]byte, error) {
	// Implements GP 2.3 Amend D KDF (counter mode) as in pySim.
	// label = 11 bytes 0x00 + derivation constant (1 byte)
	// info = label || 0x00 || L(2) || i(1) || context
	if outLen <= 0 {
		return nil, fmt.Errorf("invalid outLen")
	}
	if len(baseKey) != 16 {
		return nil, fmt.Errorf("SCP03 currently supports AES-128 only (16-byte base keys)")
	}
	Lbits := outLen * 8
	label := append(bytes.Repeat([]byte{0x00}, 11), constant)
	// single iteration is enough for outLen<=16
	info := make([]byte, 0, 12+1+2+1+len(context))
	info = append(info, label...)
	info = append(info, 0x00)
	info = append(info, byte(Lbits>>8), byte(Lbits))
	info = append(info, 0x01) // i=1
	info = append(info, context...)
	dk, err := aesCMAC(baseKey, info)
	if err != nil {
		return nil, err
	}
	return dk[:outLen], nil
}

func parseInitUpdateSCP03(respData []byte) (iParam byte, cardChallenge []byte, cardCrypt []byte, err error) {
	// key_div(10) | key_ver(1) | scp_id(1=0x03) | i_param(1) | card_chal(s) | card_crypt(s) | [seq_counter(3)?]
	if len(respData) < 10+3+8+8 {
		return 0, nil, nil, fmt.Errorf("INITIALIZE UPDATE response too short for SCP03: %d bytes", len(respData))
	}
	scpID := respData[11]
	if scpID != 0x03 {
		return 0, nil, nil, fmt.Errorf("not SCP03 (scp_id=0x%02X)", scpID)
	}
	iParam = respData[12]
	// Determine S-mode by remaining length. We only support S8 here.
	rem := len(respData) - 13
	if rem == 8+8 || rem == 8+8+3 {
		cardChallenge = append([]byte{}, respData[13:21]...)
		cardCrypt = append([]byte{}, respData[21:29]...)
		return iParam, cardChallenge, cardCrypt, nil
	}
	if rem == 16+16 || rem == 16+16+3 {
		cardChallenge = append([]byte{}, respData[13:29]...)
		cardCrypt = append([]byte{}, respData[29:45]...)
		return iParam, cardChallenge, cardCrypt, nil
	}
	return 0, nil, nil, fmt.Errorf("unexpected SCP03 INITIALIZE UPDATE response length: %d", len(respData))
}

func probeSCP03(staticEnc, staticMac []byte, hostChallenge []byte, respData []byte) error {
	iParam, cardChal, cardCrypt, err := parseInitUpdateSCP03(respData)
	if err != nil {
		return err
	}
	_ = iParam // currently unused (options byte)
	if len(hostChallenge) != len(cardChal) {
		return fmt.Errorf("SCP03 host challenge length %d does not match card challenge length %d", len(hostChallenge), len(cardChal))
	}
	context := append(append([]byte{}, hostChallenge...), cardChal...)

	sMac, err := scp03KDF(0x06, context, staticMac, 16)
	if err != nil {
		return err
	}
	expCardCrypt, err := scp03KDF(0x00, context, sMac, len(cardCrypt))
	if err != nil {
		return err
	}
	if !bytes.Equal(expCardCrypt, cardCrypt) {
		return fmt.Errorf("card cryptogram mismatch (SCP03). Expected %X, got %X", expCardCrypt, cardCrypt)
	}
	return nil
}

func OpenSCP03FromInitUpdate(r *Reader, kvn byte, sec GPSecurityLevel, static GPKeySet, hostChallenge8 []byte, initUpdateData []byte) (*SCP03Session, error) {
	encK, err := expandAESKey(static.ENC)
	if err != nil {
		return nil, fmt.Errorf("ENC key: %w", err)
	}
	macK, err := expandAESKey(static.MAC)
	if err != nil {
		return nil, fmt.Errorf("MAC key: %w", err)
	}
	var dekK []byte
	if len(static.DEK) > 0 {
		dekK, err = expandAESKey(static.DEK)
		if err != nil {
			return nil, fmt.Errorf("DEK key: %w", err)
		}
	}

	iParam, cardChal, cardCrypt, err := parseInitUpdateSCP03(initUpdateData)
	if err != nil {
		return nil, err
	}
	_ = iParam
	if len(hostChallenge8) != len(cardChal) {
		return nil, fmt.Errorf("SCP03 host challenge length %d does not match card challenge length %d", len(hostChallenge8), len(cardChal))
	}

	context := append(append([]byte{}, hostChallenge8...), cardChal...)
	sEnc, err := scp03KDF(0x04, context, encK, 16)
	if err != nil {
		return nil, err
	}
	sMac, err := scp03KDF(0x06, context, macK, 16)
	if err != nil {
		return nil, err
	}
	sRmac, _ := scp03KDF(0x07, context, macK, 16) // optional

	// Verify card cryptogram (S8 or S16 depending on card)
	expCardCrypt, err := scp03KDF(0x00, context, sMac, len(cardCrypt))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(expCardCrypt, cardCrypt) {
		return nil, fmt.Errorf("card cryptogram mismatch (SCP03). Expected %X, got %X", expCardCrypt, cardCrypt)
	}

	// Host cryptogram (S8 or S16)
	hostCrypt, err := scp03KDF(0x01, context, sMac, len(cardCrypt))
	if err != nil {
		return nil, err
	}

	sess := &SCP03Session{
		Reader:        r,
		KVN:           kvn,
		Sec:           sec,
		StaticEnc:     encK,
		StaticMac:     macK,
		StaticDek:     dekK,
		SENC:          sEnc,
		SMAC:          sMac,
		SRMAC:         sRmac,
		HostChallenge: append([]byte{}, hostChallenge8...),
		CardChallenge: append([]byte{}, cardChal...),
		sMode:         len(cardCrypt),
		macChaining:   make([]byte, 16), // 16 zeroes
	}

	// EXTERNAL AUTHENTICATE: send host cryptogram protected with C-MAC
	le := byte(0x00)
	resp, err := sess.WrapAndSend(0x80, 0x82, byte(sec), 0x00, hostCrypt, &le)
	if err != nil {
		return nil, err
	}
	if resp.HasMoreData() {
		resp, _ = r.GetResponse(resp.SW2)
	}
	if !resp.IsOK() {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE failed: %s (SW=%04X)", SWToString(resp.SW()), resp.SW())
	}

	return sess, nil
}

func (s *SCP03Session) WrapAndSend(cla, ins, p1, p2 byte, data []byte, le *byte) (*APDUResponse, error) {
	// Only wrap GP proprietary commands (CLA with b8 set) – but in our call sites we always use 0x80.
	// C-ENC is not implemented; we do C-MAC only (works for list/delete/load/install in most cases).
	_ = cla

	// Build APDU (case 3/4)
	apdu := make([]byte, 0, 5+len(data)+1)
	apdu = append(apdu, 0x80, ins, p1, p2, byte(len(data)))
	apdu = append(apdu, data...)

	// CMAC over modified APDU:
	// - mCLA = (CLA & 0xF0) | 0x04 (secure messaging indicator)
	// - mLc = Lc + sMode
	mcla := byte(0x84) // b8 set + SM bit, logical channel 0
	mlc := byte(len(data) + s.sMode)
	macInput := make([]byte, 0, 5+len(data))
	macInput = append(macInput, mcla, ins, p1, p2, mlc)
	macInput = append(macInput, data...)

	fullCmac, err := aesCMAC(s.SMAC, append(append([]byte{}, s.macChaining...), macInput...))
	if err != nil {
		return nil, err
	}
	s.macChaining = fullCmac
	trunc := fullCmac[:s.sMode]

	// Transmitted APDU uses secure CLA and Lc includes MAC
	tlc := byte(len(data) + s.sMode)
	tx := make([]byte, 0, 5+len(data)+s.sMode+1)
	tx = append(tx, 0x84, ins, p1, p2, tlc)
	tx = append(tx, data...)
	tx = append(tx, trunc...)
	if le != nil {
		tx = append(tx, *le)
	}

	resp, err := s.Reader.SendAPDU(tx)
	if err != nil {
		return nil, err
	}
	if resp.HasMoreData() {
		return s.Reader.GetResponse(resp.SW2)
	}
	return resp, nil
}
