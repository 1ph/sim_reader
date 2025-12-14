package card

import (
	"bytes"
	"crypto/des"
	"fmt"
)

// Minimal GlobalPlatform SCP02 implementation (3DES).
// This is used to open a Secure Channel and wrap GP management APDUs (GET STATUS/DELETE/INSTALL/LOAD).

type GPSCP string

const (
	GPSCP02 GPSCP = "scp02"
)

type GPSecurityLevel byte

const (
	// GP Security Level bits (common subset)
	// 0x01 = C-MAC
	// 0x02 = C-ENC
	GPSecMAC    GPSecurityLevel = 0x01
	GPSecMACENC GPSecurityLevel = 0x03
)

type GPKeySet struct {
	ENC []byte // static ENC key (16 or 24 bytes)
	MAC []byte // static MAC key (16 or 24 bytes)
	DEK []byte // static DEK key (16 or 24 bytes) - optional for delete/list/load/install (needed for PUT KEY etc.)
}

// ExpandTo3DESKey converts 16-byte (2-key 3DES) keys to 24-byte K1||K2||K1.
func ExpandTo3DESKey(k []byte) ([]byte, error) {
	if len(k) == 16 {
		out := make([]byte, 24)
		copy(out[0:16], k)
		copy(out[16:24], k[0:8])
		return out, nil
	}
	if len(k) == 24 {
		out := make([]byte, 24)
		copy(out, k)
		return out, nil
	}
	return nil, fmt.Errorf("3DES key must be 16 or 24 bytes, got %d", len(k))
}

// ISO7816-4 padding: 0x80 then 0x00 until multiple of block size.
func iso7816Pad(in []byte, blockSize int) []byte {
	out := make([]byte, len(in), len(in)+blockSize)
	copy(out, in)
	out = append(out, 0x80)
	for len(out)%blockSize != 0 {
		out = append(out, 0x00)
	}
	return out
}

// tripleDESCBCEncrypt encrypts with 3DES-CBC using the provided IV (8 bytes).
func tripleDESCBCEncrypt(key24, iv8, data []byte) ([]byte, error) {
	if len(key24) != 24 {
		return nil, fmt.Errorf("3DES key must be 24 bytes, got %d", len(key24))
	}
	if len(iv8) != 8 {
		return nil, fmt.Errorf("IV must be 8 bytes, got %d", len(iv8))
	}
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("data must be multiple of 8 bytes, got %d", len(data))
	}
	block, err := des.NewTripleDESCipher(key24)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	iv := make([]byte, 8)
	copy(iv, iv8)
	for i := 0; i < len(data); i += 8 {
		buf := xor8(data[i:i+8], iv)
		block.Encrypt(out[i:i+8], buf)
		copy(iv, out[i:i+8])
	}
	return out, nil
}

// desECBEncrypt encrypts a single 8-byte block with DES-ECB.
func desECBEncrypt(key8, block8 []byte) ([]byte, error) {
	if len(key8) != 8 {
		return nil, fmt.Errorf("DES key must be 8 bytes, got %d", len(key8))
	}
	if len(block8) != 8 {
		return nil, fmt.Errorf("block must be 8 bytes, got %d", len(block8))
	}
	c, err := des.NewCipher(key8)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	c.Encrypt(out, block8)
	return out, nil
}

// desECBDecrypt decrypts a single 8-byte block with DES-ECB.
func desECBDecrypt(key8, block8 []byte) ([]byte, error) {
	if len(key8) != 8 {
		return nil, fmt.Errorf("DES key must be 8 bytes, got %d", len(key8))
	}
	if len(block8) != 8 {
		return nil, fmt.Errorf("block must be 8 bytes, got %d", len(block8))
	}
	c, err := des.NewCipher(key8)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	c.Decrypt(out, block8)
	return out, nil
}

func xor8(a, b []byte) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// retailMAC computes ISO 9797-1 MAC Algorithm 3 ("Retail MAC") used in SCP02.
// - key24 is 3DES key K1||K2||K3 (we will use K1 and K2)
// - icv8 is 8-byte ICV (already "ICV encrypted" if your flow uses it)
// - data is the message to MAC (not yet padded)
func retailMAC(key24, icv8, data []byte) ([]byte, error) {
	key24, err := ExpandTo3DESKey(key24)
	if err != nil {
		return nil, err
	}
	if len(icv8) != 8 {
		return nil, fmt.Errorf("ICV must be 8 bytes, got %d", len(icv8))
	}
	k1 := key24[0:8]
	k2 := key24[8:16]

	padded := iso7816Pad(data, 8)

	// CBC-MAC with single DES using K1
	c, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 8)
	copy(iv, icv8)
	tmp := make([]byte, 8)
	for i := 0; i < len(padded); i += 8 {
		copy(tmp, xor8(padded[i:i+8], iv))
		c.Encrypt(iv, tmp)
	}
	last := make([]byte, 8)
	copy(last, iv)

	// Final transformation: DES-ECB decrypt with K2, then DES-ECB encrypt with K1
	last, err = desECBDecrypt(k2, last)
	if err != nil {
		return nil, err
	}
	last, err = desECBEncrypt(k1, last)
	if err != nil {
		return nil, err
	}
	return last, nil
}

type SCP02Session struct {
	Reader *Reader

	KVN byte // Key Version Number (P1 of INITIALIZE UPDATE)
	Sec GPSecurityLevel

	Static GPKeySet

	// Derived session keys (24 bytes each)
	SENC []byte
	SMAC []byte
	SDEK []byte

	// From INITIALIZE UPDATE
	SeqCounter    []byte // 2 bytes
	CardChallenge []byte // 6 bytes (SCP02)
	HostChallenge []byte // 8 bytes

	// C-MAC chaining state (8 bytes)
	icv        []byte
	icvEncrypt bool
}

func sendInitializeUpdate(r *Reader, kvn byte, hostChallenge8 []byte) (*APDUResponse, error) {
	// Try common variants used by different stacks/cards:
	// - CLA=80, INS=50 with Le=00 (case 4)
	// - CLA=80, INS=50 without Le (case 3)
	// - CLA=00, INS=50 with Le=00 (rare but seen on some stacks)
	// - CLA=00, INS=50 without Le
	var variants [][]byte
	base80 := []byte{0x80, 0x50, kvn, 0x00, 0x08}
	base80 = append(base80, hostChallenge8...)
	variants = append(variants, append(append([]byte{}, base80...), 0x00)) // with Le
	variants = append(variants, append([]byte{}, base80...))               // without Le

	base00 := []byte{0x00, 0x50, kvn, 0x00, 0x08}
	base00 = append(base00, hostChallenge8...)
	variants = append(variants, append(append([]byte{}, base00...), 0x00)) // with Le
	variants = append(variants, append([]byte{}, base00...))               // without Le

	var last *APDUResponse
	var lastErr error
	for _, apdu := range variants {
		resp, err := r.SendAPDU(apdu)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.HasMoreData() {
			resp2, err2 := r.GetResponse(resp.SW2)
			if err2 == nil && resp2 != nil {
				resp = resp2
			}
		}
		// If INS is not supported, try next variant.
		if resp.SW() == SW_INS_NOT_SUPPORTED || resp.SW() == SW_CLA_NOT_SUPPORTED {
			last = resp
			continue
		}
		return resp, nil
	}
	if last != nil {
		return last, nil
	}
	return nil, lastErr
}

// OpenSCP02 opens SCP02 secure channel.
func OpenSCP02(r *Reader, static GPKeySet, kvn byte, sec GPSecurityLevel, hostChallenge8 []byte) (*SCP02Session, error) {
	if r == nil {
		return nil, fmt.Errorf("nil reader")
	}
	enc, err := ExpandTo3DESKey(static.ENC)
	if err != nil {
		return nil, fmt.Errorf("ENC key: %w", err)
	}
	mac, err := ExpandTo3DESKey(static.MAC)
	if err != nil {
		return nil, fmt.Errorf("MAC key: %w", err)
	}
	var dek []byte
	if len(static.DEK) > 0 {
		dek, err = ExpandTo3DESKey(static.DEK)
		if err != nil {
			return nil, fmt.Errorf("DEK key: %w", err)
		}
	}
	if len(hostChallenge8) != 8 {
		return nil, fmt.Errorf("host challenge must be 8 bytes, got %d", len(hostChallenge8))
	}

	// INITIALIZE UPDATE (with fallbacks for card/stack quirks)
	resp, err := sendInitializeUpdate(r, kvn, hostChallenge8)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("INITIALIZE UPDATE failed: no response")
	}
	if !resp.IsOK() {
		return nil, fmt.Errorf("INITIALIZE UPDATE failed: %s (SW=%04X)", SWToString(resp.SW()), resp.SW())
	}

	// Parse SCP02 response (typical 28 bytes):
	// keyDivers(10) | keyInfo(2) | seqCounter(2) | cardChallenge(6) | cardCryptogram(8)
	if len(resp.Data) < 28 {
		return nil, fmt.Errorf("INITIALIZE UPDATE response too short: %d bytes", len(resp.Data))
	}
	seq := resp.Data[12:14]
	cardChal := resp.Data[14:20]
	cardCrypt := resp.Data[20:28]

	// Derive session keys (SCP02): 3DES-CBC(StaticKey, derivationData, IV=0)
	// derivationData = constant(2) || seqCounter(2) || 12*00
	senc, err := scp02Derive(enc, []byte{0x01, 0x82}, seq)
	if err != nil {
		return nil, err
	}
	smac, err := scp02Derive(mac, []byte{0x01, 0x01}, seq)
	if err != nil {
		return nil, err
	}
	var sdek []byte
	if len(dek) > 0 {
		sdek, err = scp02Derive(dek, []byte{0x01, 0x81}, seq)
		if err != nil {
			return nil, err
		}
	}

	// Verify card cryptogram
	expectedCardCrypt, err := scp02CardCryptogram(senc, seq, hostChallenge8, cardChal)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(expectedCardCrypt, cardCrypt) {
		return nil, fmt.Errorf("card cryptogram mismatch (SCP02). Expected %X, got %X", expectedCardCrypt, cardCrypt)
	}

	sess := &SCP02Session{
		Reader:        r,
		KVN:           kvn,
		Sec:           sec,
		Static:        GPKeySet{ENC: enc, MAC: mac, DEK: dek},
		SENC:          senc,
		SMAC:          smac,
		SDEK:          sdek,
		SeqCounter:    append([]byte{}, seq...),
		CardChallenge: append([]byte{}, cardChal...),
		HostChallenge: append([]byte{}, hostChallenge8...),
		icv:           make([]byte, 8), // ICV=0 for EXTERNAL AUTH MAC
		icvEncrypt:    true,            // match pySim default behaviour
	}

	// EXTERNAL AUTHENTICATE (84 82):
	// data = hostCryptogram(8) || C-MAC(8)
	hostCrypt, err := scp02HostCryptogram(senc, seq, cardChal, hostChallenge8)
	if err != nil {
		return nil, err
	}
	// Build APDU header for MAC calculation (Lc includes MAC length)
	ext := []byte{0x84, 0x82, byte(sec), 0x00, 0x10} // Lc=16
	// MAC is computed over header+dataWithoutMAC (hostCrypt) with Lc already set to 16
	macBytes, err := sess.computeCMAC(ext[:4], hostCrypt, true /* reset ICV */)
	if err != nil {
		return nil, err
	}
	ext = append(ext, hostCrypt...)
	ext = append(ext, macBytes...)
	ext = append(ext, 0x00) // Le
	resp, err = r.SendAPDU(ext)
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

func scp02Derive(staticKey24 []byte, constant2 []byte, seq2 []byte) ([]byte, error) {
	if len(constant2) != 2 || len(seq2) != 2 {
		return nil, fmt.Errorf("invalid derive inputs")
	}
	input := make([]byte, 0, 16)
	input = append(input, constant2...)
	input = append(input, seq2...)
	input = append(input, make([]byte, 12)...)
	iv := make([]byte, 8) // zero IV
	out, err := tripleDESCBCEncrypt(staticKey24, iv, input)
	if err != nil {
		return nil, err
	}
	// Result is 16 bytes -> expand to 24
	return ExpandTo3DESKey(out)
}

func scp02HostCryptogram(senc24 []byte, seq2 []byte, cardChallenge6 []byte, hostChallenge8 []byte) ([]byte, error) {
	// SCP02 Host Cryptogram:
	// hostAuthData = seqCounter(2) || cardChallenge(6) || hostChallenge(8)
	// then ISO7816 padding (0x80..00) to multiple of 8, encrypt with S-ENC (3DES-CBC, IV=0),
	// take last 8 bytes.
	if len(seq2) != 2 || len(cardChallenge6) != 6 || len(hostChallenge8) != 8 {
		return nil, fmt.Errorf("invalid host cryptogram inputs")
	}
	in := make([]byte, 0, 24)
	in = append(in, seq2...)
	in = append(in, cardChallenge6...)
	in = append(in, hostChallenge8...)
	in = iso7816Pad(in, 8)
	iv := make([]byte, 8)
	enc, err := tripleDESCBCEncrypt(senc24, iv, in)
	if err != nil {
		return nil, err
	}
	return enc[len(enc)-8:], nil
}

func scp02CardCryptogram(senc24 []byte, seq2 []byte, hostChallenge8 []byte, cardChallenge6 []byte) ([]byte, error) {
	// SCP02 Card Cryptogram:
	// cardAuthData = hostChallenge(8) || seqCounter(2) || cardChallenge(6)
	// then ISO7816 padding, encrypt with S-ENC, take last 8 bytes.
	if len(seq2) != 2 || len(cardChallenge6) != 6 || len(hostChallenge8) != 8 {
		return nil, fmt.Errorf("invalid card cryptogram inputs")
	}
	in := make([]byte, 0, 24)
	in = append(in, hostChallenge8...)
	in = append(in, seq2...)
	in = append(in, cardChallenge6...)
	in = iso7816Pad(in, 8)
	iv := make([]byte, 8)
	enc, err := tripleDESCBCEncrypt(senc24, iv, in)
	if err != nil {
		return nil, err
	}
	return enc[len(enc)-8:], nil
}

// computeCMAC computes SCP02 C-MAC for an APDU using ICV chaining compatible with pySim:
// - For EXTERNAL AUTHENTICATE: reset ICV to 0x00..00 for MAC computation (no pre-encryption of ICV).
// - For subsequent commands: use stored ICV (which is already the "ICV-encrypted" value if icvEncrypt is enabled).
// After computing MAC, update stored ICV:
//
//	if icvEncrypt: ICV := DES-ECB(K1, MAC)
//	else:          ICV := MAC
//
// header4 is CLA|INS|P1|P2. data is APDU data field WITHOUT the MAC.
func (s *SCP02Session) computeCMAC(header4 []byte, data []byte, resetICV bool) ([]byte, error) {
	if len(header4) != 4 {
		return nil, fmt.Errorf("header must be 4 bytes")
	}

	icv := s.icv
	if resetICV || len(icv) != 8 {
		icv = make([]byte, 8)
	}

	// Lc includes MAC length (8)
	lc := byte(len(data) + 8)
	msg := make([]byte, 0, 5+len(data))
	msg = append(msg, header4...)
	msg = append(msg, lc)
	msg = append(msg, data...)

	macBytes, err := retailMAC(s.SMAC, icv, msg)
	if err != nil {
		return nil, err
	}

	// Update ICV chaining state
	if s.icvEncrypt {
		k1 := s.SMAC[0:8]
		icvNew, err := desECBEncrypt(k1, macBytes)
		if err != nil {
			return nil, err
		}
		s.icv = icvNew
	} else {
		s.icv = append([]byte{}, macBytes...)
	}

	return macBytes, nil
}

// WrapAndSend wraps a GP management APDU with SCP02 secure messaging and sends it.
// This implementation supports C-MAC (and optional C-ENC padding/encryption for the data field).
func (s *SCP02Session) WrapAndSend(cla, ins, p1, p2 byte, data []byte, le *byte) (*APDUResponse, error) {
	// Secure messaging class for GP proprietary commands is typically 0x84
	secureCLA := byte(0x84)
	header4 := []byte{secureCLA, ins, p1, p2}

	// Optional C-ENC (not used by default). For now we only encrypt if explicitly requested.
	// Note: many GP operations work fine with MAC-only; encryption is needed for some sensitive commands.
	wData := data
	if s.Sec == GPSecMACENC && len(data) > 0 {
		plain := iso7816Pad(data, 8)
		iv := make([]byte, 8)
		enc, err := tripleDESCBCEncrypt(s.SENC, iv, plain)
		if err != nil {
			return nil, err
		}
		wData = enc
	}

	macBytes, err := s.computeCMAC(header4, wData, false /* resetICV */)
	if err != nil {
		return nil, err
	}

	apdu := make([]byte, 0, 5+len(wData)+8+1)
	apdu = append(apdu, secureCLA, ins, p1, p2, byte(len(wData)+8))
	apdu = append(apdu, wData...)
	apdu = append(apdu, macBytes...)
	if le != nil {
		apdu = append(apdu, *le)
	}

	resp, err := s.Reader.SendAPDU(apdu)
	if err != nil {
		return nil, err
	}
	if resp.HasMoreData() {
		resp, _ = s.Reader.GetResponse(resp.SW2)
	}
	return resp, nil
}
