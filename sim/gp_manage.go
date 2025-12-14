package sim

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"sim_reader/card"
)

// GPConfig contains parameters for GlobalPlatform operations.
// For now we implement SCP02 with static ENC/MAC/DEK keys.
type GPConfig struct {
	KVN        byte
	Security   card.GPSecurityLevel
	StaticKeys card.GPKeySet
	SDAID      []byte // ISD/Card Manager AID to select (optional)
	BlockSize  int    // LOAD block size (bytes, before MAC)
}

func ParseHexBytes(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	s = strings.ReplaceAll(s, "0x", "")
	if s == "" {
		return nil, fmt.Errorf("empty hex string")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func ParseAIDHex(s string) ([]byte, error) {
	b, err := ParseHexBytes(s)
	if err != nil {
		return nil, fmt.Errorf("invalid AID hex: %w", err)
	}
	if len(b) < 5 || len(b) > 16 {
		// AID length can vary, but this keeps us safe from obvious mistakes
		return nil, fmt.Errorf("unexpected AID length %d (expected 5..16 bytes)", len(b))
	}
	return b, nil
}

func ParseGPSecurityLevel(s string) (card.GPSecurityLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "mac", "c-mac", "cmac", "01", "0x01":
		return card.GPSecMAC, nil
	case "mac+enc", "cmac+cenc", "c-mac+c-enc", "03", "0x03":
		return card.GPSecMACENC, nil
	default:
		return 0, fmt.Errorf("unknown GP security level: %s (use: mac, mac+enc)", s)
	}
}

func OpenGPSCP02(reader *card.Reader, cfg GPConfig) (*card.SCP02Session, error) {
	// IMPORTANT: Many cards only accept INITIALIZE UPDATE after selecting Card Manager / ISD.
	// gp.jar does this implicitly. We do it explicitly here.
	if len(cfg.SDAID) > 0 {
		resp, err := reader.Select(cfg.SDAID)
		if err != nil || !(resp.IsOK() || resp.HasMoreData()) {
			// Fallback: try GlobalPlatform ISD AID (A0000001510000) if caller provided CM AID
			alt := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}
			resp2, err2 := reader.Select(alt)
			if err2 != nil || !(resp2.IsOK() || resp2.HasMoreData()) {
				if err != nil {
					return nil, fmt.Errorf("failed to select SD/CM AID before SCP02: %w", err)
				}
				return nil, fmt.Errorf("failed to select SD/CM AID before SCP02: %s (SW=%04X)", card.SWToString(resp.SW()), resp.SW())
			}
		}
	}

	hostChallenge := make([]byte, 8)
	if _, err := rand.Read(hostChallenge); err != nil {
		return nil, fmt.Errorf("failed to generate host challenge: %w", err)
	}
	return card.OpenSCP02(reader, cfg.StaticKeys, cfg.KVN, cfg.Security, hostChallenge)
}

// ListAppletsSecure lists GP registry via SCP02 secure channel.
func ListAppletsSecure(reader *card.Reader, cfg GPConfig) ([]Applet, error) {
	sess, err := OpenGPSCP02(reader, cfg)
	if err != nil {
		return nil, err
	}
	// IMPORTANT: do NOT perform a plain SELECT after opening SCP02.
	// Some cards drop or invalidate the secure channel on (re)SELECT, which would make the next
	// secure-messaging command fail with 6985/6982. OpenGPSCP02 already selects the SD/CM AID
	// before INITIALIZE UPDATE.

	var applets []Applet
	for _, entry := range []struct {
		p1  byte
		typ string
	}{
		{0x80, "ISD"},
		{0x40, "App"},
		{0x20, "Package"},
		{0x10, "Module"},
	} {
		list, err := gpGetStatusSecure(sess, entry.p1)
		if err != nil {
			return nil, err
		}
		for _, a := range list {
			a.Type = entry.typ
			applets = append(applets, a)
		}
	}
	return applets, nil
}

func gpGetStatusSecure(sess *card.SCP02Session, p1 byte) ([]Applet, error) {
	// There are cards that reject some GET STATUS data formats with SW=6A80/6985.
	// pySim uses TLV format (P2=0x02) and includes a tag list (5C...) by default, but we
	// auto-fallback to simpler forms to maximize compatibility.
	type variant struct {
		name   string
		p2Base byte
		data   []byte
	}
	variants := []variant{
		{
			name:   "TLV P2=0x02 + data=4F00",
			p2Base: 0x02,
			data:   []byte{0x4F, 0x00},
		},
		{
			name:   "TLV P2=0x02 + data=4F00 + 5C(4F,9F70,C5)",
			p2Base: 0x02,
			// tag list: 4F (AID), 9F70 (LifeCycle), C5 (Privileges)
			data: []byte{0x4F, 0x00, 0x5C, 0x04, 0x4F, 0x9F, 0x70, 0xC5},
		},
		{
			name:   "TLV P2=0x02 + data=4F00 + 5C(4F,9F70,C5,CC) (pySim)",
			p2Base: 0x02,
			// pySim default: cmd_data = aid.to_tlv() + 5c054f9f70c5cc
			data: []byte{0x4F, 0x00, 0x5C, 0x05, 0x4F, 0x9F, 0x70, 0xC5, 0xCC},
		},
	}

	var lastErr error
	for _, v := range variants {
		applets, err := gpGetStatusSecureVariant(sess, p1, v.p2Base, v.data)
		if err == nil {
			return applets, nil
		}
		lastErr = fmt.Errorf("%s: %w", v.name, err)
	}
	return nil, lastErr
}

func gpGetStatusSecureVariant(sess *card.SCP02Session, p1 byte, p2Base byte, cmdData []byte) ([]Applet, error) {
	var applets []Applet
	le := byte(0x00)

	// P2 bit0 is used for paging when SW=6310 (more data): set P2|=0x01 on next calls.
	p2 := p2Base
	for {
		resp, err := sess.WrapAndSend(0x80, 0xF2, p1, p2, cmdData, &le)
		if err != nil {
			return applets, err
		}

		sw := resp.SW()
		if !resp.IsOK() && sw != 0x6310 {
			return applets, fmt.Errorf("GET STATUS failed: %s (SW=%04X)", card.SWToString(sw), sw)
		}

		applets = append(applets, parseGetStatusResponse(resp.Data)...)
		if sw == 0x6310 {
			p2 = p2Base | 0x01
			continue
		}
		return applets, nil
	}
}

// DeleteAIDs deletes apps/packages/SDs by AID using SCP02 secure channel.
// WARNING: This can permanently remove card functionality. Use with caution.
func DeleteAIDs(reader *card.Reader, cfg GPConfig, aids [][]byte) error {
	sess, err := OpenGPSCP02(reader, cfg)
	if err != nil {
		return err
	}
	le := byte(0x00)
	data := make([]byte, 0, 3*len(aids)+32)
	for _, aid := range aids {
		data = append(data, 0x4F, byte(len(aid)))
		data = append(data, aid...)
	}
	resp, err := sess.WrapAndSend(0x80, 0xE4, 0x00, 0x00, data, &le)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("DELETE failed: %s (SW=%04X)", card.SWToString(resp.SW()), resp.SW())
	}
	return nil
}

// InstallLoadAndApplet loads a CAP and installs an applet instance.
// This is a minimal implementation (no DAP, no tokens, minimal params).
func InstallLoadAndApplet(reader *card.Reader, cfg GPConfig, capZipPath string, sdAID, packageAID, appletAID, instanceAID []byte) error {
	if cfg.BlockSize <= 0 {
		cfg.BlockSize = 200
	}
	sess, err := OpenGPSCP02(reader, cfg)
	if err != nil {
		return err
	}
	le := byte(0x00)

	// INSTALL [for load] (P1=02)
	// Data: len(loadFileAID) loadFileAID | len(sdAID) sdAID | len(hash)=0 | len(params)=0 | len(token)=0
	installForLoad := make([]byte, 0, 64)
	installForLoad = append(installForLoad, byte(len(packageAID)))
	installForLoad = append(installForLoad, packageAID...)
	installForLoad = append(installForLoad, byte(len(sdAID)))
	installForLoad = append(installForLoad, sdAID...)
	installForLoad = append(installForLoad, 0x00, 0x00, 0x00)
	resp, err := sess.WrapAndSend(0x80, 0xE6, 0x02, 0x00, installForLoad, &le)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("INSTALL [for load] failed: %s (SW=%04X)", card.SWToString(resp.SW()), resp.SW())
	}

	// LOAD blocks
	loadFile, err := ReadCAPLoadFile(capZipPath)
	if err != nil {
		return err
	}

	blockNo := byte(0x00)
	for off := 0; off < len(loadFile); {
		remaining := len(loadFile) - off
		chunk := cfg.BlockSize
		if remaining < chunk {
			chunk = remaining
		}
		part := loadFile[off : off+chunk]
		off += chunk

		p1 := byte(0x00) // last
		if off < len(loadFile) {
			p1 = 0x80 // more blocks follow
		}

		resp, err := sess.WrapAndSend(0x80, 0xE8, p1, blockNo, part, &le)
		if err != nil {
			return err
		}
		if !resp.IsOK() {
			return fmt.Errorf("LOAD failed at block %d: %s (SW=%04X)", blockNo, card.SWToString(resp.SW()), resp.SW())
		}
		blockNo++
	}

	// INSTALL [for install] (P1=0C)
	// Data: len(pkgAID) pkgAID | len(appletAID) appletAID | len(instanceAID) instanceAID |
	//       len(priv)=0 | len(params)=0 | len(token)=0
	installForInstall := make([]byte, 0, 128)
	installForInstall = append(installForInstall, byte(len(packageAID)))
	installForInstall = append(installForInstall, packageAID...)
	installForInstall = append(installForInstall, byte(len(appletAID)))
	installForInstall = append(installForInstall, appletAID...)
	installForInstall = append(installForInstall, byte(len(instanceAID)))
	installForInstall = append(installForInstall, instanceAID...)
	installForInstall = append(installForInstall, 0x00, 0x00, 0x00)

	resp, err = sess.WrapAndSend(0x80, 0xE6, 0x0C, 0x00, installForInstall, &le)
	if err != nil {
		return err
	}
	if !resp.IsOK() {
		return fmt.Errorf("INSTALL [for install] failed: %s (SW=%04X)", card.SWToString(resp.SW()), resp.SW())
	}

	return nil
}

// ReadCAPLoadFile reads a ZIP .cap and produces a "load file" byte stream by concatenating component CAP files.
// This is a pragmatic approach compatible with common CAP ZIP layouts.
func ReadCAPLoadFile(zipPath string) ([]byte, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open cap zip: %w", err)
	}
	defer zr.Close()

	// Standard CAP component order (best-effort).
	order := []string{
		"Header.cap",
		"Directory.cap",
		"Import.cap",
		"Applet.cap",
		"Class.cap",
		"Method.cap",
		"StaticField.cap",
		"Export.cap",
		"ConstantPool.cap",
		"RefLocation.cap",
		"Descriptor.cap",
		"Debug.cap",
	}

	type entry struct {
		name string
		data []byte
	}
	found := map[string]entry{}
	for _, f := range zr.File {
		for _, want := range order {
			if strings.HasSuffix(f.Name, "/"+want) || f.Name == want {
				rc, err := f.Open()
				if err != nil {
					return nil, fmt.Errorf("open %s: %w", f.Name, err)
				}
				b, err := io.ReadAll(rc)
				_ = rc.Close()
				if err != nil {
					return nil, fmt.Errorf("read %s: %w", f.Name, err)
				}
				found[want] = entry{name: f.Name, data: b}
			}
		}
	}

	var out []byte
	for _, name := range order {
		if e, ok := found[name]; ok {
			out = append(out, e.data...)
		}
	}
	if len(out) == 0 {
		// help debugging: show zip entries
		var names []string
		for _, f := range zr.File {
			names = append(names, f.Name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("no CAP component files found in zip. Entries: %v", names)
	}
	return out, nil
}

// GPSelectVerify selects an AID and returns SW.
func GPSelectVerify(reader *card.Reader, aid []byte) (uint16, error) {
	resp, err := reader.Select(aid)
	if err != nil {
		return 0, err
	}
	return resp.SW(), nil
}

// ParseAIDList parses comma-separated hex AIDs.
func ParseAIDList(s string) ([][]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	var out [][]byte
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		aid, err := ParseAIDHex(p)
		if err != nil {
			return nil, err
		}
		out = append(out, aid)
	}
	return out, nil
}

// EnsureFileExists checks path exists (helpful for user-facing error).
func EnsureFileExists(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	_, err := os.Stat(path)
	if err != nil {
		return err
	}
	return nil
}
