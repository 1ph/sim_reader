package esim

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Parser parses ASN.1 Value Notation into Profile structure
type Parser struct {
	tokens  []Token
	pos     int
	profile *Profile
}

// ParseValueNotation parses ASN.1 Value Notation text into Profile
func ParseValueNotation(input string) (*Profile, error) {
	tokenizer := NewTokenizer(input)
	tokens, err := tokenizer.Tokenize()
	if err != nil {
		return nil, fmt.Errorf("tokenization error: %w", err)
	}

	parser := &Parser{
		tokens:  tokens,
		pos:     0,
		profile: &Profile{Elements: make([]ProfileElement, 0)},
	}

	if err := parser.parse(); err != nil {
		return nil, err
	}

	return parser.profile, nil
}

// ParseValueNotationFile parses ASN.1 Value Notation from file
func ParseValueNotationFile(filename string) (*Profile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return ParseValueNotation(string(data))
}

// ============================================================================
// Parser core
// ============================================================================

func (p *Parser) current() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) peek() Token {
	return p.current()
}

func (p *Parser) peekAt(offset int) Token {
	pos := p.pos + offset
	if pos >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[pos]
}

func (p *Parser) advance() Token {
	tok := p.current()
	p.pos++
	return tok
}

func (p *Parser) expect(typ TokenType) (Token, error) {
	tok := p.current()
	if tok.Type != typ {
		return tok, fmt.Errorf("expected %v, got %v at line %d, column %d", typ, tok, tok.Line, tok.Column)
	}
	p.advance()
	return tok, nil
}

func (p *Parser) expectIdent(value string) error {
	tok := p.current()
	if tok.Type != TokenIdent || tok.Value != value {
		return fmt.Errorf("expected identifier '%s', got %v at line %d, column %d", value, tok, tok.Line, tok.Column)
	}
	p.advance()
	return nil
}

func (p *Parser) parse() error {
	for p.peek().Type != TokenEOF {
		if err := p.parseValueDefinition(); err != nil {
			return err
		}
	}
	return nil
}

// parseValueDefinition parses: valueN ProfileElement ::= choice : { ... }
func (p *Parser) parseValueDefinition() error {
	// Skip value name (e.g., "value1")
	if p.peek().Type != TokenIdent {
		return fmt.Errorf("expected value identifier at line %d", p.peek().Line)
	}
	p.advance()

	// Expect "ProfileElement"
	if err := p.expectIdent("ProfileElement"); err != nil {
		return err
	}

	// Expect "::="
	if _, err := p.expect(TokenAssign); err != nil {
		return err
	}

	// Get choice name (header, mf, usim, etc.)
	choiceTok, err := p.expect(TokenIdent)
	if err != nil {
		return err
	}

	// Expect ":"
	if _, err := p.expect(TokenColon); err != nil {
		return err
	}

	// Parse the element content
	elem, err := p.parseProfileElement(choiceTok.Value)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", choiceTok.Value, err)
	}

	p.profile.Elements = append(p.profile.Elements, *elem)
	assignToProfile(p.profile, elem)

	return nil
}

// parseProfileElement parses a profile element by choice name
func (p *Parser) parseProfileElement(choice string) (*ProfileElement, error) {
	tag := getTagFromChoice(choice)
	elem := &ProfileElement{Tag: tag}

	switch choice {
	case "header":
		val, err := p.parseProfileHeader()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "mf":
		val, err := p.parseMasterFile()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "pukCodes":
		val, err := p.parsePUKCodes()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "pinCodes":
		val, err := p.parsePINCodes()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "telecom":
		val, err := p.parseTelecom()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "usim":
		val, err := p.parseUSIM()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "opt-usim":
		val, err := p.parseOptUSIM()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "isim":
		val, err := p.parseISIM()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "opt-isim":
		val, err := p.parseOptISIM()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "csim":
		val, err := p.parseCSIM()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "opt-csim":
		val, err := p.parseOptCSIM()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "gsm-access":
		val, err := p.parseGSMAccess()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "akaParameter":
		val, err := p.parseAKAParameter()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "cdmaParameter":
		val, err := p.parseCDMAParameter()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "df-5gs":
		val, err := p.parseDF5GS()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "df-saip":
		val, err := p.parseDFSAIP()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "genericFileManagement":
		val, err := p.parseGenericFileManagement()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "securityDomain":
		val, err := p.parseSecurityDomain()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "rfm":
		val, err := p.parseRFM()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	case "end":
		val, err := p.parseEnd()
		if err != nil {
			return nil, err
		}
		elem.Value = val
	default:
		return nil, fmt.Errorf("unknown profile element type: %s", choice)
	}

	return elem, nil
}

func getTagFromChoice(choice string) int {
	switch choice {
	case "header":
		return TagProfileHeader
	case "mf":
		return TagMF
	case "pukCodes":
		return TagPukCodes
	case "pinCodes":
		return TagPinCodes
	case "telecom":
		return TagTelecom
	case "usim":
		return TagUSIM
	case "opt-usim":
		return TagOptUSIM
	case "isim":
		return TagISIM
	case "opt-isim":
		return TagOptISIM
	case "csim":
		return TagCSIM
	case "opt-csim":
		return TagOptCSIM
	case "gsm-access":
		return TagGSMAccess
	case "akaParameter":
		return TagAKAParameter
	case "cdmaParameter":
		return TagCDMAParameter
	case "df-5gs":
		return TagDF5GS
	case "df-saip":
		return TagDFSAIP
	case "genericFileManagement":
		return TagGenericFileManagement
	case "securityDomain":
		return TagSecurityDomain
	case "rfm":
		return TagRFM
	case "application":
		return TagApplication
	case "end":
		return TagEnd
	default:
		return -1
	}
}

// ============================================================================
// ProfileHeader parser
// ============================================================================

func (p *Parser) parseProfileHeader() (*ProfileHeader, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	h := &ProfileHeader{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "major-version":
			h.MajorVersion, err = p.parseIntValue()
		case "minor-version":
			h.MinorVersion, err = p.parseIntValue()
		case "profileType":
			h.ProfileType, err = p.parseStringValue()
		case "iccid":
			h.ICCID, err = p.parseHexValue()
		case "eUICC-Mandatory-services":
			h.MandatoryServices, err = p.parseMandatoryServices()
		case "eUICC-Mandatory-GFSTEList":
			h.MandatoryGFSTEList, err = p.parseOIDList()
		default:
			// Skip unknown fields
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return h, nil
}

func (p *Parser) parseMandatoryServices() (*MandatoryServices, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	ms := &MandatoryServices{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		// Expect NULL
		if p.peek().Type == TokenNull {
			p.advance()
		}

		switch fieldName.Value {
		case "usim":
			ms.USIM = true
		case "isim":
			ms.ISIM = true
		case "csim":
			ms.CSIM = true
		case "usim-test-algorithm":
			ms.USIMTestAlgorithm = true
		case "ber-tlv":
			ms.BERTLV = true
		case "get-identity":
			ms.GetIdentity = true
		case "profile-a-x25519":
			ms.ProfileAX25519 = true
		case "profile-b-p256":
			ms.ProfileBP256 = true
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return ms, nil
}

func (p *Parser) parseOIDList() ([]OID, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var oids []OID

	for p.peek().Type != TokenRBrace {
		oid, err := p.parseOID()
		if err != nil {
			return nil, err
		}
		oids = append(oids, oid)
		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return oids, nil
}

func (p *Parser) parseOID() (OID, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var oid OID

	for p.peek().Type != TokenRBrace {
		num, err := p.parseIntValue()
		if err != nil {
			return nil, err
		}
		oid = append(oid, num)
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return oid, nil
}

// ============================================================================
// MasterFile parser
// ============================================================================

func (p *Parser) parseMasterFile() (*MasterFile, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	mf := &MasterFile{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "mf-header":
			mf.MFHeader, err = p.parseElementHeader()
		case "templateID":
			mf.TemplateID, err = p.parseOID()
		case "mf":
			mf.MF, err = p.parseFileDescriptorWrapper()
		case "ef-pl":
			mf.EF_PL, err = p.parseElementaryFile()
		case "ef-iccid":
			mf.EF_ICCID, err = p.parseElementaryFile()
		case "ef-dir":
			mf.EF_DIR, err = p.parseElementaryFile()
		case "ef-arr":
			mf.EF_ARR, err = p.parseElementaryFile()
		case "ef-umpc":
			mf.EF_UMPC, err = p.parseElementaryFile()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return mf, nil
}

func (p *Parser) parseElementHeader() (*ElementHeader, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	eh := &ElementHeader{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "mandated":
			if p.peek().Type == TokenNull {
				p.advance()
			}
			eh.Mandated = true
		case "identification":
			eh.Identification, err = p.parseIntValue()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return eh, nil
}

func (p *Parser) parseFileDescriptorWrapper() (*FileDescriptor, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	// Check for "fileDescriptor :" syntax
	if p.peek().Type == TokenIdent && p.peek().Value == "fileDescriptor" {
		p.advance()
		if p.peek().Type == TokenColon {
			p.advance()
		}
	}

	fd, err := p.parseFileDescriptor()
	if err != nil {
		return nil, err
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return fd, nil
}

func (p *Parser) parseFileDescriptor() (*FileDescriptor, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	fd := &FileDescriptor{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "fileDescriptor":
			fd.FileDescriptor, err = p.parseHexValue()
		case "fileID":
			fd.FileID, err = p.parseHexValue()
		case "lcsi":
			fd.LCSI, err = p.parseHexValue()
		case "securityAttributesReferenced":
			fd.SecurityAttributesReferenced, err = p.parseHexValue()
		case "shortEFID":
			fd.ShortEFID, err = p.parseHexValue()
		case "efFileSize":
			fd.EFFileSize, err = p.parseHexValue()
		case "dfName":
			fd.DFName, err = p.parseHexValue()
		case "pinStatusTemplateDO":
			fd.PinStatusTemplateDO, err = p.parseHexValue()
		case "linkPath":
			fd.LinkPath, err = p.parseHexValue()
		case "proprietaryEFInfo":
			fd.ProprietaryEFInfo, err = p.parseProprietaryEFInfo()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return fd, nil
}

func (p *Parser) parseProprietaryEFInfo() (*ProprietaryEFInfo, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	pei := &ProprietaryEFInfo{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		var fieldErr error
		switch fieldName.Value {
		case "specialFileInformation":
			pei.SpecialFileInformation, fieldErr = p.parseHexValue()
		case "fillPattern":
			pei.FillPattern, fieldErr = p.parseHexValue()
		case "repeatPattern":
			pei.RepeatPattern, fieldErr = p.parseHexValue()
		case "maximumFileSize":
			pei.MaximumFileSize, fieldErr = p.parseHexValue()
		case "fileDetails":
			pei.FileDetails, fieldErr = p.parseHexValue()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if fieldErr != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, fieldErr)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return pei, nil
}

func (p *Parser) parseElementaryFile() (*ElementaryFile, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	ef := &ElementaryFile{
		FillContents: make([]FillContent, 0),
		Raw:          make(File, 0),
	}

	var currentOffset int

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		// Skip optional colon
		if p.peek().Type == TokenColon {
			p.advance()
		}

		switch fieldName.Value {
		case "fileDescriptor":
			ef.Descriptor, err = p.parseFileDescriptor()
			if err != nil {
				return nil, err
			}
			ef.Raw = append(ef.Raw, FileElement{
				Type:       FileElementDescriptor,
				Descriptor: ef.Descriptor,
			})
		case "fillFileOffset":
			currentOffset, err = p.parseIntValue()
			if err != nil {
				return nil, err
			}
			ef.Raw = append(ef.Raw, FileElement{
				Type:   FileElementOffset,
				Offset: currentOffset,
			})
		case "fillFileContent":
			content, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			ef.FillContents = append(ef.FillContents, FillContent{
				Offset:  currentOffset,
				Content: content,
			})
			ef.Raw = append(ef.Raw, FileElement{
				Type:    FileElementContent,
				Content: content,
			})
			currentOffset = 0 // Reset offset after content
		case "doNotCreate":
			if p.peek().Type == TokenNull {
				p.advance()
			}
			ef.Raw = append(ef.Raw, FileElement{
				Type: FileElementDoNotCreate,
			})
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return ef, nil
}

// ============================================================================
// PUK/PIN Codes parser
// ============================================================================

func (p *Parser) parsePUKCodes() (*PUKCodes, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	puk := &PUKCodes{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "puk-Header":
			puk.Header, err = p.parseElementHeader()
		case "pukCodes":
			puk.Codes, err = p.parsePUKCodeList()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return puk, nil
}

func (p *Parser) parsePUKCodeList() ([]PUKCode, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var codes []PUKCode

	for p.peek().Type != TokenRBrace {
		code, err := p.parsePUKCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, *code)
		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return codes, nil
}

func (p *Parser) parsePUKCode() (*PUKCode, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	code := &PUKCode{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "keyReference":
			code.KeyReference, err = p.parseKeyReference()
		case "pukValue":
			code.PUKValue, err = p.parseHexValue()
		case "maxNumOfAttemps-retryNumLeft":
			val, intErr := p.parseIntValue()
			if intErr != nil {
				return nil, intErr
			}
			code.MaxNumOfAttempsRetryNumLeft = byte(val)
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return code, nil
}

func (p *Parser) parsePINCodes() (*PINCodes, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	pin := &PINCodes{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "pin-Header":
			pin.Header, err = p.parseElementHeader()
		case "pinCodes":
			// Skip "pinconfig :" if present
			if p.peek().Type == TokenIdent && p.peek().Value == "pinconfig" {
				p.advance()
				if p.peek().Type == TokenColon {
					p.advance()
				}
			}
			pin.Configs, err = p.parsePINConfigList()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return pin, nil
}

func (p *Parser) parsePINConfigList() ([]PINConfig, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var configs []PINConfig

	for p.peek().Type != TokenRBrace {
		config, err := p.parsePINConfig()
		if err != nil {
			return nil, err
		}
		configs = append(configs, *config)
		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return configs, nil
}

func (p *Parser) parsePINConfig() (*PINConfig, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	config := &PINConfig{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "keyReference":
			config.KeyReference, err = p.parseKeyReference()
		case "pinValue":
			config.PINValue, err = p.parseHexValue()
		case "unblockingPINReference":
			config.UnblockingPINReference, err = p.parseKeyReference()
		case "pinAttributes":
			val, intErr := p.parseIntValue()
			if intErr != nil {
				return nil, intErr
			}
			config.PINAttributes = byte(val)
		case "maxNumOfAttemps-retryNumLeft":
			val, intErr := p.parseIntValue()
			if intErr != nil {
				return nil, intErr
			}
			config.MaxNumOfAttempsRetryNumLeft = byte(val)
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return config, nil
}

func (p *Parser) parseKeyReference() (byte, error) {
	tok := p.peek()
	if tok.Type == TokenIdent {
		p.advance()
		// Map key reference names to values
		switch tok.Value {
		case "pinAppl1":
			return 0x01, nil
		case "secondPINAppl1":
			return 0x81, nil
		case "pukAppl1":
			return 0x01, nil
		case "secondPUKAppl1":
			return 0x81, nil
		case "adm1":
			return 0x0A, nil
		case "adm2":
			return 0x0B, nil
		default:
			return 0, fmt.Errorf("unknown key reference: %s", tok.Value)
		}
	}
	val, err := p.parseIntValue()
	return byte(val), err
}

// ============================================================================
// Telecom parser
// ============================================================================

func (p *Parser) parseTelecom() (*TelecomDF, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	t := &TelecomDF{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "telecom-header":
			t.Header, err = p.parseElementHeader()
		case "templateID":
			t.TemplateID, err = p.parseOID()
		case "df-telecom":
			t.DFTelecom, err = p.parseFileDescriptorWrapper()
		case "ef-arr":
			t.EF_ARR, err = p.parseElementaryFile()
		case "ef-sume":
			t.EF_SUME, err = p.parseElementaryFile()
		case "ef-psismsc":
			t.EF_PSISMSC, err = p.parseElementaryFile()
		case "df-graphics":
			t.DFGraphics, err = p.parseFileDescriptorWrapper()
		case "ef-img":
			t.EF_IMG, err = p.parseElementaryFile()
		case "ef-launch-scws":
			t.EF_LaunchSCWS, err = p.parseElementaryFile()
		case "df-phonebook":
			t.DFPhonebook, err = p.parseFileDescriptorWrapper()
		case "ef-pbr":
			t.EF_PBR, err = p.parseElementaryFile()
		case "ef-psc":
			t.EF_PSC, err = p.parseElementaryFile()
		case "ef-cc":
			t.EF_CC, err = p.parseElementaryFile()
		case "ef-puid":
			t.EF_PUID, err = p.parseElementaryFile()
		case "df-mmss":
			t.DFMMSS, err = p.parseFileDescriptorWrapper()
		case "ef-mlpl":
			t.EF_MLPL, err = p.parseElementaryFile()
		case "ef-mspl":
			t.EF_MSPL, err = p.parseElementaryFile()
		default:
			// Store unknown EFs
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				t.AdditionalEFs[fieldName.Value] = ef
			} else if strings.HasPrefix(fieldName.Value, "df-") {
				_, dfErr := p.parseFileDescriptorWrapper()
				if dfErr != nil {
					return nil, dfErr
				}
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return t, nil
}

// ============================================================================
// USIM parser
// ============================================================================

func (p *Parser) parseUSIM() (*USIMApplication, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	u := &USIMApplication{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "usim-header":
			u.Header, err = p.parseElementHeader()
		case "templateID":
			u.TemplateID, err = p.parseOID()
		case "adf-usim":
			u.ADFUSIM, err = p.parseFileDescriptorWrapper()
		case "ef-imsi":
			u.EF_IMSI, err = p.parseElementaryFile()
		case "ef-arr":
			u.EF_ARR, err = p.parseElementaryFile()
		case "ef-keys":
			u.EF_Keys, err = p.parseElementaryFile()
		case "ef-keysPS":
			u.EF_KeysPS, err = p.parseElementaryFile()
		case "ef-hpplmn":
			u.EF_HPPLMN, err = p.parseElementaryFile()
		case "ef-ust":
			u.EF_UST, err = p.parseElementaryFile()
		case "ef-fdn":
			u.EF_FDN, err = p.parseElementaryFile()
		case "ef-sms":
			u.EF_SMS, err = p.parseElementaryFile()
		case "ef-smsp":
			u.EF_SMSP, err = p.parseElementaryFile()
		case "ef-smss":
			u.EF_SMSS, err = p.parseElementaryFile()
		case "ef-spn":
			u.EF_SPN, err = p.parseElementaryFile()
		case "ef-est":
			u.EF_EST, err = p.parseElementaryFile()
		case "ef-start-hfn":
			u.EF_StartHFN, err = p.parseElementaryFile()
		case "ef-threshold":
			u.EF_Threshold, err = p.parseElementaryFile()
		case "ef-psloci":
			u.EF_PSLOCI, err = p.parseElementaryFile()
		case "ef-acc":
			u.EF_ACC, err = p.parseElementaryFile()
		case "ef-fplmn":
			u.EF_FPLMN, err = p.parseElementaryFile()
		case "ef-loci":
			u.EF_LOCI, err = p.parseElementaryFile()
		case "ef-ad":
			u.EF_AD, err = p.parseElementaryFile()
		case "ef-ecc":
			u.EF_ECC, err = p.parseElementaryFile()
		case "ef-netpar":
			u.EF_NETPAR, err = p.parseElementaryFile()
		case "ef-epsloci":
			u.EF_EPSLOCI, err = p.parseElementaryFile()
		case "ef-epsnsc":
			u.EF_EPSNSC, err = p.parseElementaryFile()
		default:
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				u.AdditionalEFs[fieldName.Value] = ef
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return u, nil
}

func (p *Parser) parseOptUSIM() (*OptionalUSIM, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	u := &OptionalUSIM{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "optusim-header":
			u.Header, err = p.parseElementHeader()
		case "templateID":
			u.TemplateID, err = p.parseOID()
		case "ef-li":
			u.EF_LI, err = p.parseElementaryFile()
		case "ef-acmax":
			u.EF_ACMAX, err = p.parseElementaryFile()
		case "ef-acm":
			u.EF_ACM, err = p.parseElementaryFile()
		case "ef-gid1":
			u.EF_GID1, err = p.parseElementaryFile()
		case "ef-gid2":
			u.EF_GID2, err = p.parseElementaryFile()
		case "ef-msisdn":
			u.EF_MSISDN, err = p.parseElementaryFile()
		case "ef-puct":
			u.EF_PUCT, err = p.parseElementaryFile()
		case "ef-cbmi":
			u.EF_CBMI, err = p.parseElementaryFile()
		case "ef-cbmid":
			u.EF_CBMID, err = p.parseElementaryFile()
		case "ef-sdn":
			u.EF_SDN, err = p.parseElementaryFile()
		case "ef-ext2":
			u.EF_EXT2, err = p.parseElementaryFile()
		case "ef-ext3":
			u.EF_EXT3, err = p.parseElementaryFile()
		case "ef-cbmir":
			u.EF_CBMIR, err = p.parseElementaryFile()
		case "ef-plmnwact":
			u.EF_PLMNWACT, err = p.parseElementaryFile()
		case "ef-oplmnwact":
			u.EF_OPLMNWACT, err = p.parseElementaryFile()
		case "ef-hplmnwact":
			u.EF_HPLMNWACT, err = p.parseElementaryFile()
		case "ef-dck":
			u.EF_DCK, err = p.parseElementaryFile()
		case "ef-cnl":
			u.EF_CNL, err = p.parseElementaryFile()
		case "ef-smsr":
			u.EF_SMSR, err = p.parseElementaryFile()
		case "ef-bdn":
			u.EF_BDN, err = p.parseElementaryFile()
		case "ef-ext5":
			u.EF_EXT5, err = p.parseElementaryFile()
		case "ef-ccp2":
			u.EF_CCP2, err = p.parseElementaryFile()
		case "ef-acl":
			u.EF_ACL, err = p.parseElementaryFile()
		case "ef-cmi":
			u.EF_CMI, err = p.parseElementaryFile()
		case "ef-ici":
			u.EF_ICI, err = p.parseElementaryFile()
		case "ef-oci":
			u.EF_OCI, err = p.parseElementaryFile()
		case "ef-ict":
			u.EF_ICT, err = p.parseElementaryFile()
		case "ef-oct":
			u.EF_OCT, err = p.parseElementaryFile()
		case "ef-vgcs":
			u.EF_VGCS, err = p.parseElementaryFile()
		case "ef-vgcss":
			u.EF_VGCSS, err = p.parseElementaryFile()
		case "ef-vbs":
			u.EF_VBS, err = p.parseElementaryFile()
		case "ef-vbss":
			u.EF_VBSS, err = p.parseElementaryFile()
		case "ef-emlpp":
			u.EF_EMLPP, err = p.parseElementaryFile()
		case "ef-aaem":
			u.EF_AAEM, err = p.parseElementaryFile()
		case "ef-hiddenkey":
			u.EF_HIDDENKEY, err = p.parseElementaryFile()
		case "ef-pnn":
			u.EF_PNN, err = p.parseElementaryFile()
		case "ef-opl":
			u.EF_OPL, err = p.parseElementaryFile()
		case "ef-mmsn":
			u.EF_MMSN, err = p.parseElementaryFile()
		case "ef-ext8":
			u.EF_EXT8, err = p.parseElementaryFile()
		case "ef-mmsicp":
			u.EF_MMSICP, err = p.parseElementaryFile()
		case "ef-mmsup":
			u.EF_MMSUP, err = p.parseElementaryFile()
		case "ef-mmsucp":
			u.EF_MMSUCP, err = p.parseElementaryFile()
		case "ef-nia":
			u.EF_NIA, err = p.parseElementaryFile()
		case "ef-vgcsca":
			u.EF_VGCSCA, err = p.parseElementaryFile()
		case "ef-vbsca":
			u.EF_VBSCA, err = p.parseElementaryFile()
		case "ef-ehplmn":
			u.EF_EHPLMN, err = p.parseElementaryFile()
		case "ef-ehplmnpi":
			u.EF_EHPLMNPI, err = p.parseElementaryFile()
		case "ef-lrplmnsi":
			u.EF_LRPLMNSI, err = p.parseElementaryFile()
		case "ef-nasconfig":
			u.EF_NASCONFIG, err = p.parseElementaryFile()
		case "ef-fdnuri":
			u.EF_FDNURI, err = p.parseElementaryFile()
		case "ef-sdnuri":
			u.EF_SDNURI, err = p.parseElementaryFile()
		default:
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				u.AdditionalEFs[fieldName.Value] = ef
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return u, nil
}

// ============================================================================
// ISIM parser
// ============================================================================

func (p *Parser) parseISIM() (*ISIMApplication, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	i := &ISIMApplication{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "isim-header":
			i.Header, err = p.parseElementHeader()
		case "templateID":
			i.TemplateID, err = p.parseOID()
		case "adf-isim":
			i.ADFISIM, err = p.parseFileDescriptorWrapper()
		case "ef-impi":
			i.EF_IMPI, err = p.parseElementaryFile()
		case "ef-impu":
			i.EF_IMPU, err = p.parseElementaryFile()
		case "ef-domain":
			i.EF_DOMAIN, err = p.parseElementaryFile()
		case "ef-ist":
			i.EF_IST, err = p.parseElementaryFile()
		case "ef-ad":
			i.EF_AD, err = p.parseElementaryFile()
		case "ef-arr":
			i.EF_ARR, err = p.parseElementaryFile()
		default:
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				i.AdditionalEFs[fieldName.Value] = ef
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return i, nil
}

func (p *Parser) parseOptISIM() (*OptionalISIM, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	i := &OptionalISIM{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "optisim-header":
			i.Header, err = p.parseElementHeader()
		case "templateID":
			i.TemplateID, err = p.parseOID()
		case "ef-pcscf":
			i.EF_PCSCF, err = p.parseElementaryFile()
		case "ef-gbabp":
			i.EF_GBABP, err = p.parseElementaryFile()
		case "ef-gbanl":
			i.EF_GBANL, err = p.parseElementaryFile()
		default:
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				i.AdditionalEFs[fieldName.Value] = ef
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return i, nil
}

// ============================================================================
// CSIM parser
// ============================================================================

func (p *Parser) parseCSIM() (*CSIMApplication, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	c := &CSIMApplication{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "csim-header":
			c.Header, err = p.parseElementHeader()
		case "templateID":
			c.TemplateID, err = p.parseOID()
		case "adf-csim":
			c.ADFCSIM, err = p.parseFileDescriptorWrapper()
		case "ef-arr":
			c.EF_ARR, err = p.parseElementaryFile()
		default:
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				c.AdditionalEFs[fieldName.Value] = ef
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return c, nil
}

func (p *Parser) parseOptCSIM() (*OptionalCSIM, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	c := &OptionalCSIM{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "optcsim-header":
			c.Header, err = p.parseElementHeader()
		case "templateID":
			c.TemplateID, err = p.parseOID()
		default:
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				c.AdditionalEFs[fieldName.Value] = ef
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return c, nil
}

// ============================================================================
// GSM Access parser
// ============================================================================

func (p *Parser) parseGSMAccess() (*GSMAccessDF, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	g := &GSMAccessDF{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "gsm-access-header":
			g.Header, err = p.parseElementHeader()
		case "templateID":
			g.TemplateID, err = p.parseOID()
		case "df-gsm-access":
			g.DFGSMAccess, err = p.parseFileDescriptorWrapper()
		case "ef-kc":
			g.EF_Kc, err = p.parseElementaryFile()
		case "ef-kcgprs":
			g.EF_KcGPRS, err = p.parseElementaryFile()
		case "ef-cpbcch":
			g.EF_CPBCCH, err = p.parseElementaryFile()
		case "ef-invscan":
			g.EF_INVSCAN, err = p.parseElementaryFile()
		default:
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				g.AdditionalEFs[fieldName.Value] = ef
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return g, nil
}

// ============================================================================
// DF-5GS parser
// ============================================================================

func (p *Parser) parseDF5GS() (*DF5GS, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	d := &DF5GS{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "df-5gs-header":
			d.Header, err = p.parseElementHeader()
		case "templateID":
			d.TemplateID, err = p.parseOID()
		case "df-df-5gs":
			d.DFDF5GS, err = p.parseFileDescriptorWrapper()
		case "ef-5gs3gpploci":
			d.EF_5GS3GPPLOCI, err = p.parseElementaryFile()
		case "ef-5gsn3gpploci":
			d.EF_5GSN3GPPLOCI, err = p.parseElementaryFile()
		case "ef-5gs3gppnsc":
			d.EF_5GS3GPPNSC, err = p.parseElementaryFile()
		case "ef-5gsn3gppnsc":
			d.EF_5GSN3GPPNSC, err = p.parseElementaryFile()
		case "ef-5gauthkeys":
			d.EF_5GAUTHKEYS, err = p.parseElementaryFile()
		case "ef-uac-aic":
			d.EF_UAC_AIC, err = p.parseElementaryFile()
		case "ef-suci-calc-info":
			d.EF_SUCI_CALC_INFO, err = p.parseElementaryFile()
		case "ef-opl5g":
			d.EF_OPL5G, err = p.parseElementaryFile()
		case "ef-routing-indicator":
			d.EF_ROUTING_INDICATOR, err = p.parseElementaryFile()
		default:
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				d.AdditionalEFs[fieldName.Value] = ef
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return d, nil
}

// ============================================================================
// DF-SAIP parser
// ============================================================================

func (p *Parser) parseDFSAIP() (*DFSAIP, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	d := &DFSAIP{AdditionalEFs: make(map[string]*ElementaryFile)}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "df-saip-header":
			d.Header, err = p.parseElementHeader()
		case "templateID":
			d.TemplateID, err = p.parseOID()
		case "df-df-saip":
			d.DFDFSAIP, err = p.parseFileDescriptorWrapper()
		case "ef-suci-calc-info-usim":
			d.EF_SUCI_CALC_INFO_USIM, err = p.parseElementaryFile()
		default:
			if strings.HasPrefix(fieldName.Value, "ef-") {
				ef, efErr := p.parseElementaryFile()
				if efErr != nil {
					return nil, efErr
				}
				d.AdditionalEFs[fieldName.Value] = ef
			} else {
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return d, nil
}

// ============================================================================
// AKA Parameter parser
// ============================================================================

func (p *Parser) parseAKAParameter() (*AKAParameter, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	aka := &AKAParameter{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "aka-header":
			aka.Header, err = p.parseElementHeader()
		case "algoConfiguration":
			// Skip "algoParameter :" if present
			if p.peek().Type == TokenIdent && p.peek().Value == "algoParameter" {
				p.advance()
				if p.peek().Type == TokenColon {
					p.advance()
				}
			}
			aka.AlgoConfig, err = p.parseAlgoConfiguration()
		case "sqnOptions":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				aka.SQNOptions = hexVal[0]
			}
		case "sqnDelta":
			aka.SQNDelta, err = p.parseHexValue()
		case "sqnAgeLimit":
			aka.SQNAgeLimit, err = p.parseHexValue()
		case "sqnInit":
			aka.SQNInit, err = p.parseHexList()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return aka, nil
}

func (p *Parser) parseAlgoConfiguration() (*AlgoConfiguration, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	ac := &AlgoConfiguration{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "algorithmID":
			ac.AlgorithmID, err = p.parseAlgorithmID()
		case "algorithmOptions":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				ac.AlgorithmOptions = hexVal[0]
			}
		case "key":
			ac.Key, err = p.parseHexValue()
		case "opc":
			ac.OPC, err = p.parseHexValue()
		case "rotationConstants":
			ac.RotationConstants, err = p.parseHexValue()
		case "xoringConstants":
			ac.XoringConstants, err = p.parseHexValue()
		case "numberOfKeccak":
			ac.NumberOfKeccak, err = p.parseIntValue()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return ac, nil
}

func (p *Parser) parseAlgorithmID() (AlgorithmID, error) {
	tok := p.peek()
	if tok.Type == TokenIdent {
		p.advance()
		switch tok.Value {
		case "milenage":
			return AlgoMilenage, nil
		case "tuak":
			return AlgoTUAK, nil
		case "usim-test-algorithm":
			return AlgoUSIMTestAlgorithm, nil
		default:
			return 0, fmt.Errorf("unknown algorithm: %s", tok.Value)
		}
	}
	val, err := p.parseIntValue()
	return AlgorithmID(val), err
}

func (p *Parser) parseHexList() ([][]byte, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var list [][]byte

	for p.peek().Type != TokenRBrace {
		hexVal, err := p.parseHexValue()
		if err != nil {
			return nil, err
		}
		list = append(list, hexVal)
		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return list, nil
}

// ============================================================================
// CDMA Parameter parser
// ============================================================================

func (p *Parser) parseCDMAParameter() (*CDMAParameter, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	cdma := &CDMAParameter{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "cdma-header":
			cdma.Header, err = p.parseElementHeader()
		case "authenticationKey":
			cdma.AuthenticationKey, err = p.parseHexValue()
		case "ssd":
			cdma.SSD, err = p.parseHexValue()
		case "hrpdAccessAuthenticationData":
			cdma.HRPDAccessAuthenticationData, err = p.parseHexValue()
		case "simpleIPAuthenticationData":
			cdma.SimpleIPAuthenticationData, err = p.parseHexValue()
		case "mobileIPAuthenticationData":
			cdma.MobileIPAuthenticationData, err = p.parseHexValue()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return cdma, nil
}

// ============================================================================
// Generic File Management parser
// ============================================================================

func (p *Parser) parseGenericFileManagement() (*GenericFileManagement, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	gfm := &GenericFileManagement{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "gfm-header":
			gfm.Header, err = p.parseElementHeader()
		case "fileManagementCMD":
			gfm.FileManagementCMDs, err = p.parseFileManagementCMDs()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return gfm, nil
}

func (p *Parser) parseFileManagementCMDs() ([]FileManagementCMD, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var cmds []FileManagementCMD

	// Parse each FileManagementCMD block { ... }
	for p.peek().Type != TokenRBrace {
		if p.peek().Type == TokenLBrace {
			cmd, err := p.parseFileManagementCMD()
			if err != nil {
				return nil, err
			}
			cmds = append(cmds, cmd)
		} else {
			// Skip unexpected tokens
			p.advance()
		}
		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return cmds, nil
}

func (p *Parser) parseFileManagementCMD() (FileManagementCMD, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var items FileManagementCMD

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		// Skip optional colon
		if p.peek().Type == TokenColon {
			p.advance()
		}

		item := FileManagementItem{}

		switch fieldName.Value {
		case "filePath":
			item.ItemType = 0
			item.FilePath, err = p.parseHexValue()
		case "createFCP":
			item.ItemType = 1
			item.CreateFCP, err = p.parseFileDescriptor()
		case "fillFileContent":
			item.ItemType = 2
			item.FillFileContent, err = p.parseHexValue()
		case "fillFileOffset":
			item.ItemType = 3
			item.FillFileOffset, err = p.parseIntValue()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		items = append(items, item)
		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return items, nil
}

// ============================================================================
// Security Domain parser
// ============================================================================

func (p *Parser) parseSecurityDomain() (*SecurityDomain, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	sd := &SecurityDomain{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "sd-Header":
			sd.Header, err = p.parseElementHeader()
		case "instance":
			sd.Instance, err = p.parseSDInstance()
		case "keyList":
			sd.KeyList, err = p.parseSDKeyList()
		case "sdPersoData":
			sd.SDPersoData, err = p.parseSDPersoData()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return sd, nil
}

func (p *Parser) parseSDInstance() (*SDInstance, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	inst := &SDInstance{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "applicationLoadPackageAID":
			inst.ApplicationLoadPackageAID, err = p.parseHexValue()
		case "classAID":
			inst.ClassAID, err = p.parseHexValue()
		case "instanceAID":
			inst.InstanceAID, err = p.parseHexValue()
		case "applicationPrivileges":
			inst.ApplicationPrivileges, err = p.parseHexValue()
		case "lifeCycleState":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				inst.LifeCycleState = hexVal[0]
			}
		case "applicationSpecificParametersC9":
			inst.ApplicationSpecificParamsC9, err = p.parseHexValue()
		case "applicationParameters":
			inst.ApplicationParameters, err = p.parseApplicationParameters()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return inst, nil
}

func (p *Parser) parseApplicationParameters() (*ApplicationParameters, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	ap := &ApplicationParameters{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "uiccToolkitApplicationSpecificParametersField":
			ap.UIICToolkitApplicationSpecificParametersField, err = p.parseHexValue()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return ap, nil
}

func (p *Parser) parseSDKeyList() ([]SDKey, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var keys []SDKey

	for p.peek().Type != TokenRBrace {
		key, err := p.parseSDKey()
		if err != nil {
			return nil, err
		}
		keys = append(keys, *key)
		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return keys, nil
}

func (p *Parser) parseSDKey() (*SDKey, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	key := &SDKey{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "keyUsageQualifier":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				key.KeyUsageQualifier = hexVal[0]
			}
		case "keyAccess":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				key.KeyAccess = hexVal[0]
			}
		case "keyIdentifier":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				key.KeyIdentifier = hexVal[0]
			}
		case "keyVersionNumber":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				key.KeyVersionNumber = hexVal[0]
			}
		case "keyCompontents":
			key.KeyCompontents, err = p.parseKeyComponents()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return key, nil
}

func (p *Parser) parseKeyComponents() ([]KeyComponent, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var comps []KeyComponent

	for p.peek().Type != TokenRBrace {
		comp, err := p.parseKeyComponent()
		if err != nil {
			return nil, err
		}
		comps = append(comps, *comp)
		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return comps, nil
}

func (p *Parser) parseKeyComponent() (*KeyComponent, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	kc := &KeyComponent{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "keyType":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				kc.KeyType = hexVal[0]
			}
		case "keyData":
			kc.KeyData, err = p.parseHexValue()
		case "macLength":
			kc.MACLength, err = p.parseIntValue()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return kc, nil
}

func (p *Parser) parseSDPersoData() ([]byte, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	hexVal, err := p.parseHexValue()
	if err != nil {
		return nil, err
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return hexVal, nil
}

// ============================================================================
// RFM parser
// ============================================================================

func (p *Parser) parseRFM() (*RFMConfig, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	rfm := &RFMConfig{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "rfm-header":
			rfm.Header, err = p.parseElementHeader()
		case "instanceAID":
			rfm.InstanceAID, err = p.parseHexValue()
		case "tarList":
			rfm.TARList, err = p.parseHexList()
		case "minimumSecurityLevel":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				rfm.MinimumSecurityLevel = hexVal[0]
			}
		case "uiccAccessDomain":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				rfm.UICCAccessDomain = hexVal[0]
			}
		case "uiccAdminAccessDomain":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				rfm.UICCAdminAccessDomain = hexVal[0]
			}
		case "adfRFMAccess":
			rfm.ADFRFMAccess, err = p.parseADFRFMAccess()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return rfm, nil
}

func (p *Parser) parseADFRFMAccess() (*ADFRFMAccess, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	acc := &ADFRFMAccess{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "adfAID":
			acc.ADFAID, err = p.parseHexValue()
		case "adfAccessDomain":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				acc.ADFAccessDomain = hexVal[0]
			}
		case "adfAdminAccessDomain":
			hexVal, hexErr := p.parseHexValue()
			if hexErr != nil {
				return nil, hexErr
			}
			if len(hexVal) > 0 {
				acc.ADFAdminAccessDomain = hexVal[0]
			}
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return acc, nil
}

// ============================================================================
// End parser
// ============================================================================

func (p *Parser) parseEnd() (*EndElement, error) {
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	end := &EndElement{}

	for p.peek().Type != TokenRBrace {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}

		switch fieldName.Value {
		case "end-header":
			end.Header, err = p.parseElementHeader()
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName.Value, err)
		}

		p.skipComma()
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return end, nil
}

// ============================================================================
// Value parsers
// ============================================================================

func (p *Parser) parseIntValue() (int, error) {
	tok := p.advance()
	if tok.Type != TokenNumber {
		return 0, fmt.Errorf("expected number, got %v at line %d", tok, tok.Line)
	}

	// Handle hex prefix
	val := tok.Value
	if strings.HasPrefix(val, "0x") || strings.HasPrefix(val, "0X") {
		n, err := strconv.ParseInt(val[2:], 16, 64)
		return int(n), err
	}

	return strconv.Atoi(val)
}

func (p *Parser) parseStringValue() (string, error) {
	tok := p.advance()
	if tok.Type != TokenString {
		return "", fmt.Errorf("expected string, got %v at line %d", tok, tok.Line)
	}
	return tok.Value, nil
}

func (p *Parser) parseHexValue() ([]byte, error) {
	tok := p.advance()
	if tok.Type != TokenHex {
		return nil, fmt.Errorf("expected hex literal, got %v at line %d", tok, tok.Line)
	}
	return hex.DecodeString(tok.Value)
}

func (p *Parser) skipComma() {
	if p.peek().Type == TokenComma {
		p.advance()
	}
}

func (p *Parser) skipValue() error {
	tok := p.peek()

	switch tok.Type {
	case TokenLBrace:
		return p.skipBlock()
	case TokenNumber, TokenString, TokenHex, TokenNull, TokenIdent:
		p.advance()
		return nil
	default:
		return fmt.Errorf("unexpected token %v at line %d", tok, tok.Line)
	}
}

func (p *Parser) skipBlock() error {
	if _, err := p.expect(TokenLBrace); err != nil {
		return err
	}

	depth := 1
	for depth > 0 {
		tok := p.advance()
		if tok.Type == TokenEOF {
			return fmt.Errorf("unexpected EOF in block")
		}
		if tok.Type == TokenLBrace {
			depth++
		} else if tok.Type == TokenRBrace {
			depth--
		}
	}

	return nil
}

