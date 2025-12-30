package esim

import (
	"fmt"
	"strings"
	"unicode"
)

// TokenType represents the type of token
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenIdent         // identifier: value1, ProfileElement, header, major-version
	TokenNumber        // integer: 2, 143, 0x10
	TokenString        // quoted string: "GSMA Generic eUICC Test Profile"
	TokenHex           // hex literal: '89000123456789012341'H
	TokenNull          // NULL keyword
	TokenLBrace        // {
	TokenRBrace        // }
	TokenLParen        // (
	TokenRParen        // )
	TokenColon         // :
	TokenComma         // ,
	TokenAssign        // ::=
)

// Token represents a lexical token
type Token struct {
	Type    TokenType
	Value   string
	Line    int
	Column  int
}

func (t Token) String() string {
	switch t.Type {
	case TokenEOF:
		return "EOF"
	case TokenIdent:
		return fmt.Sprintf("IDENT(%s)", t.Value)
	case TokenNumber:
		return fmt.Sprintf("NUMBER(%s)", t.Value)
	case TokenString:
		return fmt.Sprintf("STRING(%s)", t.Value)
	case TokenHex:
		return fmt.Sprintf("HEX(%s)", t.Value)
	case TokenNull:
		return "NULL"
	case TokenLBrace:
		return "{"
	case TokenRBrace:
		return "}"
	case TokenLParen:
		return "("
	case TokenRParen:
		return ")"
	case TokenColon:
		return ":"
	case TokenComma:
		return ","
	case TokenAssign:
		return "::="
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t.Type)
	}
}

// Tokenizer tokenizes ASN.1 Value Notation text
type Tokenizer struct {
	input   string
	pos     int
	line    int
	column  int
	tokens  []Token
	current int
}

// NewTokenizer creates a new tokenizer
func NewTokenizer(input string) *Tokenizer {
	return &Tokenizer{
		input:  input,
		pos:    0,
		line:   1,
		column: 1,
	}
}

// Tokenize tokenizes the entire input
func (t *Tokenizer) Tokenize() ([]Token, error) {
	t.tokens = make([]Token, 0)

	for {
		tok, err := t.nextToken()
		if err != nil {
			return nil, err
		}
		t.tokens = append(t.tokens, tok)
		if tok.Type == TokenEOF {
			break
		}
	}

	return t.tokens, nil
}

// peek returns current character without advancing
func (t *Tokenizer) peek() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	return t.input[t.pos]
}

// peekAt returns character at offset from current position
func (t *Tokenizer) peekAt(offset int) byte {
	pos := t.pos + offset
	if pos >= len(t.input) {
		return 0
	}
	return t.input[pos]
}

// advance moves to next character
func (t *Tokenizer) advance() byte {
	if t.pos >= len(t.input) {
		return 0
	}
	ch := t.input[t.pos]
	t.pos++
	if ch == '\n' {
		t.line++
		t.column = 1
	} else {
		t.column++
	}
	return ch
}

// skipWhitespace skips whitespace and comments
func (t *Tokenizer) skipWhitespace() {
	for t.pos < len(t.input) {
		ch := t.peek()
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			t.advance()
		} else if ch == '-' && t.peekAt(1) == '-' {
			// ASN.1 comment: -- until end of line
			t.advance() // skip first -
			t.advance() // skip second -
			for t.pos < len(t.input) && t.peek() != '\n' {
				t.advance()
			}
		} else {
			break
		}
	}
}

// nextToken returns the next token
func (t *Tokenizer) nextToken() (Token, error) {
	t.skipWhitespace()

	if t.pos >= len(t.input) {
		return Token{Type: TokenEOF, Line: t.line, Column: t.column}, nil
	}

	line := t.line
	column := t.column
	ch := t.peek()

	// Single character tokens
	switch ch {
	case '{':
		t.advance()
		return Token{Type: TokenLBrace, Value: "{", Line: line, Column: column}, nil
	case '}':
		t.advance()
		return Token{Type: TokenRBrace, Value: "}", Line: line, Column: column}, nil
	case '(':
		t.advance()
		return Token{Type: TokenLParen, Value: "(", Line: line, Column: column}, nil
	case ')':
		t.advance()
		return Token{Type: TokenRParen, Value: ")", Line: line, Column: column}, nil
	case ',':
		t.advance()
		return Token{Type: TokenComma, Value: ",", Line: line, Column: column}, nil
	case ':':
		t.advance()
		// Check for ::=
		if t.peek() == ':' && t.peekAt(1) == '=' {
			t.advance() // skip second :
			t.advance() // skip =
			return Token{Type: TokenAssign, Value: "::=", Line: line, Column: column}, nil
		}
		return Token{Type: TokenColon, Value: ":", Line: line, Column: column}, nil
	}

	// Hex literal: '...'H
	if ch == '\'' {
		return t.readHexLiteral(line, column)
	}

	// String literal: "..."
	if ch == '"' {
		return t.readString(line, column)
	}

	// Number (including negative)
	if isDigit(ch) || (ch == '-' && isDigit(t.peekAt(1))) {
		return t.readNumber(line, column)
	}

	// Identifier or keyword
	if isIdentStart(ch) {
		return t.readIdentifier(line, column)
	}

	return Token{}, fmt.Errorf("unexpected character '%c' at line %d, column %d", ch, line, column)
}

// readHexLiteral reads a hex literal: '...'H
func (t *Tokenizer) readHexLiteral(line, column int) (Token, error) {
	t.advance() // skip opening '
	
	var sb strings.Builder
	for t.pos < len(t.input) && t.peek() != '\'' {
		ch := t.advance()
		// Allow whitespace and newlines inside hex literals
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			continue
		}
		sb.WriteByte(ch)
	}

	if t.pos >= len(t.input) {
		return Token{}, fmt.Errorf("unterminated hex literal at line %d, column %d", line, column)
	}

	t.advance() // skip closing '

	// Check for 'H' suffix
	if t.peek() == 'H' {
		t.advance()
	}

	return Token{Type: TokenHex, Value: sb.String(), Line: line, Column: column}, nil
}

// readString reads a quoted string
func (t *Tokenizer) readString(line, column int) (Token, error) {
	t.advance() // skip opening "
	
	var sb strings.Builder
	for t.pos < len(t.input) && t.peek() != '"' {
		ch := t.advance()
		if ch == '\\' && t.pos < len(t.input) {
			// Handle escape sequences
			next := t.advance()
			switch next {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case 'r':
				sb.WriteByte('\r')
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			default:
				sb.WriteByte(ch)
				sb.WriteByte(next)
			}
		} else {
			sb.WriteByte(ch)
		}
	}

	if t.pos >= len(t.input) {
		return Token{}, fmt.Errorf("unterminated string at line %d, column %d", line, column)
	}

	t.advance() // skip closing "

	return Token{Type: TokenString, Value: sb.String(), Line: line, Column: column}, nil
}

// readNumber reads a number (decimal or hex)
func (t *Tokenizer) readNumber(line, column int) (Token, error) {
	var sb strings.Builder

	// Handle negative sign
	if t.peek() == '-' {
		sb.WriteByte(t.advance())
	}

	// Check for hex prefix 0x
	if t.peek() == '0' && (t.peekAt(1) == 'x' || t.peekAt(1) == 'X') {
		sb.WriteByte(t.advance()) // 0
		sb.WriteByte(t.advance()) // x
		for isHexDigit(t.peek()) {
			sb.WriteByte(t.advance())
		}
	} else {
		// Decimal number
		for isDigit(t.peek()) {
			sb.WriteByte(t.advance())
		}
	}

	return Token{Type: TokenNumber, Value: sb.String(), Line: line, Column: column}, nil
}

// readIdentifier reads an identifier or keyword
func (t *Tokenizer) readIdentifier(line, column int) (Token, error) {
	var sb strings.Builder

	for isIdentChar(t.peek()) {
		sb.WriteByte(t.advance())
	}

	value := sb.String()

	// Check for NULL keyword
	if value == "NULL" {
		return Token{Type: TokenNull, Value: value, Line: line, Column: column}, nil
	}

	return Token{Type: TokenIdent, Value: value, Line: line, Column: column}, nil
}

// Helper functions

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isHexDigit(ch byte) bool {
	return isDigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

func isIdentStart(ch byte) bool {
	return unicode.IsLetter(rune(ch)) || ch == '_'
}

func isIdentChar(ch byte) bool {
	return unicode.IsLetter(rune(ch)) || unicode.IsDigit(rune(ch)) || ch == '_' || ch == '-'
}

