package mar

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Scanner is a marionette DSL tokenizer.
type Scanner struct {
	i    int
	data []byte
	pos  Pos
}

// NewScanner returns a new instance of Scanner.
func NewScanner(data []byte) *Scanner {
	data = bytes.Replace(data, []byte{0}, []byte("\uFFFD"), -1)
	data = bytes.Replace(data, []byte{'\f'}, []byte{'\n'}, -1)
	data = bytes.Replace(data, []byte{'\r', '\n'}, []byte{'\n'}, -1)
	return &Scanner{data: data}
}

// Scan returns the next token from the reader.
func (s *Scanner) Scan() (tok Token, lit string, pos Pos) {
	for {
		// Special handling for whitespace, numbers, strings, & names.
		ch := s.peek()
		switch {
		case isWhitespace(ch):
			return s.scanWhitespace()
		case isDigit(ch) || ch == '-':
			return s.scanNumber()
		case ch == '"' || ch == '\'':
			return s.scanString()
		case isNameStart(ch):
			return s.scanIdent()
		}

		// Check against individual code points next.
		pos = s.pos
		switch ch := s.read(); ch {
		case eof:
			return EOF, "", pos
		case ',':
			return COMMA, string(ch), pos
		case ':':
			return COLON, string(ch), pos
		case '(':
			return LPAREN, string(ch), pos
		case ')':
			return RPAREN, string(ch), pos
		case '.':
			return DOT, string(ch), pos
		case '#':
			return HASH, string(ch), pos
		default:
			return ILLEGAL, string(ch), pos
		}
	}
}

// ScanIgnoreWhitespace returns the next non-whitespace, non-comment token.
func (s *Scanner) ScanIgnoreWhitespace() (tok Token, lit string, pos Pos) {
	for {
		if tok, lit, pos = s.Scan(); tok == HASH {
			s.scanUntilNewline()
		} else if tok != WS {
			return tok, lit, pos
		}
	}
}

// Peek returns the next token without moving the scanner forward.
func (s *Scanner) Peek() (tok Token, lit string, pos Pos) {
	i, prev := s.i, s.pos
	tok, lit, pos = s.Scan()
	s.i, s.pos = i, prev
	return tok, lit, pos
}

// PeekIgnoreWhitespace returns the next non-whitespace, non-comment token without moving the scanner forward.
func (s *Scanner) PeekIgnoreWhitespace() (tok Token, lit string, pos Pos) {
	i, prev := s.i, s.pos
	for {
		if tok, lit, pos = s.Scan(); tok == HASH {
			s.scanUntilNewline()
		} else if tok != WS {
			s.i, s.pos = i, prev
			return tok, lit, pos
		}
	}
}

// scanWhitespace consumes the current code point and all subsequent whitespace.
func (s *Scanner) scanWhitespace() (tok Token, lit string, pos Pos) {
	pos = s.pos

	var buf bytes.Buffer
	for ch := s.peek(); isWhitespace(ch); ch = s.peek() {
		buf.WriteRune(s.read())
	}
	return WS, buf.String(), pos
}

// scanUntilNewline consumes all code points up to and including the next newline or EOF.
func (s *Scanner) scanUntilNewline() {
	for ch := s.read(); ch != '\n' && ch != eof; ch = s.read() {
	}
}

// scanString consumes a quoted string.
func (s *Scanner) scanString() (tok Token, lit string, pos Pos) {
	pos = s.pos
	ending := s.read()

	var buf bytes.Buffer
	for {
		if ch := s.peek(); ch == eof {
			return ILLEGAL, "", pos
		}

		switch ch := s.read(); ch {
		case ending:
			return STRING, buf.String(), pos
		case '\\':
			switch next := s.peek(); next {
			case '\\':
				buf.WriteRune(s.read())
			case '\'':
				buf.WriteRune(s.read())
			case '"':
				buf.WriteRune(s.read())
			case 'a':
				s.read()
				buf.WriteRune('\a')
			case 'b':
				s.read()
				buf.WriteRune('\b')
			case 'f':
				s.read()
				buf.WriteRune('\f')
			case 'n':
				s.read()
				buf.WriteRune('\n')
			case 'r':
				s.read()
				buf.WriteRune('\r')
			case 't':
				s.read()
				buf.WriteRune('\t')
			case 'v':
				s.read()
				buf.WriteRune('\v')
			case 'o':
				s.read()
				buf.WriteRune(rune(s.readOctal()))
			case 'x':
				s.read()
				buf.WriteRune(rune(s.readHex()))
			default:
				buf.WriteRune('\\')
			}
		default:
			buf.WriteRune(ch)
		}
	}
}

// scanNumber consumes a number.
func (s *Scanner) scanNumber() (tok Token, lit string, pos Pos) {
	pos = s.pos

	// If initial code point is + or - then store it.
	var buf bytes.Buffer
	switch ch := s.peek(); ch {
	case '+', '-':
		buf.WriteRune(s.read())
	}

	// Read as many digits as possible.
	s.scanDigits(&buf)

	// If next code points are a full stop and digit then consume them.
	if next := s.peek(); next == '.' {
		buf.WriteRune(s.read())
		s.scanDigits(&buf)
		return FLOAT, buf.String(), pos
	}
	return INTEGER, buf.String(), pos
}

// scanDigits consume a contiguous series of digits.
func (s *Scanner) scanDigits(buf *bytes.Buffer) {
	for ch := s.peek(); isDigit(ch); ch = s.peek() {
		buf.WriteRune(s.read())
	}
}

// readOctal reads and parses a stream of octal digits.
func (s *Scanner) readOctal() int {
	var buf bytes.Buffer
	for ch := s.peek(); isOctal(ch); ch = s.peek() {
		buf.WriteRune(s.read())
	}
	i, _ := strconv.ParseInt(buf.String(), 8, 64)
	return int(i)
}

// readHex reads and parses a stream of hex digits.
func (s *Scanner) readHex() int {
	var buf bytes.Buffer
	for ch := s.peek(); isHex(ch); ch = s.peek() {
		buf.WriteRune(s.read())
	}
	i, _ := strconv.ParseInt(buf.String(), 16, 64)
	return int(i)
}

// scanIdent consumes an identifier token.
func (s *Scanner) scanIdent() (tok Token, lit string, pos Pos) {
	pos = s.pos

	var buf bytes.Buffer
	for ch := s.peek(); isName(ch); ch = s.peek() {
		buf.WriteRune(s.read())
	}

	lit = buf.String()
	switch strings.ToLower(lit) {
	case "action":
		return ACTION, lit, pos
	case "client":
		return CLIENT, lit, pos
	case "if":
		return IF, lit, pos
	case "end":
		return END, lit, pos
	case "null":
		return NULL, lit, pos
	case "regex_match_incoming":
		return REGEX_MATCH_INCOMING, lit, pos
	case "server":
		return SERVER, lit, pos
	case "start":
		return START, lit, pos
	default:
		return IDENT, buf.String(), pos
	}
}

func (s *Scanner) read() rune {
	if s.i >= len(s.data) {
		return eof
	}
	ch, sz := utf8.DecodeRune(s.data[s.i:])
	s.i += sz

	// Track scanner position.
	if ch == '\n' {
		s.pos.Line++
		s.pos.Char = 0
	} else {
		s.pos.Char++
	}

	return ch
}

func (s *Scanner) peek() rune {
	if s.i >= len(s.data) {
		return eof
	}
	ch, _ := utf8.DecodeRune(s.data[s.i:])
	return ch
}

// isWhitespace returns true if the rune is a space, tab, or newline.
func isWhitespace(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\n'
}

// isLetter returns true if the rune is a letter.
func isLetter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// isDigit returns true if the rune is a decimal digit.
func isDigit(ch rune) bool {
	return (ch >= '0' && ch <= '9')
}

// isOctal returns true if the rune is an octal digit.
func isOctal(ch rune) bool {
	return (ch >= '0' && ch <= '7')
}

// isHex returns true if the rune is a hex digit.
func isHex(ch rune) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// isNameStart returns true if the rune can start a name.
func isNameStart(ch rune) bool {
	return isLetter(ch) || ch == '_'
}

// isName returns true if the character is a name code point.
func isName(ch rune) bool {
	return isNameStart(ch) || isDigit(ch) || ch == '-'
}

// eof represents an EOF file byte.
var eof rune = -1
