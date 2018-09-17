package mar

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strconv"
)

// Parse parses data in to a MAR document.
func Parse(party string, data []byte) (*Document, error) {
	return NewParser(party).Parse(data)
}

// MustParse parses data in to a MAR document. Panic on error.
func MustParse(party string, data []byte) *Document {
	doc, err := Parse(party, data)
	if err != nil {
		panic(err)
	}
	return doc
}

// Parser represents a Marionette DSL parser.
//
// The parser will automatically convert certain actions to their complement
// depending on the party that is parsing the document. No transformation is
// performed if the party is blank.
type Parser struct {
	party string
}

// NewParser returns a new instance of Parser.
func NewParser(party string) *Parser {
	return &Parser{party: party}
}

// Parse parses s into an AST.
func (p *Parser) Parse(data []byte) (*Document, error) {
	scanner := NewScanner(data)

	var doc Document
	doc.UUID = GenerateUUID(data)

	// Read 'connection' keyword.
	tok, lit, pos := scanner.ScanIgnoreWhitespace()
	if err := expect(IDENT, "connection", tok, lit, pos); err != nil {
		return nil, err
	}
	doc.Connection = pos

	// Read opening parenthesis.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if err := expect(LPAREN, "", tok, lit, pos); err != nil {
		return nil, err
	}
	doc.Lparen = pos

	// Read transport type.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if tok != IDENT {
		return nil, newSyntaxError("expected transport type ('tcp' or 'udp')", tok, lit, pos)
	}
	doc.Transport = lit
	doc.TransportPos = pos

	// Read comma.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if err := expect(COMMA, "", tok, lit, pos); err != nil {
		return nil, err
	}
	doc.Comma = pos

	// Read port.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if tok != IDENT && tok != INTEGER {
		return nil, newSyntaxError("expected named or numeric port", tok, lit, pos)
	}
	doc.Port = lit
	doc.PortPos = pos

	// Read closing parenthesis.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if err := expect(RPAREN, "", tok, lit, pos); err != nil {
		return nil, err
	}
	doc.Rparen = pos

	// Read colon.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if err := expect(COLON, "", tok, lit, pos); err != nil {
		return nil, err
	}
	doc.Colon = pos

	transitions, err := p.parseTransitions(scanner)
	if err != nil {
		return nil, err
	}
	doc.Transitions = transitions

	actionBlocks, err := p.parseActionBlocks(scanner)
	if err != nil {
		return nil, err
	}
	doc.ActionBlocks = actionBlocks

	if err := doc.Normalize(); err != nil {
		return nil, err
	}

	return &doc, nil
}

func (p *Parser) parseTransitions(scanner *Scanner) ([]*Transition, error) {
	var transitions []*Transition
	for {
		// Exit once we hit an 'action' keyword or end-of-file.
		if tok, _, _ := scanner.PeekIgnoreWhitespace(); tok == ACTION || tok == EOF {
			break
		}

		transition, err := p.parseTransition(scanner)
		if err != nil {
			return nil, err
		}
		transitions = append(transitions, transition)
	}
	return transitions, nil
}

func (p *Parser) parseTransition(scanner *Scanner) (*Transition, error) {
	var transition Transition

	// Read transition source.
	tok, lit, pos := scanner.ScanIgnoreWhitespace()
	if tok != START && tok != IDENT {
		return nil, newSyntaxError("expected source or 'start'", tok, lit, pos)
	}
	transition.Source = lit
	transition.SourcePos = pos

	// Read transition destination.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if tok != IDENT && tok != END {
		return nil, newSyntaxError("expected destination or 'end'", tok, lit, pos)
	}
	transition.Destination = lit
	transition.DestinationPos = pos

	// Read action block name.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if tok != IDENT && tok != NULL {
		return nil, newSyntaxError("expected action block name or NULL", tok, lit, pos)
	}
	transition.ActionBlock = lit
	transition.ActionBlockPos = pos

	// Read probability.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if tok != IDENT && tok != INTEGER && tok != FLOAT {
		return nil, newSyntaxError("expected probability or 'error'", tok, lit, pos)
	}
	transition.Probability, _ = strconv.ParseFloat(lit, 64)
	transition.ProbabilityPos = pos
	transition.IsErrorTransition = lit == "error"

	return &transition, nil
}

func (p *Parser) parseActionBlocks(scanner *Scanner) ([]*ActionBlock, error) {
	var blks []*ActionBlock
	for {
		if tok, _, _ := scanner.PeekIgnoreWhitespace(); tok == EOF {
			break
		}

		blk, err := p.parseActionBlock(scanner)
		if err != nil {
			return nil, err
		}
		blks = append(blks, blk)
	}
	return blks, nil
}

func (p *Parser) parseActionBlock(scanner *Scanner) (*ActionBlock, error) {
	var blk ActionBlock

	// Read action keyword.
	tok, lit, pos := scanner.ScanIgnoreWhitespace()
	if err := expect(ACTION, "", tok, lit, pos); err != nil {
		return nil, err
	}
	blk.Action = pos

	// Read block name.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if tok != START && tok != IDENT {
		return nil, newSyntaxError("expected block name", tok, lit, pos)
	}
	blk.Name = lit
	blk.NamePos = pos

	// Read colon.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if err := expect(COLON, "", tok, lit, pos); err != nil {
		return nil, err
	}
	blk.Colon = pos

	// Read action list.
	actions, err := p.parseActions(scanner)
	if err != nil {
		return nil, err
	}
	blk.Actions = actions

	return &blk, nil
}

func (p *Parser) parseActions(scanner *Scanner) ([]*Action, error) {
	var actions []*Action
	for {
		if tok, _, _ := scanner.PeekIgnoreWhitespace(); tok == ACTION || tok == EOF {
			break
		}

		action, err := p.parseAction(scanner)
		if err != nil {
			return nil, err
		}
		actions = append(actions, action)
	}
	return actions, nil
}

func (p *Parser) parseAction(scanner *Scanner) (*Action, error) {
	var action Action

	// Read client/server keyword.
	tok, lit, pos := scanner.ScanIgnoreWhitespace()
	if tok != CLIENT && tok != SERVER {
		return nil, newSyntaxError("expected party name ('client' or 'server')", tok, lit, pos)
	}
	action.Party = lit
	action.PartyPos = pos

	// Read module name.
	tok, lit, pos = scanner.ScanIgnoreWhitespace()
	if tok != IDENT {
		return nil, newSyntaxError("expected module name", tok, lit, pos)
	}
	action.Module = lit
	action.ModulePos = pos

	// Read dot.
	tok, lit, pos = scanner.Scan()
	if tok != DOT {
		return nil, newSyntaxError("expected dot", tok, lit, pos)
	}
	action.Dot = pos

	// Read method name.
	tok, lit, pos = scanner.Scan()
	if tok != IDENT {
		return nil, newSyntaxError("expected method name", tok, lit, pos)
	}
	action.Method = lit
	action.MethodPos = pos

	// Read parens & args.
	tok, lit, pos = scanner.Scan()
	if tok != LPAREN {
		return nil, newSyntaxError("expected '('", tok, lit, pos)
	}
	action.Lparen = pos

	args, err := p.parseArgs(scanner)
	if err != nil {
		return nil, err
	}
	action.Args = args

	tok, lit, pos = scanner.Scan()
	if tok != RPAREN {
		return nil, newSyntaxError("expected ')'", tok, lit, pos)
	}
	action.Rparen = pos

	// Parse incoming regex match.
	if tok, _, _ := scanner.PeekIgnoreWhitespace(); tok == IF {
		// Read "if" statement.
		_, _, action.If = scanner.ScanIgnoreWhitespace()

		// Read 'regex_match_incoming' keyword.
		tok, lit, pos = scanner.ScanIgnoreWhitespace()
		if tok != REGEX_MATCH_INCOMING {
			return nil, newSyntaxError("expected 'regex_match_incoming'", tok, lit, pos)
		}
		action.RegexMatchIncoming = pos

		// Read parens and regex string.
		tok, lit, pos = scanner.Scan()
		if tok != LPAREN {
			return nil, newSyntaxError("expected '('", tok, lit, pos)
		}
		action.RegexMatchIncomingLparen = pos

		tok, lit, pos = scanner.ScanIgnoreWhitespace()
		if tok != STRING {
			return nil, newSyntaxError("expected regex string", tok, lit, pos)
		}
		action.Regex = lit
		action.RegexPos = pos

		tok, lit, pos = scanner.ScanIgnoreWhitespace()
		if tok != RPAREN {
			return nil, newSyntaxError("expected ')'", tok, lit, pos)
		}
		action.RegexMatchIncomingRparen = pos
	}

	// Perform transformation depending on party.
	action.Transform(p.party)

	return &action, nil
}

func (p *Parser) parseArgs(scanner *Scanner) ([]*Arg, error) {
	if tok, _, _ := scanner.PeekIgnoreWhitespace(); tok == RPAREN {
		return nil, nil
	}

	var args []*Arg
	for {
		tok, lit, pos := scanner.ScanIgnoreWhitespace()
		arg := &Arg{Pos: pos, EndPos: Pos{Line: pos.Line, Char: pos.Char + len(lit)}}

		switch tok {
		case STRING:
			arg.Value = lit

		case INTEGER:
			i, err := strconv.Atoi(lit)
			if err != nil {
				return nil, err
			}
			arg.Value = i

		case FLOAT:
			f, err := strconv.ParseFloat(lit, 64)
			if err != nil {
				return nil, err
			}
			arg.Value = f

		default:
			return nil, newSyntaxError("expected string, integer, or float argument", tok, lit, pos)
		}

		args = append(args, arg)

		if tok, _, _ := scanner.PeekIgnoreWhitespace(); tok == COMMA {
			scanner.ScanIgnoreWhitespace()
		} else if tok == RPAREN {
			break
		} else {
			return nil, newSyntaxError("expected ',' or ')'", tok, lit, pos)
		}
	}
	return args, nil
}

func expect(expectedTok Token, expectedLit string, tok Token, lit string, pos Pos) error {
	switch expectedTok {
	case IDENT:
		if tok != IDENT || expectedLit != lit {
			return newSyntaxError(fmt.Sprintf("expected '%s'", expectedLit), tok, lit, pos)
		}
	default:
		if expectedTok != tok {
			return newSyntaxError(fmt.Sprintf("expected %s", expectedTok.String()), tok, lit, pos)
		}
	}
	return nil
}

type SyntaxError struct {
	Message string
	Pos     Pos
}

func (e *SyntaxError) Error() string { return e.Message }

func newSyntaxError(exp string, tok Token, lit string, pos Pos) *SyntaxError {
	return &SyntaxError{
		Message: fmt.Sprintf("%s at line %d, found %s", exp, pos.Line, tok.String()),
		Pos:     pos,
	}
}

func GenerateUUID(data []byte) int {
	sum := md5.Sum(data)
	return int(binary.BigEndian.Uint32(sum[:4]))
}
