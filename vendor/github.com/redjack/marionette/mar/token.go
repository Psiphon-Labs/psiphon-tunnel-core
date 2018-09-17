package mar

import "strconv"

// Token represents a lexical token type.
type Token int

const (
	ILLEGAL Token = iota
	EOF
	COMMENT
	WS

	IDENT   // connection
	NULL    // NULL
	STRING  // "foo"
	INTEGER // 12345
	FLOAT   // 123.45

	LPAREN // (
	RPAREN // )
	DOT    // .
	COMMA  // ,
	COLON  // :
	HASH   // #

	// keywords
	ACTION
	CLIENT
	IF
	END
	REGEX_MATCH_INCOMING
	SERVER
	START
)

var tokens = [...]string{
	ILLEGAL: "ILLEGAL",
	EOF:     "EOF",
	COMMENT: "COMMENT",
	WS:      "WS",

	IDENT:   "IDENT",
	NULL:    "NULL",
	STRING:  "STRING",
	INTEGER: "INTEGER",
	FLOAT:   "FLOAT",

	LPAREN: "(",
	RPAREN: ")",
	DOT:    ".",
	COMMA:  ",",
	COLON:  ":",
	HASH:   "#",

	ACTION:               "action",
	CLIENT:               "client",
	IF:                   "if",
	END:                  "end",
	REGEX_MATCH_INCOMING: "regex_match_incoming",
	SERVER:               "server",
	START:                "start",
}

func (tok Token) String() string {
	s := ""
	if 0 <= tok && tok < Token(len(tokens)) {
		s = tokens[tok]
	}
	if s == "" {
		s = "token(" + strconv.Itoa(int(tok)) + ")"
	}
	return s
}
