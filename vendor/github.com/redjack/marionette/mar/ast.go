package mar

import (
	"math/rand"
)

// Node represents a node within the AST.
type Node interface {
	node()
}

func (*Document) node()    {}
func (*Transition) node()  {}
func (*ActionBlock) node() {}
func (*Action) node()      {}
func (*Arg) node()         {}
func (*Pos) node()         {}

type Document struct {
	UUID   int
	Format string

	Connection   Pos
	Lparen       Pos
	Transport    string
	TransportPos Pos
	Comma        Pos
	Port         string
	PortPos      Pos
	Rparen       Pos
	Colon        Pos
	Transitions  []*Transition
	ActionBlocks []*ActionBlock
}

// FirstSender returns the party that initiates the protocol.
func (doc *Document) FirstSender() string {
	if doc.Format == "ftp_pasv_transfer" {
		return "server"
	}
	return "client"
}

// ActionBlock returns an action block by name.
func (doc *Document) ActionBlock(name string) *ActionBlock {
	for _, blk := range doc.ActionBlocks {
		if blk.Name == name {
			return blk
		}
	}
	return nil
}

// HasTransition returns true if there is a transition between src and dst.
func (doc *Document) HasTransition(src, dst string) bool {
	for _, transition := range doc.Transitions {
		if transition.Source == src && transition.Destination == dst {
			return true
		}
	}
	return false
}

// Normalize ensures document conforms to expected state.
func (doc *Document) Normalize() error {
	// Add dead state transitions.
	if !doc.HasTransition("end", "dead") {
		doc.Transitions = append(doc.Transitions, &Transition{Source: "end", Destination: "dead", ActionBlock: "NULL", Probability: 1})
	}
	if !doc.HasTransition("dead", "dead") {
		doc.Transitions = append(doc.Transitions, &Transition{Source: "dead", Destination: "dead", ActionBlock: "NULL", Probability: 1})
	}
	return nil
}

type Transition struct {
	Source            string
	SourcePos         Pos
	Destination       string
	DestinationPos    Pos
	ActionBlock       string
	ActionBlockPos    Pos
	Probability       float64
	ProbabilityPos    Pos
	IsErrorTransition bool
}

func FilterTransitionsBySource(a []*Transition, name string) []*Transition {
	other := make([]*Transition, 0, len(a))
	for _, t := range a {
		if t.Source == name {
			other = append(other, t)
		}
	}
	return other
}

func FilterTransitionsByDestination(a []*Transition, name string) []*Transition {
	other := make([]*Transition, 0, len(a))
	for _, t := range a {
		if t.Destination == name {
			other = append(other, t)
		}
	}
	return other
}

func FilterProbableTransitions(a []*Transition) []*Transition {
	other := make([]*Transition, 0, len(a))
	for _, t := range a {
		if t.Probability > 0 {
			other = append(other, t)
		}
	}
	return other
}

func FilterErrorTransitions(a []*Transition) []*Transition {
	var other []*Transition
	for _, t := range a {
		if t.IsErrorTransition {
			other = append(other, t)
		}
	}
	return other
}

func FilterNonErrorTransitions(a []*Transition) []*Transition {
	other := make([]*Transition, 0, len(a))
	for _, t := range a {
		if !t.IsErrorTransition {
			other = append(other, t)
		}
	}
	return other
}

// TransitionsDestinations returns the destination state names from the transitions.
func TransitionsDestinations(a []*Transition) []string {
	other := make([]string, 0, len(a))
	for _, t := range a {
		other = append(other, t.Destination)
	}
	return other
}

// TransitionsErrorState returns the first error state in a list of transitions.
func TransitionsErrorState(a []*Transition) string {
	for _, t := range a {
		if t.IsErrorTransition {
			return t.Destination
		}
	}
	return ""
}

func ChooseTransitions(a []*Transition, rand *rand.Rand) []*Transition {
	// If PRNG not available then return all transitions with a non-zero probability.
	if rand == nil {
		return FilterProbableTransitions(a)
	}

	// If there is only one transition then return it.
	if len(a) == 1 {
		return a
	}

	// Otherwise randomly choose a transition based on probability.
	sum, coin := float64(0), rand.Float64()
	for _, t := range a {
		if t.Probability <= 0 {
			continue
		}
		sum += t.Probability
		if sum >= coin {
			return []*Transition{t}
		}
	}
	return []*Transition{a[len(a)-1]}
}

type ActionBlock struct {
	Action  Pos
	Name    string
	NamePos Pos
	Colon   Pos
	Actions []*Action
}

type Action struct {
	Party     string
	PartyPos  Pos
	Module    string
	ModulePos Pos
	Dot       Pos
	Method    string
	MethodPos Pos
	Lparen    Pos
	Args      []*Arg
	Rparen    Pos
	If        Pos

	RegexMatchIncoming       Pos
	RegexMatchIncomingLparen Pos
	Regex                    string
	RegexPos                 Pos
	RegexMatchIncomingRparen Pos
}

// Name returns the concatenation of the module & method.
func (a *Action) Name() string {
	return a.Module + "." + a.Method
}

func (a *Action) ArgValues() []interface{} {
	other := make([]interface{}, len(a.Args))
	for i, arg := range a.Args {
		other[i] = arg.Value
	}
	return other
}

// Transform converts the action to its complement depending on the party.
func (a *Action) Transform(party string) {
	switch party {
	case "client":
		a.transform("server", "client")
	case "server":
		a.transform("client", "server")
	}
}

func (a *Action) transform(from, to string) {
	if a.Party == from {
		switch a.Module {
		case "fte", "tg":
			if a.Method == "send" {
				a.Method = "recv"
			} else if a.Method == "send_async" {
				a.Method = "recv_async"
			}
			a.Party = to
		case "io":
			if a.Method == "gets" {
				a.Method = "puts"
			} else if a.Method == "puts" {
				a.Method = "gets"
			}
			a.Party = to
		}
	}
}

// FilterActionsByParty returns a slice of actions matching party.
func FilterActionsByParty(actions []*Action, party string) []*Action {
	other := make([]*Action, 0, len(actions))
	for _, action := range actions {
		if action.Party == party {
			other = append(other, action)
		}
	}
	return other
}

type Arg struct {
	Value  interface{}
	Pos    Pos
	EndPos Pos
}

// Pos specifies the line and character position of a token.
// The Char and Line are both zero-based indexes.
type Pos struct {
	Char int
	Line int
}

// Walk traverses an AST in depth-first order.
func Walk(v Visitor, node Node) {
	if v = v.Visit(node); v == nil {
		return
	}

	// Walk children.
	switch node := node.(type) {
	case *Document:
		for _, transition := range node.Transitions {
			Walk(v, transition)
		}
		for _, blk := range node.ActionBlocks {
			Walk(v, blk)
		}

	case *ActionBlock:
		for _, action := range node.Actions {
			Walk(v, action)
		}

	case *Action:
		for _, arg := range node.Args {
			Walk(v, arg)
		}
	}

	v.Visit(nil)
}

// Visitor represents an object for iterating over nodes using Walk().
type Visitor interface {
	Visit(node Node) (w Visitor)
}

// VisitorFunc implements a type to use a function as a Visitor.
type VisitorFunc func(node Node)

func (fn VisitorFunc) Visit(node Node) Visitor {
	fn(node)
	return fn
}
