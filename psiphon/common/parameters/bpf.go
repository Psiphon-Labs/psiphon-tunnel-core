/*
 * Copyright (c) 2020, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package parameters

import (
	"encoding/json"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"golang.org/x/net/bpf"
)

// BPFProgramSpec specifies a BPF program. The Name field is informational and
// may be used for logging. The Instructions field is a list of values which
// map to golang.org/x/net/bpf.Instruction and which can be marshaled.
type BPFProgramSpec struct {
	Name         string
	Instructions []BPFInstructionSpec
}

// Validate validates a BPF program spec.
func (s *BPFProgramSpec) Validate() error {
	if s.Name == "" {
		return errors.TraceNew("missing name")
	}
	if len(s.Instructions) < 1 {
		return errors.TraceNew("missing instructions")
	}
	_, err := s.Assemble()
	return errors.Trace(err)
}

// Assemble converts the Instructions to equivilent
// golang.org/x/net/bpf.Instruction values and assembles these into raw
// instructions suitable for attaching to a socket.
func (s *BPFProgramSpec) Assemble() ([]bpf.RawInstruction, error) {

	if len(s.Instructions) == 0 {
		return nil, errors.TraceNew("empty program")
	}

	program := make([]bpf.Instruction, len(s.Instructions))
	for i, instructionSpec := range s.Instructions {
		instruction, err := instructionSpec.GetInstruction()
		if err != nil {
			return nil, errors.Trace(err)
		}
		program[i] = instruction
	}

	raw, err := bpf.Assemble(program)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return raw, nil
}

// BPFInstructionSpec represents a golang.org/x/net/bpf.Instruction and can be
// marshaled.
type BPFInstructionSpec struct {
	Op   string
	Args json.RawMessage
}

// GetInstruction coverts a BPFInstructionSpec to the equivilent
// golang.org/x/net/bpf.Instruction.
func (s *BPFInstructionSpec) GetInstruction() (bpf.Instruction, error) {
	switch s.Op {
	case "ALUOpConstant":
		var instruction bpf.ALUOpConstant
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "ALUOpX":
		var instruction bpf.ALUOpX
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "Jump":
		var instruction bpf.Jump
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "JumpIf":
		var instruction bpf.JumpIf
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "JumpIfX":
		var instruction bpf.JumpIfX
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "LoadAbsolute":
		var instruction bpf.LoadAbsolute
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "LoadConstant":
		var instruction bpf.LoadConstant
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "LoadExtension":
		var instruction bpf.LoadExtension
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "LoadIndirect":
		var instruction bpf.LoadIndirect
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "LoadMemShift":
		var instruction bpf.LoadMemShift
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "LoadScratch":
		var instruction bpf.LoadScratch
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "NegateA":
		var instruction bpf.NegateA
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "RetA":
		var instruction bpf.RetA
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "RetConstant":
		var instruction bpf.RetConstant
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "StoreScratch":
		var instruction bpf.StoreScratch
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "TAX":
		var instruction bpf.TAX
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	case "TXA":
		var instruction bpf.TXA
		err := json.Unmarshal(s.Args, &instruction)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return instruction, nil
	}

	return nil, errors.Tracef("unknown bpf instruction: %s", s.Op)
}
