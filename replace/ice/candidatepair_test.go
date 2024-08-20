// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func hostCandidate() *CandidateHost {
	return &CandidateHost{
		candidateBase: candidateBase{
			candidateType: CandidateTypeHost,
			component:     ComponentRTP,
		},
	}
}

func prflxCandidate() *CandidatePeerReflexive {
	return &CandidatePeerReflexive{
		candidateBase: candidateBase{
			candidateType: CandidateTypePeerReflexive,
			component:     ComponentRTP,
		},
	}
}

func srflxCandidate() *CandidateServerReflexive {
	return &CandidateServerReflexive{
		candidateBase: candidateBase{
			candidateType: CandidateTypeServerReflexive,
			component:     ComponentRTP,
		},
	}
}

func relayCandidate() *CandidateRelay {
	return &CandidateRelay{
		candidateBase: candidateBase{
			candidateType: CandidateTypeRelay,
			component:     ComponentRTP,
		},
	}
}

func TestCandidatePairPriority(t *testing.T) {
	for _, test := range []struct {
		Pair         *CandidatePair
		WantPriority uint64
	}{
		{
			Pair: newCandidatePair(
				hostCandidate(),
				hostCandidate(),
				false,
			),
			WantPriority: 9151314440652587007,
		},
		{
			Pair: newCandidatePair(
				hostCandidate(),
				hostCandidate(),
				true,
			),
			WantPriority: 9151314440652587007,
		},
		{
			Pair: newCandidatePair(
				hostCandidate(),
				prflxCandidate(),
				true,
			),
			WantPriority: 7998392936314175488,
		},
		{
			Pair: newCandidatePair(
				hostCandidate(),
				prflxCandidate(),
				false,
			),
			WantPriority: 7998392936314175487,
		},
		{
			Pair: newCandidatePair(
				hostCandidate(),
				srflxCandidate(),
				true,
			),
			WantPriority: 7277816996102668288,
		},
		{
			Pair: newCandidatePair(
				hostCandidate(),
				srflxCandidate(),
				false,
			),
			WantPriority: 7277816996102668287,
		},
		{
			Pair: newCandidatePair(
				hostCandidate(),
				relayCandidate(),
				true,
			),
			WantPriority: 72057593987596288,
		},
		{
			Pair: newCandidatePair(
				hostCandidate(),
				relayCandidate(),
				false,
			),
			WantPriority: 72057593987596287,
		},
	} {
		if got, want := test.Pair.priority(), test.WantPriority; got != want {
			t.Fatalf("CandidatePair(%v).Priority() = %d, want %d", test.Pair, got, want)
		}
	}
}

func TestCandidatePairEquality(t *testing.T) {
	pairA := newCandidatePair(hostCandidate(), srflxCandidate(), true)
	pairB := newCandidatePair(hostCandidate(), srflxCandidate(), false)

	if !pairA.equal(pairB) {
		t.Fatalf("Expected %v to equal %v", pairA, pairB)
	}
}

func TestNilCandidatePairString(t *testing.T) {
	var nilCandidatePair *CandidatePair
	assert.Equal(t, nilCandidatePair.String(), "")
}
