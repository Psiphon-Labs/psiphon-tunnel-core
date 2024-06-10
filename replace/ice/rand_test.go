// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"sync"
	"testing"
)

func TestRandomGeneratorCollision(t *testing.T) {
	candidateIDGen := newCandidateIDGenerator()

	testCases := map[string]struct {
		gen func(t *testing.T) string
	}{
		"CandidateID": {
			gen: func(t *testing.T) string {
				return candidateIDGen.Generate()
			},
		},
		"PWD": {
			gen: func(t *testing.T) string {
				s, err := generatePwd()
				if err != nil {
					t.Fatal(err)
				}
				return s
			},
		},
		"Ufrag": {
			gen: func(t *testing.T) string {
				s, err := generateUFrag()
				if err != nil {
					t.Fatal(err)
				}
				return s
			},
		},
	}

	const N = 100
	const iteration = 100

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			for iter := 0; iter < iteration; iter++ {
				var wg sync.WaitGroup
				var mu sync.Mutex

				rands := make([]string, 0, N)

				for i := 0; i < N; i++ {
					wg.Add(1)
					go func() {
						r := testCase.gen(t)
						mu.Lock()
						rands = append(rands, r)
						mu.Unlock()
						wg.Done()
					}()
				}
				wg.Wait()

				if len(rands) != N {
					t.Fatal("Failed to generate randoms")
				}

				for i := 0; i < N; i++ {
					for j := i + 1; j < N; j++ {
						if rands[i] == rands[j] {
							t.Fatalf("generateRandString caused collision: %s == %s", rands[i], rands[j])
						}
					}
				}
			}
		})
	}
}
