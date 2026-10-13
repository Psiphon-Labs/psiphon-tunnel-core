//go:build !PSIPHON_USE_BADGER_DB && !PSIPHON_USE_FILES_DB

/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package psiphon

import (
	"fmt"
	"testing"

	"github.com/Psiphon-Labs/bolt"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

// benchmarkReplayStoreStats reads the committed transaction ID and write stats.
// The benchmarks run serially with no other datastore users. The snapshot view
// runs outside timing; unlike Stats.TxN, the ID measures writable commits.
func benchmarkReplayStoreStats(b *testing.B) (int, bolt.Stats) {
	b.Helper()
	datastoreMutex.RLock()
	defer datastoreMutex.RUnlock()
	db := activeDatastoreDB.boltDB
	var id int
	if err := db.View(func(tx *bolt.Tx) error {
		id = tx.ID()
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	return id, db.Stats()
}

// reportReplayStoreStats reports writable commits and Bolt write stats per
// operation. bolt-write-ns/op is TxStats.WriteTime: the commit write phase
// only, not selection, unmarshalling or mutex wait. ns/op is the full call.
func reportReplayStoreStats(b *testing.B, beforeID int, before bolt.Stats) {
	b.Helper()
	afterID, after := benchmarkReplayStoreStats(b)
	delta := after.Sub(&before)
	b.ReportMetric(float64(afterID-beforeID)/float64(b.N), "commits/op")
	b.ReportMetric(float64(delta.TxStats.Write)/float64(b.N), "writes/op")
	b.ReportMetric(float64(delta.TxStats.WriteTime.Nanoseconds())/float64(b.N), "bolt-write-ns/op")
}

// BenchmarkInproxyReplayTransaction measures the transaction floor, including
// the production datastore wrappers and normal durability settings.
func BenchmarkInproxyReplayTransaction(b *testing.B) {
	for _, writable := range []bool{false, true} {
		name := "View"
		if writable {
			name = "Update"
		}
		b.Run(name, func(b *testing.B) {
			newGateTestManager(b)
			operation := datastoreView
			if writable {
				operation = datastoreUpdate
			}
			beforeID, before := benchmarkReplayStoreStats(b)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := operation(func(*datastoreTx) error { return nil }); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			reportReplayStoreStats(b, beforeID, before)
		})
	}
}

// BenchmarkInproxyBrokerReplayLookup measures a selection after initialization.
// It uses fresh progress and fixed broker/provider order. Configuration,
// fixture seeding, instance construction and network operations are excluded;
// the lookup's own datastore transactions, including validation and
// invalid-record deletion, remain timed. Factory-generated parameters give
// replay decoding realistic record sizes. All brokers in a case support the
// same providers; sparse eligibility only reduces loads.
func BenchmarkInproxyBrokerReplayLookup(b *testing.B) {
	for _, brokers := range []int{4, 13, 17} {
		for _, providers := range []int{1, 3} {
			for _, scenario := range []string{
				"FirstHit", "Missing", "LastHit", "OrderFirst",
				"Disabled", "AtBroker", "ProxyJump",
			} {
				b.Run(fmt.Sprintf("B%d/P%d/%s", brokers, providers, scenario), func(b *testing.B) {
					ids := []string{"A", "B", "C"}[:providers]
					specs := make(parameters.InproxyBrokerSpecsValue, brokers)
					for i := range specs {
						specs[i] = newProviderTestBroker(b, ids...)
					}
					m := newProviderTestManager(b, 1, specs...)
					m.config.DisableReplay = scenario == "Disabled"
					p := m.config.GetParameters().Get()
					defer p.Close()
					wantReplay := scenario == "FirstHit" || scenario == "LastHit"
					selected := 0
					if scenario == "LastHit" {
						selected = brokers - 1
					}
					if wantReplay {
						params, err := MakeInproxyBrokerDialParameters(m.config, p,
							specs[selected], specs[selected].BrokerFrontingSpecs[:1], m.tlsCache)
						if err != nil {
							b.Fatal(err)
						}
						if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
							b.Fatal(err)
						}
					}
					beforeID, before := benchmarkReplayStoreStats(b)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						visit := &inproxyBrokerSelectionState{}
						proxy := scenario == "AtBroker" || scenario == "ProxyJump"
						if scenario == "AtBroker" {
							visit.spec = specs[0]
						}
						s := inproxyBrokerSelector{
							brokers: specs, providers: ids,
							currentBrokerSelection: visit,
							proxy:                  proxy, exhaustBrokerProviders: proxy,
							preferBrokerOrder: scenario == "OrderFirst",
						}
						selection, err := s.selectClient(m.config, p, "TEST", proxy, nil)
						if err != nil {
							b.Fatal(err)
						}
						if selection == nil || selection.brokerSpec != specs[selected] ||
							(selection.replayDialParams != nil) != wantReplay ||
							selection.frontingSpecs[0].FrontingProviderID != "A" {
							b.Fatal("unexpected selected route or replay")
						}
					}
					b.StopTimer()
					reportReplayStoreStats(b, beforeID, before)
				})
			}
		}
	}
}
