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

package psiphon

import (
	"context"
	std_errors "errors"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
)

// GetTactics attempts to apply tactics, for the current network, to the given
// config. GetTactics first checks for unexpired stored tactics, which it will
// immediately return. If no unexpired stored tactics are found, tactics
// requests are attempted until the input context is cancelled.
//
// Callers are responsible for ensuring that the input context eventually
// cancels, and should synchronize GetTactics calls to ensure no unintended
// concurrent fetch attempts occur.
func GetTactics(ctx context.Context, config *Config) {

	// Limitation: GetNetworkID may not account for device VPN status, so
	// Psiphon-over-Psiphon or Psiphon-over-other-VPN scenarios can encounter
	// this issue:
	//
	// 1. Tactics are established when tunneling through a VPN and egressing
	//    through a remote region/ISP.
	// 2. Psiphon is next run when _not_ tunneling through the VPN. Yet the
	//    network ID remains the same. Initial applied tactics will be for the
	//    remote egress region/ISP, not the local region/ISP.

	tacticsRecord, err := tactics.UseStoredTactics(
		GetTacticsStorer(),
		config.GetNetworkID())
	if err != nil {
		NoticeWarning("get stored tactics failed: %s", err)

		// The error will be due to a local datastore problem.
		// While we could proceed with the tactics request, this
		// could result in constant tactics requests. So, abort.
		return
	}

	if tacticsRecord == nil {

		iterator, err := NewTacticsServerEntryIterator(config)
		if err != nil {
			NoticeWarning("tactics iterator failed: %s", err)
			return
		}
		defer iterator.Close()

		for iteration := 0; ; iteration++ {

			if !WaitForNetworkConnectivity(
				ctx, config.NetworkConnectivityChecker) {
				return
			}

			serverEntry, err := iterator.Next()
			if err != nil {
				NoticeWarning("tactics iterator failed: %s", err)
				return
			}

			if serverEntry == nil {
				if iteration == 0 {
					NoticeWarning("tactics request skipped: no capable servers")
					return
				}

				iterator.Reset()
				continue
			}

			tacticsRecord, err = fetchTactics(
				ctx, config, serverEntry)
			if err == nil {
				break
			}

			NoticeWarning("tactics request failed: %s", err)

			// On error, proceed with a retry, as the error is likely
			// due to a network failure.
			//
			// TODO: distinguish network and local errors and abort
			// on local errors.

			p := config.GetClientParameters().Get()
			timeout := prng.JitterDuration(
				p.Duration(parameters.TacticsRetryPeriod),
				p.Float(parameters.TacticsRetryPeriodJitter))
			p.Close()

			tacticsRetryDelay := time.NewTimer(timeout)

			select {
			case <-ctx.Done():
				return
			case <-tacticsRetryDelay.C:
			}

			tacticsRetryDelay.Stop()
		}
	}

	if tacticsRecord != nil &&
		prng.FlipWeightedCoin(tacticsRecord.Tactics.Probability) {

		err := config.SetClientParameters(
			tacticsRecord.Tag, true, tacticsRecord.Tactics.Parameters)
		if err != nil {
			NoticeWarning("apply tactics failed: %s", err)

			// The error will be due to invalid tactics values from
			// the server. When ApplyClientParameters fails, all
			// previous tactics values are left in place. Abort
			// without retry since the server is highly unlikely
			// to return different values immediately.
			return
		}
	}

	// Reclaim memory from the completed tactics request as we're likely
	// to be proceeding to the memory-intensive tunnel establishment phase.
	DoGarbageCollection()
	emitMemoryMetrics()
}

func fetchTactics(
	ctx context.Context,
	config *Config,
	serverEntry *protocol.ServerEntry) (*tactics.Record, error) {

	canReplay := func(serverEntry *protocol.ServerEntry, replayProtocol string) bool {
		return common.Contains(
			serverEntry.GetSupportedTacticsProtocols(), replayProtocol)
	}

	selectProtocol := func(serverEntry *protocol.ServerEntry) (string, bool) {
		tacticsProtocols := serverEntry.GetSupportedTacticsProtocols()
		if len(tacticsProtocols) == 0 {
			return "", false
		}
		index := prng.Intn(len(tacticsProtocols))
		return tacticsProtocols[index], true
	}

	dialParams, err := MakeDialParameters(
		config,
		canReplay,
		selectProtocol,
		serverEntry,
		true,
		0,
		0)
	if dialParams == nil {
		// MakeDialParameters may return nil, nil when the server entry can't
		// satisfy protocol selection criteria. This case in not expected
		// since NewTacticsServerEntryIterator should only return tactics-
		// capable server entries and selectProtocol will select any tactics
		// protocol.
		err = std_errors.New("failed to make dial parameters")
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	NoticeRequestingTactics(dialParams)

	// TacticsTimeout should be a very long timeout, since it's not
	// adjusted by tactics in a new network context, and so clients
	// with very slow connections must be accomodated. This long
	// timeout will not entirely block the beginning of tunnel
	// establishment, which beings after the shorter TacticsWaitPeriod.
	//
	// Using controller.establishCtx will cancel FetchTactics
	// if tunnel establishment completes first.

	timeout := config.GetClientParameters().Get().Duration(
		parameters.TacticsTimeout)

	ctx, cancelFunc := context.WithTimeout(ctx, timeout)
	defer cancelFunc()

	// DialMeek completes the TCP/TLS handshakes for HTTPS
	// meek protocols but _not_ for HTTP meek protocols.
	//
	// TODO: pre-dial HTTP protocols to conform with speed
	// test RTT spec.
	//
	// TODO: ensure that meek in round trip mode will fail
	// the request when the pre-dial connection is broken,
	// to minimize the possibility of network ID mismatches.

	meekConn, err := DialMeek(
		ctx, dialParams.GetMeekConfig(), dialParams.GetDialConfig())
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer meekConn.Close()

	apiParams := getBaseAPIParameters(
		baseParametersAll, config, dialParams)

	tacticsRecord, err := tactics.FetchTactics(
		ctx,
		config.clientParameters,
		GetTacticsStorer(),
		config.GetNetworkID,
		apiParams,
		serverEntry.Region,
		dialParams.TunnelProtocol,
		serverEntry.TacticsRequestPublicKey,
		serverEntry.TacticsRequestObfuscatedKey,
		meekConn.RoundTrip)
	if err != nil {
		return nil, errors.Trace(err)
	}

	NoticeRequestedTactics(dialParams)

	return tacticsRecord, nil
}
