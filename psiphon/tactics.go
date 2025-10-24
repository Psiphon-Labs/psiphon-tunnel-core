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
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	utls "github.com/Psiphon-Labs/utls"
)

// GetTactics attempts to apply tactics, for the current network, to the given
// config. GetTactics first checks for unexpired stored tactics, which it will
// immediately return. If no unexpired stored tactics are found, tactics
// requests are attempted until the input context is cancelled.
//
// Callers may pass in a context that is already done. In this case, stored
// tactics, when available, are applied but no request will be attempted.
//
// Callers are responsible for ensuring that the input context eventually
// cancels, and should synchronize GetTactics calls to ensure no unintended
// concurrent fetch attempts occur.
//
// GetTactics implements a limited workaround for multiprocess datastore
// synchronization, enabling, for example, SendFeedback in one process to
// access tactics as long as a Controller is not running in another process;
// and without blocking the Controller from starting. Accessing tactics is
// most critical for untunneled network operations; when a Controller is
// running, a tunnel may be used. See TacticsStorer for more details.
//
// When the useStoredTactics input flag is false, any locally cached tactics
// are ignored, regardless of TTL, and a fetch is always performed. GetTactics
// returns true when a fetch was performed and false otherwise (either cached
// tactics were found and applied, or there was a failure). This combination
// of useStoredTactics input and fetchedTactics output is used by the
// caller to force a fetch if one was not already performed to handle states
// where no tunnels can be established due to missing tactics.
func GetTactics(ctx context.Context, config *Config, useStoredTactics bool) (fetchedTactics bool) {

	// Limitation: GetNetworkID may not account for device VPN status, so
	// Psiphon-over-Psiphon or Psiphon-over-other-VPN scenarios can encounter
	// this issue:
	//
	// 1. Tactics are established when tunneling through a VPN and egressing
	//    through a remote region/ISP.
	// 2. Psiphon is next run when _not_ tunneling through the VPN. Yet the
	//    network ID remains the same. Initial applied tactics will be for the
	//    remote egress region/ISP, not the local region/ISP.

	var tacticsRecord *tactics.Record

	if useStoredTactics {
		var err error
		tacticsRecord, err = tactics.UseStoredTactics(
			GetTacticsStorer(config),
			config.GetNetworkID())
		if err != nil {
			NoticeWarning("get stored tactics failed: %s", errors.Trace(err))

			// The error will be due to a local datastore problem.
			// While we could proceed with the tactics request, this
			// could result in constant tactics requests. So, abort.
			return
		}
	}

	if tacticsRecord == nil {

		// If the context is already Done, don't even start the request.
		if ctx.Err() != nil {
			return
		}

		iterator, err := NewTacticsServerEntryIterator(config)
		if err != nil {
			NoticeWarning("tactics iterator failed: %s", errors.Trace(err))
			return
		}
		defer iterator.Close()

		noCapableServers := true

		for iteration := 0; ; iteration++ {

			if !WaitForNetworkConnectivity(
				ctx, config.NetworkConnectivityChecker, nil) {
				return
			}

			serverEntry, err := iterator.Next()
			if err != nil {
				NoticeWarning("tactics iterator failed: %s", errors.Trace(err))
				return
			}

			if serverEntry == nil {
				if noCapableServers {
					// Abort when no capable servers have been found after
					// a full iteration. Server entries that are skipped are
					// classified as not capable.
					NoticeWarning("tactics request aborted: no capable servers")
					return
				}

				err := iterator.Reset()
				if err != nil {
					NoticeWarning("tactics iterator failed: %s", errors.Trace(err))
					return
				}
				continue
			}

			tacticsRecord, err = fetchTactics(
				ctx, config, serverEntry)

			if tacticsRecord != nil || err != nil {
				// The fetch succeeded or failed but was not skipped.
				noCapableServers = false
			}

			if err == nil {
				if tacticsRecord != nil {

					// Set the return value indicating a successful fetch.
					// Note that applying the tactics below may still fail,
					// but this is not an expected case and we don't want the
					// caller to continuously force refetches after this point.
					fetchedTactics = true

					// The fetch succeeded, so exit the fetch loop and apply
					// the result.
					break
				} else {
					// MakeDialParameters, via fetchTactics, returns nil/nil
					// when the server entry is to be skipped. See
					// MakeDialParameters for skip cases and skip logging.
					// Silently select a new candidate in this case.
					continue
				}
			}

			NoticeWarning("tactics request failed: %s", errors.Trace(err))

			// On error, proceed with a retry, as the error is likely
			// due to a network failure.
			//
			// TODO: distinguish network and local errors and abort
			// on local errors.

			p := config.GetParameters().Get()
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

	if tacticsRecord != nil {

		err := config.SetParameters(
			tacticsRecord.Tag, true, tacticsRecord.Tactics.Parameters)
		if err != nil {
			NoticeWarning("apply tactics failed: %s", errors.Trace(err))

			// The error will be due to invalid tactics values from
			// the server. When SetParameters fails, all
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

	return
}

// fetchTactics performs a tactics request using the specified server entry.
// fetchTactics will return nil/nil when the candidate server entry is
// skipped.
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

	// No upstreamProxyErrorCallback is set: for tunnel establishment, the
	// tactics head start is short, and tunnel connections will eventually post
	// NoticeUpstreamProxyError for any persistent upstream proxy error
	// conditions. Non-tunnel establishment cases, such as SendFeedback, which
	// use tactics are not currently expected to post NoticeUpstreamProxyError.

	dialParams, err := MakeDialParameters(
		config,
		nil,
		tls.NewLRUClientSessionCache(0),
		utls.NewLRUClientSessionCache(0),
		nil,
		canReplay,
		selectProtocol,
		serverEntry,
		nil,
		nil,
		true,
		0,
		0)
	if dialParams == nil && err == nil {
		err = errors.TraceNew("unexpected nil dialParams")
	}
	if err != nil {
		return nil, errors.Tracef(
			"failed to make dial parameters for %s: %v",
			serverEntry.GetDiagnosticID(),
			errors.Trace(err))
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

	timeout := config.GetParameters().Get().Duration(
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

	// No padding is added via the params as this is provided by the tactics
	// request obfuscation layer.
	includeSessionID := true
	apiParams := getBaseAPIParameters(
		baseParametersAll, nil, includeSessionID, config, dialParams)

	tacticsRecord, err := tactics.FetchTactics(
		ctx,
		config.GetParameters(),
		GetTacticsStorer(config),
		config.GetNetworkID,
		compressTacticsEnabled,
		apiParams,
		serverEntry.Region,
		dialParams.TunnelProtocol,
		serverEntry.TacticsRequestPublicKey,
		serverEntry.TacticsRequestObfuscatedKey,
		meekConn.ObfuscatedRoundTrip)
	if err != nil {
		return nil, errors.Trace(err)
	}

	NoticeRequestedTactics(dialParams)

	return tacticsRecord, nil
}
