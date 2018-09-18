/*
 * Copyright (c) 2018, Psiphon Inc.
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
	"fmt"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

// NewTCPFragmentorDialer creates a TCP dialer that wraps dialed conns in
// fragmentor.Conn. A single FragmentorProbability coin flip is made and all
// conns get the same treatment.
func NewTCPFragmentorDialer(
	config *DialConfig,
	tunnelProtocol string,
	clientParameters *parameters.ClientParameters) Dialer {

	p := clientParameters.Get()
	coinFlip := p.WeightedCoinFlip(parameters.FragmentorProbability)
	p = nil

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, common.ContextError(fmt.Errorf("%s unsupported", network))
		}
		return DialTCPFragmentor(ctx, addr, config, tunnelProtocol, clientParameters, &coinFlip)
	}
}

// DialTCPFragmentor performs a DialTCP and wraps the dialed conn in a
// fragmentor.Conn, subject to FragmentorProbability and
// FragmentorLimitProtocols.
func DialTCPFragmentor(
	ctx context.Context,
	addr string,
	config *DialConfig,
	tunnelProtocol string,
	clientParameters *parameters.ClientParameters,
	oneTimeCoinFlip *bool) (net.Conn, error) {

	conn, err := DialTCP(ctx, addr, config)
	if err != nil {
		return nil, common.ContextError(err)
	}

	p := clientParameters.Get()

	protocols := p.TunnelProtocols(parameters.FragmentorLimitProtocols)
	if len(protocols) > 0 && !common.Contains(protocols, tunnelProtocol) {
		return conn, nil
	}

	var coinFlip bool
	if oneTimeCoinFlip != nil {
		coinFlip = *oneTimeCoinFlip
	} else {
		coinFlip = p.WeightedCoinFlip(parameters.FragmentorProbability)
	}

	if coinFlip {
		return conn, nil
	}

	totalBytes, err := common.MakeSecureRandomRange(
		p.Int(parameters.FragmentorMinTotalBytes),
		p.Int(parameters.FragmentorMaxTotalBytes))
	if err != nil {
		totalBytes = 0
		NoticeAlert("MakeSecureRandomRange failed: %s", common.ContextError(err))
	}

	if totalBytes == 0 {
		return conn, nil
	}

	return fragmentor.NewConn(
			conn,
			func(message string) { NoticeInfo(message) },
			totalBytes,
			p.Int(parameters.FragmentorMinWriteBytes),
			p.Int(parameters.FragmentorMaxWriteBytes),
			p.Duration(parameters.FragmentorMinDelay),
			p.Duration(parameters.FragmentorMaxDelay)),
		nil
}
