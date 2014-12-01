/*
 * Copyright (c) 2014, Psiphon Inc.
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

package stats

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

type StatsTestSuite struct {
	suite.Suite
}

func TestStatsTestSuite(t *testing.T) {
	suite.Run(t, new(StatsTestSuite))
}

func statsDialer(network, addr string) (conn net.Conn, err error) {
	fmt.Println("statsDialer", network, addr)

	var subConn net.Conn

	switch network {
	case "tcp", "tcp4", "tcp6":
		tcpAddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, err
		}
		subConn, err = net.DialTCP(network, nil, tcpAddr)
		if err != nil {
			return nil, err
		}
	default:
		err = errors.New("Using an unsupported testing network type")
		return
	}

	conn = &StatsConn{
		Conn: subConn,
	}
	err = nil
	return
}

func (suite *StatsTestSuite) Test_Blah() {
	tr := &http.Transport{
		Dial: statsDialer,
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://s3.amazonaws.com/f58xp-mqce-k1yj/en/index.html")
	resp.Body.Close()
	fmt.Println("resp", resp, "; err", err)

	resp, err = client.Get("http://s3.amazonaws.com/f58p-mqce-k1yj/en/index.html")
	resp.Body.Close()
	fmt.Println("resp", resp, "; err", err)
}
