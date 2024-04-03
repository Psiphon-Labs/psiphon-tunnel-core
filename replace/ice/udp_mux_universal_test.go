// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package ice

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun"
	"github.com/stretchr/testify/require"
)

func TestUniversalUDPMux(t *testing.T) {
	conn, err := net.ListenUDP(udp, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	udpMux := NewUniversalUDPMuxDefault(UniversalUDPMuxParams{
		Logger:  nil,
		UDPConn: conn,
	})

	defer func() {
		_ = udpMux.Close()
		_ = conn.Close()
	}()

	require.NotNil(t, udpMux.LocalAddr(), "tcpMux.LocalAddr() is nil")

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		testMuxSrflxConnection(t, udpMux, "ufrag4", udp)
	}()

	wg.Wait()
}

func testMuxSrflxConnection(t *testing.T, udpMux *UniversalUDPMuxDefault, ufrag string, network string) {
	pktConn, err := udpMux.GetConn(ufrag, udpMux.LocalAddr())
	require.NoError(t, err, "error retrieving muxed connection for ufrag")
	defer func() {
		_ = pktConn.Close()
	}()

	remoteConn, err := net.DialUDP(network, nil, &net.UDPAddr{
		Port: udpMux.LocalAddr().(*net.UDPAddr).Port,
	})
	require.NoError(t, err, "error dialing test UDP connection")
	defer func() {
		_ = remoteConn.Close()
	}()

	// Use small value for TTL to check expiration of the address
	udpMux.params.XORMappedAddrCacheTTL = time.Millisecond * 20
	testXORIP := net.ParseIP("213.141.156.236")
	testXORPort := 21254

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		address, e := udpMux.GetXORMappedAddr(remoteConn.LocalAddr(), time.Second)
		require.NoError(t, e)
		require.NotNil(t, address)
		require.True(t, address.IP.Equal(testXORIP))
		require.Equal(t, address.Port, testXORPort)
	}()

	// Wait until GetXORMappedAddr calls sendSTUN method
	time.Sleep(time.Millisecond)

	// Check that mapped address filled correctly after sent STUN
	udpMux.mu.Lock()
	mappedAddr, ok := udpMux.xorMappedMap[remoteConn.LocalAddr().String()]
	require.True(t, ok)
	require.NotNil(t, mappedAddr)
	require.True(t, mappedAddr.pending())
	require.False(t, mappedAddr.expired())
	udpMux.mu.Unlock()

	// Clean receiver read buffer
	buf := make([]byte, receiveMTU)
	_, err = remoteConn.Read(buf)
	require.NoError(t, err)

	// Write back to udpMux XOR message with address
	msg := stun.New()
	msg.Type = stun.MessageType{Method: stun.MethodBinding, Class: stun.ClassRequest}
	msg.Add(stun.AttrUsername, []byte(ufrag+":otherufrag"))
	addr := &stun.XORMappedAddress{
		IP:   testXORIP,
		Port: testXORPort,
	}
	err = addr.AddTo(msg)
	require.NoError(t, err)

	msg.Encode()
	_, err = remoteConn.Write(msg.Raw)
	require.NoError(t, err)

	// Wait for the packet to be consumed and parsed by udpMux
	wg.Wait()

	// We should get address immediately from the cached map
	address, err := udpMux.GetXORMappedAddr(remoteConn.LocalAddr(), time.Second)
	require.NoError(t, err)
	require.NotNil(t, address)

	udpMux.mu.Lock()
	// Check mappedAddr is not pending, we didn't send STUN twice
	require.False(t, mappedAddr.pending())

	// Check expiration by TTL
	time.Sleep(time.Millisecond * 21)
	require.True(t, mappedAddr.expired())
	udpMux.mu.Unlock()

	// After expire, we send STUN request again
	// but we not receive response in 5 milliseconds and should get error here
	address, err = udpMux.GetXORMappedAddr(remoteConn.LocalAddr(), time.Millisecond*5)
	require.NotNil(t, err)
	require.Nil(t, address)
}
