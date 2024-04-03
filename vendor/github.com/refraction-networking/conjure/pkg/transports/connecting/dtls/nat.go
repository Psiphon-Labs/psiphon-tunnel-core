package dtls

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/stun"
)

const ttl = 5
const defaultTTL = 64

type fileConn interface {
	File() (*os.File, error)
}

func openUDP(ctx context.Context, laddr, addr string, dialer dialFunc) error {
	conn, err := dialer(ctx, "udp", laddr, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	return sendPacket(ctx, conn)
}

func sendPacket(ctx context.Context, conn net.Conn) error {
	_, err := conn.Write([]byte(""))
	if err != nil {
		return err
	}

	return nil
}

func openUDPLimitTTL(ctx context.Context, laddr, addr string, dialer dialFunc) error {
	// Create a UDP connection
	conn, err := dialer(ctx, "udp", laddr, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	fileConn, ok := conn.(fileConn)
	if !ok {
		return fmt.Errorf("dialed conn does not implement File()")
	}

	// Get the file descriptor
	fd, err := fileConn.File()
	if err != nil {
		return err
	}
	defer fd.Close()

	// Set the TTL
	err = setSocketTTL(fd, ttl)
	if err != nil {
		return err
	}

	// Write data to the connection
	_, err = conn.Write([]byte(""))
	if err != nil {
		return err
	}

	// reset TTL
	err = setSocketTTL(fd, defaultTTL)
	if err != nil {
		return err
	}

	// No error
	return nil
}

func publicAddr(ctx context.Context, network string, stunServer string, dialer dialFunc) (privateAddr *net.UDPAddr, publicAddr *net.UDPAddr, err error) {

	udpConn, err := dialer(ctx, network, "", stunServer)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to STUN server: %v", err)
	}
	defer udpConn.Close()

	localAddr, err := net.ResolveUDPAddr(udpConn.LocalAddr().Network(), udpConn.LocalAddr().String())
	if err != nil {
		return nil, nil, fmt.Errorf("error resolving local address: %v", err)
	}

	pubAddr, err := doSTUN(ctx, udpConn)
	if err != nil {
		return nil, nil, err
	}

	return localAddr, pubAddr, nil
}

func doSTUN(ctx context.Context, udpConn net.Conn) (*net.UDPAddr, error) {

	client, err := stun.NewClient(udpConn)
	if err != nil {
		return nil, fmt.Errorf("error creating STUN client: %v", err)
	}

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var xorAddr stun.XORMappedAddress

	doneCh := make(chan error, 1)

	err = client.Start(message, func(res stun.Event) {
		if res.Error != nil {
			doneCh <- res.Error
			return
		}

		resErr := xorAddr.GetFrom(res.Message)
		doneCh <- resErr
	})

	if err != nil {
		return nil, fmt.Errorf("error getting address from STUN: %v", err)
	}

	defer client.Close()
	if deadline, ok := ctx.Deadline(); ok {
		timer := time.AfterFunc(time.Until(deadline), func() { client.Close() })
		defer timer.Stop()
	}

	select {
	case err := <-doneCh:
		if err != nil {
			return nil, fmt.Errorf("error during client: %v", err)
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout: %v", ctx.Err())
	}

	return &net.UDPAddr{IP: xorAddr.IP, Port: xorAddr.Port}, nil

}
