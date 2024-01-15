//go:build windows

package dtls

import (
	"os"
	"syscall"
)

func setSocketTTL(f *os.File, ttl int) error {
	return syscall.SetsockoptInt(syscall.Handle(f.Fd()), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}
