package psiphon

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"sort"
	"strings"
)

// SplitTunnelDirector determines whether a destination should be
// accessed through a tunnel or accessed directly.
type SplitTunnelDirector struct {
	localNetworks []*net.IPNet
}

// NewSplitTunnelDirector creates a new SplitTunnelDirector, initializing
// it with routes data which maps out the ranges of IP addresses which should
// be excluded from tunneling. dnsServerAddress is used when a hostname must
// be resolved prior to making a determination. dnsDialConfig is used when
// making the connection to dnsServerAddress.
func NewSplitTunnelDirector(routesData []byte) (director *SplitTunnelDirector, err error) {

	// TODO: implementation
	dir := &SplitTunnelDirector{}
	dir.initRoutesData(routesData)
	return dir, nil
}

func (director *SplitTunnelDirector) initRoutesData(routesData []byte) {
	scanner := bufio.NewScanner(bytes.NewReader(routesData))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), "\t")
		if len(s) != 2 {
			continue
		}

		nwIP := ParseIPv4(s[0])
		nwMask := ParseIPv4Mask(s[1])

		if nwIP == nil || nwMask == nil {
			continue
		}

		director.localNetworks = append(director.localNetworks, &net.IPNet{IP: nwIP.Mask(nwMask), Mask: nwMask})
		// sort and remove duplicates from our networks array
		// so we could run binary search against it
		sort.Sort(NetworkSorter(director.localNetworks))
		director.removeDuplicates()
	}
}

// Adapted from
// http://openmymind.net/2011/7/15/Learning-Go-By-Benchmarking-Set-Implementation/
func (director *SplitTunnelDirector) removeDuplicates() {
	length := len(director.localNetworks) - 1
	for i := 0; i < length; i++ {
		for j := i + 1; j <= length; j++ {
			if director.localNetworks[i].IP.Equal(director.localNetworks[j].IP) {
				director.localNetworks[j] = director.localNetworks[length]
				director.localNetworks = director.localNetworks[0:length]
				length--
				j--
			}
		}
	}
}

func (director *SplitTunnelDirector) isLocalAddress(addr net.IP) bool {
	length := len(director.localNetworks)
	addrValue := binary.BigEndian.Uint32(addr.To4())
	idx := sort.Search(length, func(i int) bool {
		nwValue := binary.BigEndian.Uint32(director.localNetworks[i].IP)
		return nwValue > addrValue
	})

	return idx > 0 && director.localNetworks[idx-1].IP.Equal(addr.Mask(director.localNetworks[idx-1].Mask))
}

type NetworkSorter []*net.IPNet

func (ns NetworkSorter) Len() int      { return len(ns) }
func (ns NetworkSorter) Swap(i, j int) { ns[i], ns[j] = ns[j], ns[i] }
func (ns NetworkSorter) Less(i, j int) bool {
	nwa := binary.BigEndian.Uint32(ns[i].IP)
	nwb := binary.BigEndian.Uint32(ns[j].IP)
	return nwa < nwb
}

