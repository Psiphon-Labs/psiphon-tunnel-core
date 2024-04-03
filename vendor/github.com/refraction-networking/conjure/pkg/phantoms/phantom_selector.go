package phantoms

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"

	pb "github.com/refraction-networking/conjure/proto"
	"golang.org/x/crypto/hkdf"
)

var (
	// ErrLegacyAddrSelectBug indicates that we have hit a corner case in a legacy address selection
	// algorithm that causes phantom address selection to fail.
	ErrLegacyAddrSelectBug  = errors.New("no valid addresses specified")
	ErrLegacyMissingAddrs   = errors.New("No valid addresses specified")
	ErrLegacyV0SelectionBug = errors.New("let's rewrite the phantom address selector")

	// ErrMissingAddrs indicates that no subnets were provided with addresses to select from. This
	// is only valid for phantomHkdfMinVersion and newer.
	ErrMissingAddrs = errors.New("no valid addresses specified to select")
)

// getSubnetsHkdf returns EITHER all subnet strings as one composite array if
// we are selecting unweighted, or return the array associated with the (seed)
// selected array of subnet strings based on the associated weights. Random
// values are seeded using an hkdf function to prevent biases introduced by
// math/rand and varint.
//
// Used by Client version 2+
func getSubnetsHkdf(sc genericSubnetConfig, seed []byte, weighted bool) ([]*phantomNet, error) {

	weightedSubnets := sc.GetWeightedSubnets()
	if weightedSubnets == nil {
		return []*phantomNet{}, nil
	}

	if weighted {
		choices := make([]*pb.PhantomSubnets, 0, len(weightedSubnets))

		totWeight := int64(0)
		for _, cjSubnet := range weightedSubnets {
			cjSubnet := cjSubnet // copy loop ptr
			weight := cjSubnet.GetWeight()
			subnets := cjSubnet.GetSubnets()
			if subnets == nil {
				continue
			}

			totWeight += int64(weight)
			choices = append(choices, cjSubnet)
		}

		// Sort choices ascending
		sort.Slice(choices, func(i, j int) bool {
			return choices[i].GetWeight() < choices[j].GetWeight()
		})

		// Naive method: get random int, subtract from weights until you are < 0
		hkdfReader := hkdf.New(sha256.New, seed, nil, []byte("phantom-select-subnet"))
		totWeightBig := big.NewInt(totWeight)
		rndBig, err := rand.Int(hkdfReader, totWeightBig)
		if err != nil {
			return nil, err
		}

		// Decrement rnd by each weight until it's < 0
		rnd := rndBig.Int64()
		for _, choice := range choices {
			rnd -= int64(choice.GetWeight())
			if rnd < 0 {
				return parseSubnets(choice)
			}
		}

	}

	// Use unweighted config for subnets, concat all into one array and return.
	out := []*phantomNet{}
	for _, cjSubnet := range weightedSubnets {
		nets, err := parseSubnets(cjSubnet)
		if err != nil {
			return nil, fmt.Errorf("error parsing subnet: %v", err)
		}
		out = append(out, nets...)
	}

	return out, nil
}

func selectPhantomImplHkdf(seed []byte, subnets []*phantomNet) (*PhantomIP, error) {
	type idNet struct {
		min, max big.Int
		net      *phantomNet
	}
	var idNets []idNet

	// Compose a list of ID Nets with min, max and network associated and count
	// the total number of available addresses.
	addressTotal := big.NewInt(0)
	for _, _net := range subnets {
		netMaskOnes, _ := _net.Mask.Size()
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(32-netMaskOnes)), nil))
			_idNet.max.Sub(addressTotal, big.NewInt(1))
			_idNet.net = _net
			idNets = append(idNets, _idNet)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(128-netMaskOnes)), nil))
			_idNet.max.Sub(addressTotal, big.NewInt(1))
			_idNet.net = _net
			idNets = append(idNets, _idNet)
		} else {
			return nil, fmt.Errorf("failed to parse %v", _net)
		}
	}

	// If the total number of addresses is 0 something has gone wrong
	if addressTotal.Cmp(big.NewInt(0)) <= 0 {
		return nil, ErrMissingAddrs
	}

	// Pick a value using the seed in the range of between 0 and the total
	// number of addresses.
	hkdfReader := hkdf.New(sha256.New, seed, nil, []byte("phantom-addr-id"))
	id, err := rand.Int(hkdfReader, addressTotal)
	if err != nil {
		return nil, err
	}

	// Find the network (ID net) that contains our random value and select a
	// random address from that subnet.
	// min >= id%total >= max
	var result *PhantomIP
	for _, _idNet := range idNets {
		// fmt.Printf("tot:%s, seed%%tot:%s     id cmp max: %d,  id cmp min: %d %s\n", addressTotal.String(), id, _idNet.max.Cmp(id), _idNet.min.Cmp(id), _idNet.net.String())
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) <= 0 {

			var offset big.Int
			offset.Sub(id, &_idNet.min)
			result, err = selectAddrFromSubnetOffset(_idNet.net, &offset)
			if err != nil {
				return nil, fmt.Errorf("failed to chose IP address: %v", err)
			}
		}
	}

	// We want to make it so this CANNOT happen
	if result == nil {
		return nil, errors.New("nil result should not be possible")
	}
	return result, nil
}

// selectAddrFromSubnetOffset given a CIDR block and offset, return the net.IP
//
// Version 2: HKDF-based
func selectAddrFromSubnetOffset(net1 *phantomNet, offset *big.Int) (*PhantomIP, error) {
	bits, addrLen := net1.Mask.Size()

	// Compute network size (e.g. an ipv4 /24 is 2^(32-24)
	var netSize big.Int
	netSize.Exp(big.NewInt(2), big.NewInt(int64(addrLen-bits)), nil)

	// Check that offset is within this subnet
	if netSize.Cmp(offset) <= 0 {
		return nil, errors.New("offset too big for subnet")
	}

	ipBigInt := &big.Int{}
	if v4net := net1.IP.To4(); v4net != nil {
		ipBigInt.SetBytes(net1.IP.To4())
	} else if v6net := net1.IP.To16(); v6net != nil {
		ipBigInt.SetBytes(net1.IP.To16())
	}

	ipBigInt.Add(ipBigInt, offset)
	ip := net.IP(ipBigInt.Bytes())

	return &PhantomIP{ip: &ip, supportRandomPort: net1.supportRandomPort}, nil
}
