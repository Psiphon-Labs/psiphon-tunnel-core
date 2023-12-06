package phantoms

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"time"

	wr "github.com/mroth/weightedrand"
	pb "github.com/refraction-networking/conjure/proto"
)

// getSubnetsVarint - return EITHER all subnet strings as one composite array if
// we are selecting unweighted, or return the array associated with the (seed)
// selected array of subnet strings based on the associated weights
//
// Used by Client version 0 and 1
func (sc *SubnetConfig) getSubnetsVarint(seed []byte, weighted bool) ([]*phantomNet, error) {

	if weighted {
		// seed random with hkdf derived seed provided by client
		seedInt, n := binary.Varint(seed)
		if n == 0 {
			return nil, fmt.Errorf("failed to seed random for weighted rand")
		}

		// nolint:staticcheck // here for backwards compatibility with clients
		mrand.Seed(seedInt)

		choices := make([]wr.Choice, 0, len(sc.WeightedSubnets))
		for _, cjSubnet := range sc.WeightedSubnets {
			cjSubnet := cjSubnet // copy loop ptr
			choices = append(choices, wr.Choice{Item: cjSubnet, Weight: uint(cjSubnet.GetWeight())})
		}
		c, err := wr.NewChooser(choices...)
		if err != nil {
			return nil, err
		}

		return parseSubnets(c.Pick().(*pb.PhantomSubnets))

	}

	// Use unweighted config for subnets, concat all into one array and return.
	out := []*phantomNet{}
	for _, cjSubnet := range sc.WeightedSubnets {
		nets, err := parseSubnets(cjSubnet)
		if err != nil {
			return nil, fmt.Errorf("error parsing subnet: %v", err)
		}
		out = append(out, nets...)
	}

	return out, nil
}

// selectPhantomImplVarint - select an ip address from the list of subnets
// associated with the specified generation by constructing a set of start and
// end values for the high and low values in each allocation. The random number
// is then bound between the global min and max of that set. This ensures that
// addresses are chosen based on the number of addresses in the subnet.
func selectPhantomImplVarint(seed []byte, subnets []*phantomNet) (*PhantomIP, error) {
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
		return nil, ErrLegacyAddrSelectBug
	}

	// Pick a value using the seed in the range of between 0 and the total
	// number of addresses.
	id := &big.Int{}
	id.SetBytes(seed)
	if id.Cmp(addressTotal) >= 0 {
		id.Mod(id, addressTotal)
	}

	// Find the network (ID net) that contains our random value and select a
	// random address from that subnet.
	// min >= id%total >= max
	var result *PhantomIP
	for _, _idNet := range idNets {
		// fmt.Printf("tot:%s, seed%%tot:%s     id cmp max: %d,  id cmp min: %d %s\n", addressTotal.String(), id, _idNet.max.Cmp(id), _idNet.min.Cmp(id), _idNet.net.String())
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) <= 0 {
			res, err := SelectAddrFromSubnet(seed, _idNet.net.IPNet)
			if err != nil {
				return nil, fmt.Errorf("failed to chose IP address: %v", err)
			}

			result = &PhantomIP{ip: &res, supportRandomPort: _idNet.net.supportRandomPort}
		}
	}

	// We want to make it so this CANNOT happen
	if result == nil {
		return nil, errors.New("nil result should not be possible")
	}
	return result, nil
}

// selectPhantomImplV0 implements support for the legacy (buggy) client phantom
// address selection algorithm.
func selectPhantomImplV0(seed []byte, subnets []*phantomNet) (*PhantomIP, error) {

	addressTotal := big.NewInt(0)

	type idNet struct {
		min, max big.Int
		net      *phantomNet
	}
	var idNets []idNet

	for _, _net := range subnets {
		netMaskOnes, _ := _net.Mask.Size()
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(32-netMaskOnes)), nil))
			addressTotal.Sub(addressTotal, big.NewInt(1))
			_idNet.max.Set(addressTotal)
			_idNet.net = _net
			idNets = append(idNets, _idNet)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(128-netMaskOnes)), nil))
			addressTotal.Sub(addressTotal, big.NewInt(1))
			_idNet.max.Set(addressTotal)
			_idNet.net = _net
			idNets = append(idNets, _idNet)
		} else {
			return nil, fmt.Errorf("failed to parse %v", _net)
		}
	}

	if addressTotal.Cmp(big.NewInt(0)) <= 0 {
		return nil, ErrLegacyMissingAddrs
	}

	id := &big.Int{}
	id.SetBytes(seed)
	if id.Cmp(addressTotal) > 0 {
		id.Mod(id, addressTotal)
	}

	var result *PhantomIP
	for _, _idNet := range idNets {
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) == -1 {
			res, err := SelectAddrFromSubnet(seed, _idNet.net.IPNet)
			if err != nil {
				return nil, fmt.Errorf("failed to chose IP address: %v", err)
			}
			result = &PhantomIP{ip: &res, supportRandomPort: _idNet.net.supportRandomPort}
		}
	}
	if result == nil {
		return nil, ErrLegacyV0SelectionBug
	}
	return result, nil
}

// SelectAddrFromSubnet - given a seed and a CIDR block choose an address.
//
// This is done by generating a seeded random bytes up to the length of the full
// address then using the net mask to zero out any bytes that are already
// specified by the CIDR block. Tde masked random value is then added to the
// cidr block base giving the final randomly selected address.
func SelectAddrFromSubnet(seed []byte, net1 *net.IPNet) (net.IP, error) {
	bits, addrLen := net1.Mask.Size()

	ipBigInt := &big.Int{}
	if v4net := net1.IP.To4(); v4net != nil {
		ipBigInt.SetBytes(net1.IP.To4())
	} else if v6net := net1.IP.To16(); v6net != nil {
		ipBigInt.SetBytes(net1.IP.To16())
	}

	seedInt, n := binary.Varint(seed)
	if n == 0 {
		return nil, fmt.Errorf("failed to create seed ")
	}

	// nolint:staticcheck // here for backwards compatibility with clients
	mrand.Seed(seedInt)
	randBytes := make([]byte, addrLen/8)

	// nolint:staticcheck // here for backwards compatibility with clients
	_, err := mrand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	randBigInt := &big.Int{}
	randBigInt.SetBytes(randBytes)

	mask := make([]byte, addrLen/8)
	for i := 0; i < addrLen/8; i++ {
		mask[i] = 0xff
	}
	maskBigInt := &big.Int{}
	maskBigInt.SetBytes(mask)
	maskBigInt.Rsh(maskBigInt, uint(bits))

	randBigInt.And(randBigInt, maskBigInt)
	ipBigInt.Add(ipBigInt, randBigInt)

	return net.IP(ipBigInt.Bytes()), nil
}

func init() {
	// NOTE: math/rand is only used for backwards compatibility.
	// nolint:staticcheck
	mrand.Seed(time.Now().UnixNano())
}
