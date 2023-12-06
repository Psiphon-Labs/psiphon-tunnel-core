package phantoms

import (
	"fmt"
	"net"

	pb "github.com/refraction-networking/conjure/proto"
)

type phantomNet struct {
	*net.IPNet
	supportRandomPort bool
}

func (p *phantomNet) SupportRandomPort() bool {
	return p.supportRandomPort
}

type genericSubnetConfig interface {
	GetWeightedSubnets() []*pb.PhantomSubnets
}

// getSubnets - return EITHER all subnet strings as one composite array if we are
// selecting unweighted, or return the array associated with the (seed) selected
// array of subnet strings based on the associated weights
func getSubnets(sc genericSubnetConfig, seed []byte, weighted bool) ([]*phantomNet, error) {
	return getSubnetsHkdf(sc, seed, weighted)
}

// SubnetFilter - Filter IP subnets based on whatever to prevent specific subnets from
//
//	inclusion in choice. See v4Only and v6Only for reference.
type SubnetFilter func([]*phantomNet) ([]*phantomNet, error)

// V4Only - a functor for transforming the subnet list to only include IPv4 subnets
func V4Only(obj []*phantomNet) ([]*phantomNet, error) {
	out := []*phantomNet{}

	for _, _net := range obj {
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			out = append(out, _net)
		}
	}
	return out, nil
}

// V6Only - a functor for transforming the subnet list to only include IPv6 subnets
func V6Only(obj []*phantomNet) ([]*phantomNet, error) {
	out := []*phantomNet{}

	for _, _net := range obj {
		if _net.IP == nil {
			continue
		}
		if net := _net.IP.To4(); net != nil {
			continue
		}
		out = append(out, _net)
	}
	return out, nil
}

func parseSubnets(phantomSubnet *pb.PhantomSubnets) ([]*phantomNet, error) {
	subnets := []*phantomNet{}

	if len(phantomSubnet.GetSubnets()) == 0 {
		return nil, fmt.Errorf("parseSubnets - no subnets provided")
	}

	for _, strNet := range phantomSubnet.GetSubnets() {
		parsedNet, err := parseSubnet(strNet)
		if err != nil {
			return nil, err
		}

		subnets = append(subnets, &phantomNet{IPNet: parsedNet, supportRandomPort: phantomSubnet.GetRandomizeDstPort()})
	}

	return subnets, nil
}

func parseSubnet(phantomSubnet string) (*net.IPNet, error) {
	_, parsedNet, err := net.ParseCIDR(phantomSubnet)
	if err != nil {
		return nil, err
	}
	if parsedNet == nil {
		return nil, fmt.Errorf("failed to parse %v as subnet", parsedNet)
	}

	return parsedNet, nil
}

// selectIPAddr selects an ip address from the list of subnets associated
// with the specified generation by constructing a set of start and end values
// for the high and low values in each allocation. The random number is then
// bound between the global min and max of that set. This ensures that
// addresses are chosen based on the number of addresses in the subnet.
func selectIPAddr(seed []byte, subnets []*phantomNet) (*PhantomIP, error) {
	return selectPhantomImplHkdf(seed, subnets)
}

// SelectPhantom - select one phantom IP address based on shared secret
func SelectPhantom(seed []byte, subnetsList *pb.PhantomSubnetsList, transform SubnetFilter, weighted bool) (*PhantomIP, error) {

	s, err := getSubnets(subnetsList, seed, weighted)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subnets: %v", err)
	}

	if transform != nil {
		s, err = transform(s)
		if err != nil {
			return nil, err
		}
	}

	return selectIPAddr(seed, s)
}

// SelectPhantomUnweighted - select one phantom IP address based on shared secret
func SelectPhantomUnweighted(seed []byte, subnets *pb.PhantomSubnetsList, transform SubnetFilter) (*PhantomIP, error) {
	return SelectPhantom(seed, subnets, transform, false)
}

// SelectPhantomWeighted - select one phantom IP address based on shared secret
func SelectPhantomWeighted(seed []byte, subnets *pb.PhantomSubnetsList, transform SubnetFilter) (*PhantomIP, error) {
	return SelectPhantom(seed, subnets, transform, true)
}

// GetDefaultPhantomSubnets implements the
func GetDefaultPhantomSubnets() *pb.PhantomSubnetsList {
	var w1 = uint32(9.0)
	var w2 = uint32(1.0)
	return &pb.PhantomSubnetsList{
		WeightedSubnets: []*pb.PhantomSubnets{
			{
				Weight:  &w1,
				Subnets: []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"},
			},
			{
				Weight:  &w2,
				Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"},
			},
		},
	}
}

// GetUnweightedSubnetList returns the list of subnets provided by the protobuf. Convenience
// function to not have to export getSubnets() or parseSubnets()
func GetUnweightedSubnetList(subnetsList *pb.PhantomSubnetsList) ([]*phantomNet, error) {
	return getSubnets(subnetsList, nil, false)
}

func IP(ip net.IP, supportRandomPort bool) *PhantomIP {
	return &PhantomIP{ip: &ip, supportRandomPort: supportRandomPort}
}

// type alias to make embedding unexported
// nolint:unused
type ip = net.IP
type PhantomIP struct {
	*ip
	supportRandomPort bool
}

func (p *PhantomIP) SupportRandomPort() bool {
	return p.supportRandomPort
}

func (p *PhantomIP) IP() *net.IP {
	return p.ip
}
