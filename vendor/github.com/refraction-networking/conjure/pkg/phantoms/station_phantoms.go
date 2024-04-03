package phantoms

import (
	"fmt"
	"os"
	"strconv"

	toml "github.com/pelletier/go-toml"
	"github.com/refraction-networking/conjure/pkg/core"
	pb "github.com/refraction-networking/conjure/proto"
)

// SubnetConfig - Configuration of subnets for Conjure to choose a Phantom out of.
type SubnetConfig struct {
	WeightedSubnets []*pb.PhantomSubnets
}

func (sc *SubnetConfig) GetWeightedSubnets() []*pb.PhantomSubnets {
	return sc.WeightedSubnets
}

// PhantomIPSelector - Object for tracking current generation to SubnetConfig Mapping.
type PhantomIPSelector struct {
	Networks map[uint]*SubnetConfig
}

// type shim because github.com/pelletier/go-toml doesn't allow for integer value keys to maps so
// we have to parse them ourselves. :(
type phantomIPSelectorInternal struct {
	Networks map[string]*SubnetConfig
}

// NewPhantomIPSelector - create object currently populated with a static map of
// generation number to SubnetConfig, but this may be loaded dynamically in the
// future.
func NewPhantomIPSelector() (*PhantomIPSelector, error) {
	return GetPhantomSubnetSelector()
}

// GetPhantomSubnetSelector gets the location of the configuration file from an
// environment variable and returns the parsed configuration.
func GetPhantomSubnetSelector() (*PhantomIPSelector, error) {
	return SubnetsFromTomlFile(os.Getenv("PHANTOM_SUBNET_LOCATION"))
}

// SubnetsFromTomlFile takes a path and parses the toml config file
func SubnetsFromTomlFile(path string) (*PhantomIPSelector, error) {

	tree, err := toml.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error opening configuration file: %v", err)
	}

	var pss = &PhantomIPSelector{
		Networks: make(map[uint]*SubnetConfig),
	}
	// shim because github.com/pelletier/go-toml doesn't allow for integer value keys to maps so
	// we have to parse them ourselves. :(
	var phantomSelectorSet = &phantomIPSelectorInternal{}
	err = tree.Unmarshal(phantomSelectorSet)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling configuration file: %v", err)
	}

	for gen, set := range phantomSelectorSet.Networks {
		g, err := strconv.Atoi(gen)
		if err != nil {
			return nil, err
		}
		// fmt.Printf("[GetPhantomSubnetSelector] adding %d, %+v\n", g, set)
		pss.AddGeneration(g, set)
	}

	return pss, nil
}

// GetSubnetsByGeneration - provide a generation index. If the generation exists
// the associated SubnetConfig is returned. If it is not defined the default
// subnets are returned.
func (p *PhantomIPSelector) GetSubnetsByGeneration(generation uint) *SubnetConfig {
	if subnets, ok := p.Networks[generation]; ok {
		return subnets
	}

	// No Default subnets provided if the generation is not known
	return nil
}

// AddGeneration - add a subnet config as a new new generation, if the requested
// generation index is taken then it uses (and returns) the next available
// number.
func (p *PhantomIPSelector) AddGeneration(gen int, subnets *SubnetConfig) uint {

	ugen := uint(gen)

	if gen == -1 || p.IsTakenGeneration(ugen) {
		ugen = p.newGenerationIndex()
	}

	p.Networks[ugen] = subnets
	return ugen
}

func (p *PhantomIPSelector) newGenerationIndex() uint {
	maxGen := uint(0)
	for k := range p.Networks {
		if k > maxGen {
			maxGen = k
		}
	}
	return maxGen + 1
}

// IsTakenGeneration - check if the generation index is already in use.
func (p *PhantomIPSelector) IsTakenGeneration(gen uint) bool {
	if _, ok := p.Networks[gen]; ok {
		return true
	}
	return false
}

// RemoveGeneration - remove a generation from the mapping
func (p *PhantomIPSelector) RemoveGeneration(generation uint) bool {
	p.Networks[generation] = nil
	return true
}

// UpdateGeneration - Update the subnet list associated with a specific generation
func (p *PhantomIPSelector) UpdateGeneration(generation uint, subnets *SubnetConfig) bool {
	p.Networks[generation] = subnets
	return true
}

// Select - select an ip address from the list of subnets associated with the specified generation
func (p *PhantomIPSelector) Select(seed []byte, generation uint, clientLibVer uint, v6Support bool) (*PhantomIP, error) {
	genConfig := p.GetSubnetsByGeneration(generation)
	if genConfig == nil {
		return nil, fmt.Errorf("generation number not recognized")
	}

	genSubnets, err := subnetsByVersion(seed, clientLibVer, genConfig)
	if err != nil {
		return nil, err
	}

	if v6Support {
		genSubnets, err = V6Only(genSubnets)
		if err != nil {
			return nil, err
		}
	} else {
		genSubnets, err = V4Only(genSubnets)
		if err != nil {
			return nil, err
		}
	}

	// handle legacy clientLibVersions for selecting phantoms.
	if clientLibVer < core.PhantomSelectionMinGeneration {
		// Version 0
		ip, err := selectPhantomImplV0(seed, genSubnets)
		if err != nil {
			return nil, err
		}
		return ip, nil
	} else if clientLibVer < core.PhantomHkdfMinVersion {
		// Version 1
		ip, err := selectPhantomImplVarint(seed, genSubnets)
		if err != nil {
			return nil, err
		}
		return ip, nil
	}

	// Version 2+
	ip, err := selectPhantomImplHkdf(seed, genSubnets)
	if err != nil {
		return nil, err
	}
	return ip, nil
}

func subnetsByVersion(seed []byte, clientLibVer uint, genConfig *SubnetConfig) ([]*phantomNet, error) {

	if clientLibVer < core.PhantomHkdfMinVersion {
		// Version 0 or 1
		return genConfig.getSubnetsVarint(seed, true)
	} else {
		// Version 2
		return getSubnetsHkdf(genConfig, seed, true)
	}

}
