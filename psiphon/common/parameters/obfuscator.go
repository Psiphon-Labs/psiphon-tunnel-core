package parameters

import (
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func NewOSSHPrefixSpecParameters(p ParametersAccessor, dialPortNumber string) (*obfuscator.OSSHPrefixSpec, error) {

	seed, err := prng.NewSeed()
	if err != nil {
		return nil, errors.Trace(err)
	}

	if !p.WeightedCoinFlip(OSSHPrefixProbability) {
		return &obfuscator.OSSHPrefixSpec{}, nil
	}

	specs := p.ProtocolTransformSpecs(OSSHPrefixSpecs)
	scopedSpecNames := p.ProtocolTransformScopedSpecNames(OSSHPrefixScopedSpecNames)

	name, spec := specs.Select(dialPortNumber, scopedSpecNames)

	if spec == nil {
		return &obfuscator.OSSHPrefixSpec{}, nil
	} else {
		return &obfuscator.OSSHPrefixSpec{
			Name: name,
			Spec: spec,
			Seed: seed,
		}, nil
	}
}

func NewOSSHPrefixSplitConfig(p ParametersAccessor) (*obfuscator.OSSHPrefixSplitConfig, error) {

	seed, err := prng.NewSeed()
	if err != nil {
		return nil, errors.Trace(err)
	}

	minDelay := p.Duration(OSSHPrefixSplitMinDelay)
	maxDelay := p.Duration(OSSHPrefixSplitMaxDelay)

	return &obfuscator.OSSHPrefixSplitConfig{
		Seed:     seed,
		MinDelay: minDelay,
		MaxDelay: maxDelay,
	}, nil
}
