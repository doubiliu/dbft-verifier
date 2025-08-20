package n3

import (
	"github.com/stretchr/testify/assert"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"github.com/txhsl/neox-dbft-verifier/mod"
	"testing"
)

func TestVerifyHeader(t *testing.T) {
	network, parent, current := HeaderTestData()
	verifierInstanceConfig := mod.InstanceConfig{
		CcsPath: "../../cmd/meta/n3/verifier_header.ccs",
		PkPath:  "../../cmd/meta/n3/verifier_header.pk",
		VkPath:  "../../cmd/meta/n3/verifier_header.vk",
	}
	//ct, err := new(N3VerifyHeaderWrapper).Circuit(
	//	func() ([]circuit.HashableBlockHeader, error) {
	//		return []circuit.HashableBlockHeader{NewN3BlockHeader(parent), NewN3BlockHeader(current)}, nil
	//	}, network)
	//assert.NoError(t, err)
	assignment, err := new(N3VerifyHeaderWrapper).Assignment(
		func() ([]circuit.HashableBlockHeader, error) {
			return []circuit.HashableBlockHeader{NewN3BlockHeader(parent), NewN3BlockHeader(current)}, nil
		}, network)
	assert.NoError(t, err)
	//ccs, pk, vk, err := helper.TrustedLocalSetup(ct, assignment)
	//assert.NoError(t, err)
	//assert.NoError(t, mod.ExportCircuitInstance(mod.PackedCircuitInstance{Ccs: ccs, Pk: pk, Vk: vk}, verifierInstanceConfig))
	instance, err := mod.LoadFromInstanceConfig(verifierInstanceConfig)
	assert.NoError(t, err)
	assert.NoError(t, helper.ProveCircuit(instance.Ccs, instance.Pk, instance.Vk, assignment))
}
