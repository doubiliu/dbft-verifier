package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/stretchr/testify/assert"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"github.com/txhsl/neox-dbft-verifier/mod"
	"testing"
	"time"
)

func TestVerifyHeaderV0(t *testing.T) {
	parent, current := HeaderTestData(ExtraV0)
	rlpHashInstanceConfig := mod.InstanceConfig{
		CcsPath: "../../cmd/meta/test/v0/rlp_encode_hash_extra_v0_test.ccs",
		PkPath:  "../../cmd/meta/test/v0/rlp_encode_hash_extra_v0_test.pk",
		VkPath:  "../../cmd/meta/test/v0/rlp_encode_hash_extra_v0_test.vk",
	}
	rlpHashInstance, err := mod.LoadFromInstanceConfig(rlpHashInstanceConfig)
	assert.NoError(t, err)
	noSigHashInstanceConfig := mod.InstanceConfig{
		CcsPath: "../../cmd/meta/test/v0/rlp_encode_noSig_hash_extra_v0_test.ccs",
		PkPath:  "../../cmd/meta/test/v0/rlp_encode_noSig_hash_extra_v0_test.pk",
		VkPath:  "../../cmd/meta/test/v0/rlp_encode_noSig_hash_extra_v0_test.vk",
	}
	noSigHashInstance, err := mod.LoadFromInstanceConfig(noSigHashInstanceConfig)
	assert.NoError(t, err)
	computeParentRlpHashProof := func() (groth16.Proof, error) {
		start := time.Now()
		rlpHashVerifyProof1, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashInstance.Ccs, rlpHashInstance.Pk, rlpHashInstance.Vk, parent, false)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Parent RLP证明计算操作耗时：%s\n", time.Since(start))
		return rlpHashVerifyProof1, nil
	}
	computeCurrentRlpHashProof := func() (groth16.Proof, error) {
		start := time.Now()
		rlpHashVerifyProof2, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashInstance.Ccs, rlpHashInstance.Pk, rlpHashInstance.Vk, current, false)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Current RLP证明计算操作耗时：%s\n", time.Since(start))
		return rlpHashVerifyProof2, err
	}
	computeNoSigHashProof := func() (groth16.Proof, error) {
		start := time.Now()
		noSigHashProof, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), noSigHashInstance.Ccs, noSigHashInstance.Pk, noSigHashInstance.Vk, current, true)
		if err != nil {
			return nil, err
		}
		fmt.Printf("NoSigHash证明计算操作耗时：%s\n", time.Since(start))
		return noSigHashProof, nil
	}

	headerGenerator := func() ([]circuit.HashableBlockHeader, error) {
		return []circuit.HashableBlockHeader{NewNeoxBlockHeader(parent), NewNeoxBlockHeader(current)}, nil
	}
	ct, err := new(ExtraV0HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]).Circuit(
		headerGenerator,
		rlpHashInstance.Ccs, noSigHashInstance.Ccs,
		rlpHashInstance.Vk, noSigHashInstance.Vk,
	)
	assert.NoError(t, err)
	assignment, err := new(ExtraV0HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]).Assignment(
		headerGenerator,
		computeParentRlpHashProof, computeCurrentRlpHashProof, computeNoSigHashProof,
	)
	assert.NoError(t, err)

	verifierInstanceConfig := mod.InstanceConfig{
		CcsPath: "../../cmd/meta/test/v0/verifier_header_extra_v0.ccs",
		PkPath:  "../../cmd/meta/test/v0/verifier_header_extra_v0.pk",
		VkPath:  "../../cmd/meta/test/v0/verifier_header_extra_v0.vk",
	}
	//instance, err := mod.LoadFromInstanceConfig(verifierInstanceConfig)
	//assert.NoError(t, err)
	ccs, pk, vk, err := helper.TrustedLocalSetup(ct, assignment)
	assert.NoError(t, err)
	assert.NoError(t, ExportCircuitInstance(mod.PackedCircuitInstance{Ccs: ccs, Pk: pk, Vk: vk}, verifierInstanceConfig))
}

func TestVerifyHeaderV1OrV2(t *testing.T) {
	extraVersion := ExtraV1
	parent, current := HeaderTestData(extraVersion)
	rlpHashInstanceConfig := mod.InstanceConfig{
		CcsPath: "../../cmd/meta/test/v1/rlp_encode_hash_extra_v1_test.ccs",
		PkPath:  "../../cmd/meta/test/v1/rlp_encode_hash_extra_v1_test.pk",
		VkPath:  "../../cmd/meta/test/v1/rlp_encode_hash_extra_v1_test.vk",
	}
	rlpHashInstance, err := mod.LoadFromInstanceConfig(rlpHashInstanceConfig)
	assert.NoError(t, err)
	toG2HashInstanceConfig := mod.InstanceConfig{
		CcsPath: "../../cmd/meta/test/v1/to_g2_hash.ccs",
		PkPath:  "../../cmd/meta/test/v1/to_g2_hash.pk",
		VkPath:  "../../cmd/meta/test/v1/to_g2_hash.vk",
	}
	toG2HashInstance, err := mod.LoadFromInstanceConfig(toG2HashInstanceConfig)
	assert.NoError(t, err)
	computeParentRlpHashProof := func() (groth16.Proof, error) {
		start := time.Now()
		rlpHashVerifyProof1, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashInstance.Ccs, rlpHashInstance.Pk, rlpHashInstance.Vk, parent, false)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Parent RLP证明计算操作耗时：%s\n", time.Since(start))
		return rlpHashVerifyProof1, nil
	}
	computeCurrentRlpHashProof := func() (groth16.Proof, error) {
		start := time.Now()
		rlpHashVerifyProof2, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashInstance.Ccs, rlpHashInstance.Pk, rlpHashInstance.Vk, current, false)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Current RLP证明计算操作耗时：%s\n", time.Since(start))
		return rlpHashVerifyProof2, nil
	}
	computeToG2HashProof := func() (groth16.Proof, error) {
		start := time.Now()
		tog2HashVerifyProof, _, err := ComputeToG2HashProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), toG2HashInstance.Ccs, toG2HashInstance.Pk, toG2HashInstance.Vk, current)
		if err != nil {
			return nil, err
		}
		fmt.Printf("toG2Hash证明计算操作耗时：%s\n", time.Since(start))
		return tog2HashVerifyProof, nil
	}
	headerGenerator := func() ([]circuit.HashableBlockHeader, error) {
		return []circuit.HashableBlockHeader{NewNeoxBlockHeader(parent), NewNeoxBlockHeader(current)}, nil
	}
	//ct, err := new(ExtraV1OrV2HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]).Circuit(
	//	headerGenerator,
	//	rlpHashInstance.Ccs, toG2HashInstance.Ccs,
	//	rlpHashInstance.Vk, toG2HashInstance.Vk,
	//)
	//assert.NoError(t, err)
	assignment, err := new(ExtraV1OrV2HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]).Assignment(
		headerGenerator,
		computeParentRlpHashProof, computeCurrentRlpHashProof, computeToG2HashProof,
	)
	assert.NoError(t, err)
	verifierInstanceConfig := mod.InstanceConfig{
		CcsPath: "../../cmd/meta/test/v1/verifier_header_extra_v1.ccs",
		PkPath:  "../../cmd/meta/test/v1/verifier_header_extra_v1.pk",
		VkPath:  "../../cmd/meta/test/v1/verifier_header_extra_v1.vk",
	}
	assert.NoError(t, err)
	//ccs, pk, vk, err := helper.TrustedLocalSetup(ct, assignment)
	//assert.NoError(t, err)
	//assert.NoError(t, mod.ExportCircuitInstance(mod.PackedCircuitInstance{Ccs: ccs, Pk: pk, Vk: vk}, verifierInstanceConfig))

	// if has been setup
	instance, err := mod.LoadFromInstanceConfig(verifierInstanceConfig)
	assert.NoError(t, err)
	assert.NoError(t, helper.ProveCircuit(instance.Ccs, instance.Pk, instance.Vk, assignment))
}
