package circuit

import (
	"crypto/sha256"
	"fmt"
	btc_ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/txhsl/neox-dbft-verifier/helper"

	"golang.org/x/crypto/sha3"
	"testing"
	"time"
)

func TestVerifyHeaderV0(t *testing.T) {
	parent, current := HeaderTestData(ExtraV0)
	parentParameters, err := GetHeaderParamter(parent)
	assert.NoError(t, err)
	currentParameters, err := GetHeaderParamter(current)
	assert.NoError(t, err)
	// we need to recover address and public keys
	addrBytes := current.Extra[HashableExtraV0Len : HashableExtraV0Len+7*common.AddressLength]
	sigBytes := current.Extra[HashableExtraV0Len+7*common.AddressLength:]
	addrs := make([]common.Address, 7)
	for i := range addrs {
		copy(addrs[i][:], addrBytes[i*common.AddressLength:(i+1)*common.AddressLength])
	}
	sigs := make([][]byte, 5)
	for i := range sigs {
		sigs[i] = sigBytes[i*crypto.SignatureLength : (i+1)*crypto.SignatureLength]
	}

	data, err := EncodeHeader(current, true)
	fmt.Println("sigHeader RLP: ", data)
	assert.NoError(t, err)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	//hash := crypto.Keccak256(data)
	fmt.Println("signature message hash: ", hash)
	noSigHashVar := make([]frontend.Variable, 0)
	for i := 0; i < len(hash); i++ {
		noSigHashVar = append(noSigHashVar, hash[i])
	}
	// recover pk from sig
	signers := make([]common.Address, len(sigs))
	addressIndices := make([]int, len(sigs))
	publicKeys := make([]ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(sigs))
	for i := range signers {
		btcsig := make([]byte, crypto.SignatureLength)
		btcsig[0] = sigs[i][64] + 27
		copy(btcsig[1:], sigs[i])
		pub, _, err := btc_ecdsa.RecoverCompact(btcsig, hash)
		assert.NoError(t, err)
		publicKeys[i] = publicKeyToVariable(*pub)
		pubBytes := pub.SerializeUncompressed()
		signers[i] = common.BytesToAddress(crypto.Keccak256(pubBytes[1:])[12:])
		flag := false
		for j := range addrs {
			if signers[i].Cmp(addrs[j]) == 0 {
				addressIndices[i] = j
				flag = true
			}
		}
		if !flag {
			assert.NoError(t, fmt.Errorf("invalid signature"))
		}
	}
	indexVariables := make([]frontend.Variable, len(addressIndices))
	for i := 0; i < len(indexVariables); i++ {
		indexVariables[i] = addressIndices[i]
	}

	rlpHashVerifyCcs, err := helper.ReadCCS("/root/neo/dbft-verifier/neox/cmd/meta/v1/rlp_encode_hash_extra_v0_test.ccs")
	if err != nil {
		panic(err)
	}
	var rlpHashVerifyVk groth16.VerifyingKey
	rlpHashVerifyVk, err = helper.ReadVerifyingKey("/root/neo/dbft-verifier/neox/cmd/meta/v1/rlp_encode_hash_extra_v0_test.vk")
	if err != nil {
		panic(err)
	}
	rlpKey, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashVerifyVk)
	if err != nil {
		panic(err)
	}
	var rlpHashVerifyPk groth16.ProvingKey
	rlpHashVerifyPk, err = helper.ReadProvingKey("/root/neo/dbft-verifier/neox/cmd/meta/v1/rlp_encode_hash_extra_v0_test.pk")
	if err != nil {
		panic(err)
	}
	start := time.Now()
	rlpHashVerifyProof1, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashVerifyCcs, rlpHashVerifyPk, rlpHashVerifyVk, parent, false)
	if err != nil {
		panic(err)
	}
	//rlpHashVerifyProof1 := readProof("rlp_hash_1_v0.proof")
	//err = writeProof(rlpHashVerifyProof1, "rlp_hash_1_v0.proof")
	assert.NoError(t, err)
	elapsed := time.Since(start)
	fmt.Printf("Parent RLP证明计算操作耗时：%s\n", elapsed)
	rlpProof1, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyProof1)
	if err != nil {
		panic(err)
	}
	//rlpHashVerifyProof2 := readProof("rlp_hash_2_v0.proof")
	start = time.Now()
	rlpHashVerifyProof2, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashVerifyCcs, rlpHashVerifyPk, rlpHashVerifyVk, current, false)
	if err != nil {
		panic(err)
	}
	//err = writeProof(rlpHashVerifyProof2, "rlp_hash_2_v0.proof")
	//assert.NoError(t, err)
	elapsed = time.Since(start)
	fmt.Printf("Current RLP证明计算操作耗时：%s\n", elapsed)
	rlpProof2, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyProof2)
	if err != nil {
		panic(err)
	}

	noSigHashCCS, err := helper.ReadCCS("rlp_encode_hash_no_sig_extra_v0.ccs")
	if err != nil {
		panic(err)
	}
	var noSigHashVk groth16.VerifyingKey
	noSigHashVk, err = helper.ReadVerifyingKey("rlp_encode_hash_no_sig_extra_v0.vk")
	if err != nil {
		panic(err)
	}
	noSigKey, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](noSigHashVk)
	if err != nil {
		panic(err)
	}
	var noSigHashPk groth16.ProvingKey
	noSigHashPk, err = helper.ReadProvingKey("rlp_encode_hash_no_sig_extra_v0.pk")
	if err != nil {
		panic(err)
	}
	start = time.Now()
	noSigHashProof, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), noSigHashCCS, noSigHashPk, noSigHashVk, current, true)
	if err != nil {
		panic(err)
	}
	//err = writeProof(noSigHashProof, "no_sig_rlp_hash_v0.proof")
	assert.NoError(t, err)
	elapsed = time.Since(start)
	fmt.Printf("NoSigHash证明计算操作耗时：%s\n", elapsed)
	//noSigHashProof := readProof("no_sig_rlp_hash_v0.proof")
	noSigProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](noSigHashProof)
	if err != nil {
		panic(err)
	}
	pdata, err := EncodeHeader(parent, false)
	if err != nil {
		panic(err)
	}
	pdata = common.BytesToHash(crypto.Keccak256(pdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var ParentHash [32]frontend.Variable
	for i := 0; i < len(ParentHash); i++ {
		ParentHash[i] = pdata[i]
	}
	cdata, err := EncodeHeader(current, false)
	if err != nil {
		panic(err)
	}
	cdata = common.BytesToHash(crypto.Keccak256(cdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var CurrentHash [32]frontend.Variable
	for i := 0; i < len(CurrentHash); i++ {
		CurrentHash[i] = cdata[i]
	}
	var MixDigest [32]frontend.Variable
	for i := 0; i < len(MixDigest); i++ {
		MixDigest[i] = current.MixDigest[i]
	}
	circuit := ExtraV0HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:         parentParameters,
		Current:        currentParameters,
		RLPHashProof1:  rlpProof1,
		RLPHashProof2:  rlpProof2,
		RLPHashVk:      rlpKey,
		NoSigHashProof: noSigProof,
		NoSigHashVk:    noSigKey,
		PublicKeys:     publicKeys,
		AddressIndices: indexVariables,
	}
	assignment := ExtraV0HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:         parentParameters,
		Current:        currentParameters,
		RLPHashProof1:  rlpProof1,
		RLPHashProof2:  rlpProof2,
		RLPHashVk:      rlpKey,
		NoSigHashProof: noSigProof,
		NoSigHashVk:    noSigKey,
		NoSigHash:      [32]frontend.Variable(noSigHashVar),
		PublicKeys:     publicKeys,
		AddressIndices: indexVariables,
		ParentHash:     ParentHash,
		CurrentHash:    CurrentHash,
		MixDigest:      MixDigest,
	}

	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println(ccs.GetNbConstraints())

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	//pk, err := helper.ReadProvingKey("rlp_encode_hash_extra_v0.pk")
	//if err != nil {
	//	panic(err)
	//}
	//vk, err := helper.ReadVerifyingKey("rlp_encode_hash_extra_v0.vk")
	//if err != nil {
	//	panic(err)
	//}
	proof, err := groth16.Prove(ccs, pk, w, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}
	publicWitness, err := w.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	helper.ExportCCS(ccs, "verify_header_extra_v0.ccs")
	helper.ExportProvingKey(pk.(*groth16_bn254.ProvingKey), "verify_header_extra_v0.pk")
	helper.ExportVerifyingKey(vk.(*groth16_bn254.VerifyingKey), "verify_header_extra_v0.vk")
	proofData, cmts, cmtPok := helper.GetGroth16ContractInput(proof.(*groth16_bn254.Proof))
	// proof.Ar, proof.Bs, proof.Krs
	fmt.Printf("Proof:")
	for i := 0; i < 8; i++ {
		fmt.Printf(proofData[i].String())
	}
	fmt.Println()
	// commitments
	fmt.Printf("Commitments:")
	for i := 0; i < len(cmts); i++ {
		fmt.Printf(cmts[i].String())
	}
	fmt.Println()
	// commitmentPok
	fmt.Printf("CommitmentPok:")
	for i := 0; i < len(cmtPok); i++ {
		fmt.Printf(cmtPok[i].String())
	}
	//err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	//if err != nil {
	//	panic(err)
	//}
	assert.NoError(t, err)
}

func TestVerifyHeaderV1OrV2(t *testing.T) {
	assert := test.NewAssert(t)
	extraVersion := ExtraV1
	parent := new(types.Header)
	parent, current := HeaderTestData(extraVersion)
	pparent, err := GetHeaderParamter(parent)
	assert.NoError(err)
	pcurrent, err := GetHeaderParamter(current)
	assert.NoError(err)
	pubBytes := current.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
	sigBytes := current.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]
	var pub bls12381.G1Affine
	_, err = pub.SetBytes(pubBytes)
	if err != nil {
		panic(err)
	}
	_, _, g1, _ := bls12381.Generators()
	g1.Neg(&g1)
	var sig bls12381.G2Affine
	_, err = sig.SetBytes(sigBytes)
	data, err := EncodeHeader(current, true)
	if err != nil {
		panic(err)
	}
	hash, _ := bls12381.HashToG2(data, BLSDomain)
	hashBytes := hash.Bytes()
	var ToG2Hash [96]frontend.Variable
	for i := 0; i < len(ToG2Hash); i++ {
		ToG2Hash[i] = hashBytes[i]
	}
	//slices.Reverse(ToG2Hash)
	rlpHashVerifyCcs, err := helper.ReadCCS("/root/neo/dbft-verifier/neox/cmd/meta/v1/rlp_encode_hash_extra_v1_test.ccs")
	if err != nil {
		panic(err)
	}
	var rlpHashVerifyVk groth16.VerifyingKey
	rlpHashVerifyVk, err = helper.ReadVerifyingKey("/root/neo/dbft-verifier/neox/cmd/meta/v1/rlp_encode_hash_extra_v1_test.vk")
	if err != nil {
		panic(err)
	}
	//rlpKey, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashVerifyVk)
	//if err != nil {
	//	panic(err)
	//}
	var rlpHashVerifyPk groth16.ProvingKey
	rlpHashVerifyPk, err = helper.ReadProvingKey("/root/neo/dbft-verifier/neox/cmd/meta/v1/rlp_encode_hash_extra_v1_test.pk")
	if err != nil {
		panic(err)
	}
	start := time.Now()
	rlpHashVerifyProof1, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashVerifyCcs, rlpHashVerifyPk, rlpHashVerifyVk, parent, false)
	if err != nil {
		panic(err)
	}
	//rlpHashVerifyProof1 := readProof("rlp_hash_1_v1.proof")
	//err = writeProof(rlpHashVerifyProof1, "rlp_hash_1_v1.proof")
	assert.NoError(err)
	elapsed := time.Since(start)
	fmt.Printf("Parent RLP证明计算操作耗时：%s\n", elapsed)
	rlpProof1, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyProof1)
	if err != nil {
		panic(err)
	}
	//rlpHashVerifyProof2 := readProof("rlp_hash_2_v1.proof")
	start = time.Now()
	rlpHashVerifyProof2, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashVerifyCcs, rlpHashVerifyPk, rlpHashVerifyVk, current, false)
	if err != nil {
		panic(err)
	}
	//err = writeProof(rlpHashVerifyProof2, "rlp_hash_2_v1.proof")
	assert.NoError(err)
	elapsed = time.Since(start)
	fmt.Printf("Current RLP证明计算操作耗时：%s\n", elapsed)
	rlpProof2, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyProof2)
	if err != nil {
		panic(err)
	}
	toG2HashVerifyCcs, err := helper.ReadCCS("/root/neo/dbft-verifier/neox/cmd/meta/v1/to_g2_hash.ccs")
	if err != nil {
		panic(err)
	}
	var toG2HashVerifyVk groth16.VerifyingKey
	toG2HashVerifyVk, err = helper.ReadVerifyingKey("/root/neo/dbft-verifier/neox/cmd/meta/v1/to_g2_hash.vk")
	if err != nil {
		panic(err)
	}
	//g2Key, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](toG2HashVerifyVk)
	//if err != nil {
	//	panic(err)
	//}
	var toG2HashVerifyPk groth16.ProvingKey
	toG2HashVerifyPk, err = helper.ReadProvingKey("/root/neo/dbft-verifier/neox/cmd/meta/v1/to_g2_hash.pk")
	if err != nil {
		panic(err)
	}
	start = time.Now()
	tog2HashVerifyProof, _, err := ComputeToG2HashProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), toG2HashVerifyCcs, toG2HashVerifyPk, toG2HashVerifyVk, current)
	if err != nil {
		panic(err)
	}
	//err = writeProof(tog2HashVerifyProof, "to_g2_hash.proof")
	assert.NoError(err)
	elapsed = time.Since(start)
	fmt.Printf("toG2Hash证明计算操作耗时：%s\n", elapsed)
	//tog2HashVerifyProof := readProof("to_g2_hash.proof")
	g2Proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](tog2HashVerifyProof)
	if err != nil {
		panic(err)
	}

	pdata, err := EncodeHeader(parent, false)
	if err != nil {
		panic(err)
	}
	pdata = common.BytesToHash(crypto.Keccak256(pdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var ParentHash [32]frontend.Variable
	for i := 0; i < len(ParentHash); i++ {
		ParentHash[i] = pdata[i]
	}
	cdata, err := EncodeHeader(current, false)
	if err != nil {
		panic(err)
	}
	cdata = common.BytesToHash(crypto.Keccak256(cdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var CurrentHash [32]frontend.Variable
	for i := 0; i < len(CurrentHash); i++ {
		CurrentHash[i] = cdata[i]
	}
	var MixDigest [32]frontend.Variable
	for i := 0; i < len(MixDigest); i++ {
		MixDigest[i] = current.MixDigest[i]
	}

	//circuit := ExtraV1OrV2HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
	//	Parent:        pparent,
	//	Current:       pcurrent,
	//	RLPHashVk:     rlpKey,
	//	RLPHashProof1: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyCcs),
	//	RLPHashProof2: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyCcs),
	//	ToG2HashVk:    g2Key,
	//	ToG2HashProof: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](toG2HashVerifyCcs),
	//}

	assignment := ExtraV1OrV2HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:        pparent,
		Current:       pcurrent,
		RLPHashProof1: rlpProof1,
		RLPHashProof2: rlpProof2,
		ToG2HashProof: g2Proof,
		ToG2Hash:      ToG2Hash,
		ParentHash:    ParentHash,
		CurrentHash:   CurrentHash,
		MixDigest:     MixDigest,
	}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	//err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	//if err != nil {
	//	panic(err)
	//}
	ccs, err := helper.ReadCCS("/root/neo/dbft-verifier/neox/cmd/meta/v1/verify_header_extra_v1.ccs")
	//ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println(ccs.GetNbConstraints())
	//pk, vk, err := groth16.Setup(ccs)
	//if err != nil {
	//	panic(err)
	//}
	pk, err := helper.ReadProvingKey("/root/neo/dbft-verifier/neox/cmd/meta/v1/verify_header_extra_v1.pk")
	if err != nil {
		panic(err)
	}
	vk, err := helper.ReadVerifyingKey("/root/neo/dbft-verifier/neox/cmd/meta/v1/verify_header_extra_v1.vk")
	if err != nil {
		panic(err)
	}

	start = time.Now()
	proof, err := groth16.Prove(ccs, pk, w, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify V1 Header Time: ", time.Since(start))
	publicWitness, err := w.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	assert.NoError(err)
	//err = helper.ExportCCS(ccs, "verify_header_extra_v1.ccs")
	//assert.NoError(err)
	//err = helper.ExportProvingKey(pk.(*groth16_bn254.ProvingKey), "verify_header_extra_v1.pk")
	//assert.NoError(err)
	//err = helper.ExportVerifyingKey(vk.(*groth16_bn254.VerifyingKey), "verify_header_extra_v1.vk")
	//assert.NoError(err)
	helper.GetGroth16ContractInput(proof.(*groth16_bn254.Proof))
}
