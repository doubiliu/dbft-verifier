package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"math/big"
	"testing"
	"time"
)

func TestVerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	parent := new(types.Header)
	err := parent.UnmarshalJSON([]byte(
		`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x2",
			"extraData": "0x0201072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76976d77c5cdebcce0c6e39cdd29d21ac54ad911720cf7fd28d7806515816587b95c6fc14588d93c564bd46ade8affac53aa75d3d4d2abcbc7363ead5d7ada2e9e2de20a40c8d78d440f23f36bd82638cad0039ce46bcfc86c380b643ed9ae38a801d9097e699a9b30306289388bedbc50fabb3633ec8e9d8596c5800d0dc6f3859c766170fb406915574fa81827a0c3d6",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0x70b8d2a8371cf83d94012459876d326fe236141ea2d8c04ccaa7ba5d4dad19a4",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0x8ff779018b306c26cf13c12aa70002ecb98e553f725049d81bfca73ca5141ec9",
			"nonce": "0x0000000000000002",
			"number": "0x3aac81",
			"parentHash": "0xa71dba8853d9a78570c223273b1baa54f1940da2ab6c65cec4a8e055b18a9e91",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x2db",
			"stateRoot": "0x73fa78a8689580ed7319392cb2f9d062acece70f938f9b9af6578e15c6ee4aeb",
			"timestamp": "0x6862306b",
			"totalDifficulty": "0x729861",
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
	))
	current := new(types.Header)
	err = current.UnmarshalJSON([]byte(
		`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x2",
			"extraData": "0x0201072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76976d77c5cdebcce0c6e39cdd29d21ac54ad911720cf7fd28d7806515816587b95c6fc14588d93c564bd46ade8affac53b509b7477d85c870d635371a054713ecff352b98261bac920963a7891d86537c8f3ea9f37ebf9bc7a325129f4b9bc47e064bd1ae1f588f62df3613b81c50680d81d7a754262d4027919c827834ce3676997a15b4adea6b387171afb7c65a13a8",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0x5ee3e44dbf6a87b798534efb870f63957c2d5b2ccda1b7360ea0159a403e738b",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0x8ff779018b306c26cf13c12aa70002ecb98e553f725049d81bfca73ca5141ec9",
			"nonce": "0x0000000000000003",
			"number": "0x3aac82",
			"parentHash": "0x70b8d2a8371cf83d94012459876d326fe236141ea2d8c04ccaa7ba5d4dad19a4",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x2db",
			"stateRoot": "0x73fa78a8689580ed7319392cb2f9d062acece70f938f9b9af6578e15c6ee4aeb",
			"timestamp": "0x68623070",
			"totalDifficulty": "0x729863",
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
	))
	pparent := GetHeaderParamter(parent)
	pcurrent := GetHeaderParamter(current)

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
	data, err := encodeSigHeader(current)
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
	rlpHashVerifyCcs, err := helper.ReadCCS("rlphash_css")
	if err != nil {
		panic(err)
	}
	var rlpHashVerifyVk groth16.VerifyingKey
	rlpHashVerifyVk, err = helper.ReadVerifyingKey("rlphash_vk")
	if err != nil {
		panic(err)
	}
	rlpKey, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashVerifyVk)
	if err != nil {
		panic(err)
	}
	var rlpHashVerifyPk groth16.ProvingKey
	rlpHashVerifyPk, err = helper.ReadProvingKey("rlphash_pk")
	if err != nil {
		panic(err)
	}
	start := time.Now()
	rlpHashVerifyProof1, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashVerifyCcs, &rlpHashVerifyPk, &rlpHashVerifyVk, parent)
	if err != nil {
		panic(err)
	}
	elapsed := time.Since(start)
	fmt.Printf("Parent RLP证明计算操作耗时：%s\n", elapsed)
	rlpProof1, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](*rlpHashVerifyProof1)
	if err != nil {
		panic(err)
	}
	start = time.Now()
	rlpHashVerifyProof2, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashVerifyCcs, &rlpHashVerifyPk, &rlpHashVerifyVk, current)
	if err != nil {
		panic(err)
	}
	elapsed = time.Since(start)
	fmt.Printf("Current RLP证明计算操作耗时：%s\n", elapsed)
	rlpProof2, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](*rlpHashVerifyProof2)
	if err != nil {
		panic(err)
	}
	toG2HashVerifyCcs, err := helper.ReadCCS("tog2hash_css")
	if err != nil {
		panic(err)
	}
	var toG2HashVerifyVk groth16.VerifyingKey
	toG2HashVerifyVk, err = helper.ReadVerifyingKey("tog2hash_vk")
	if err != nil {
		panic(err)
	}
	g2Key, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](toG2HashVerifyVk)
	if err != nil {
		panic(err)
	}
	var toG2HashVerifyPk groth16.ProvingKey
	toG2HashVerifyPk, err = helper.ReadProvingKey("tog2hash_pk")
	if err != nil {
		panic(err)
	}
	start = time.Now()
	tog2HashVerifyProof, _, err := ComputeToG2HashProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), toG2HashVerifyCcs, &toG2HashVerifyPk, &toG2HashVerifyVk, current)
	if err != nil {
		panic(err)
	}
	elapsed = time.Since(start)
	fmt.Printf("toG2Hash证明计算操作耗时：%s\n", elapsed)
	g2Proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](*tog2HashVerifyProof)
	if err != nil {
		panic(err)
	}

	pdata, err := encodeHeader(parent)
	if err != nil {
		panic(err)
	}
	pdata = common.BytesToHash(crypto.Keccak256(pdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var ParentHash [32]frontend.Variable
	for i := 0; i < len(ParentHash); i++ {
		ParentHash[i] = pdata[i]
	}
	cdata, err := encodeHeader(current)
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

	circuit := VerifyWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:        pparent,
		Current:       pcurrent,
		RLPHashVk:     rlpKey,
		RLPHashProof1: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyCcs),
		RLPHashProof2: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyCcs),
		ToG2HashVk:    g2Key,
		ToG2HashProof: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](toG2HashVerifyCcs),
	}

	assignment := VerifyWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
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
	//witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	/*	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			panic(err)
		}
		pk, vk, err := groth16.Setup(css)
		if err != nil {
			panic(err)
		}
		proof, err := groth16.Prove(css.(*cs.R1CS), pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
		if err != nil {
			panic(err)
		}
		publicWitness, err := witness.Public()
		if err != nil {
			panic(err)
		}
		err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))*/
	assert.NoError(err)
}

func ComputeRLPProof(field, outer *big.Int, innerccs constraint.ConstraintSystem, innerPK *groth16.ProvingKey, innerVK *groth16.VerifyingKey, header *types.Header) (*groth16.Proof, witness.Witness, error) {
	pheader := GetHeaderParamter(header)
	data, err := encodeHeader(header)
	if err != nil {
		panic(err)
	}
	data = common.BytesToHash(crypto.Keccak256(data)).Bytes()
	//fmt.Printf("%v\n", data)
	RLPHash := make([]frontend.Variable, len(data))
	for i := 0; i < len(RLPHash); i++ {
		RLPHash[i] = data[i]
	}
	serializeHeader := Serialize(pheader)
	input := make([]frontend.Variable, 0)
	input = append(input, RLPHash...)
	input = append(input, serializeHeader...)
	fmt.Println("rlpInput-out-circuit:")
	fmt.Println(input)
	innerAssignment := &HeaderRLPEncodeVerifyWrapper{
		input,
	}
	r1cs := innerccs.(*cs.R1CS)
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		return nil, nil, err
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		return nil, nil, err
	}
	innerProof, err := groth16.Prove(r1cs, *innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	err = groth16.Verify(innerProof, *innerVK, innerPubWitness, stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}

	return &innerProof, innerPubWitness, nil
}

func ComputeToG2HashProof(field, outer *big.Int, innerccs constraint.ConstraintSystem, innerPK *groth16.ProvingKey, innerVK *groth16.VerifyingKey, header *types.Header) (*groth16.Proof, witness.Witness, error) {
	cheader := GetHeaderParamter(header)
	data, err := encodeSigHeader(header)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v\n", data)
	hash, err := bls12381.HashToG2(data, BLSDomain)
	if err != nil {
		panic(err)
	}
	ToG2Hash := make([]frontend.Variable, len(hash.Bytes()))
	for i := 0; i < len(ToG2Hash); i++ {
		ToG2Hash[i] = hash.Bytes()[i]
	}
	serializeHeader := Serialize(cheader)
	input := make([]frontend.Variable, 0)
	input = append(input, ToG2Hash...)
	input = append(input, serializeHeader...)
	innerAssignment := &HeaderHashToG2VerifyWrapper{
		input,
	}
	r1cs := innerccs.(*cs.R1CS)
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		return nil, nil, err
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		return nil, nil, err
	}
	innerProof, err := groth16.Prove(r1cs, *innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	err = groth16.Verify(innerProof, *innerVK, innerPubWitness, stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}

	return &innerProof, innerPubWitness, nil
}
