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
)

func TestVerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	parent := new(types.Header)
	err := parent.UnmarshalJSON([]byte(
		`{
    "baseFeePerGas": "0x4a817c800",
    "difficulty": "0x2",
    "extraData": "0x0101072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76a5b5119bdcba3022c77f07b13bea98239781492b075fb8a1dff6895377dcd5251c3134660c973244d84101814ad14fa9a6605298b06a5c70c969ee5c1357236cbe9b7b65ee59f567e95d6a8fe0966175676170c0ecf174ef6ad701574d7b7d1a099068d29ac7662e20a2ae74898d19b93966d89314946745860d47c59c38208f83b50013414845cb5706840426f45b2c",
    "gasLimit": "0x1c9c380",
    "gasUsed": "0x0",
    "hash": "0xecd8bd1c514fd33d9e01184783af6f2dd58f3a213b294fe8019aab5271140633",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "miner": "0x1212000000000000000000000000000000000003",
    "mixHash": "0xc1a8ea569ae7daff411094c088d4dd58cd439d241d9c31af61a537c6505761a5",
    "nonce": "0x0000000000000005",
    "number": "0x2970d9",
    "parentHash": "0x59db04b079ab47dde8736b231469db4e4a1ca2c9fc8e251bf41cf3c336facefe",
    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "size": "0x2db",
    "stateRoot": "0xf675a08553de3363c8abc70879a9cc6ca6c6be517ae21a7f6601835fb6181ff9",
    "timestamp": "0x680b3b51",
    "totalDifficulty": "0x5023a5",
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
    "extraData": "0x0101072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76a5b5119bdcba3022c77f07b13bea98239781492b075fb8a1dff6895377dcd5251c3134660c973244d84101814ad14fa9a2267aebbca32f4f307ffe32c1d387b78585335d413747522953d7eccdfdb54fec71d9c8d28ce456ce51fadbf3dd059a15c42c964250c71107c987966a23d49f086cadf981f812d8deab403047cd8b8438fc8ca79cb6ee9290b3780f80007838",
    "gasLimit": "0x1c9c380",
    "gasUsed": "0x0",
    "hash": "0x72273a91d87952260ff37c86839d69d1e1b6d3bbfc6e00a55198950bbcf182dc",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "miner": "0x1212000000000000000000000000000000000003",
    "mixHash": "0xc1a8ea569ae7daff411094c088d4dd58cd439d241d9c31af61a537c6505761a5",
    "nonce": "0x0000000000000006",
    "number": "0x2970da",
    "parentHash": "0xecd8bd1c514fd33d9e01184783af6f2dd58f3a213b294fe8019aab5271140633",
    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "size": "0x2db",
    "stateRoot": "0xf675a08553de3363c8abc70879a9cc6ca6c6be517ae21a7f6601835fb6181ff9",
    "timestamp": "0x680b3b56",
    "totalDifficulty": "0x5023a7",
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
	ToG2Hash := make([]frontend.Variable, len(hash.Bytes()))
	for i := 0; i < len(ToG2Hash); i++ {
		ToG2Hash[i] = data[i]
	}

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
	rlpHashVerifyProof, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashVerifyCcs, &rlpHashVerifyPk, &rlpHashVerifyVk, parent)
	if err != nil {
		panic(err)
	}
	rlpProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](*rlpHashVerifyProof)
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
	tog2HashVerifyProof, _, err := ComputeToG2HashProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), toG2HashVerifyCcs, &toG2HashVerifyPk, &toG2HashVerifyVk, current)
	if err != nil {
		panic(err)
	}
	g2Proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](*tog2HashVerifyProof)
	if err != nil {
		panic(err)
	}
	circuit := VerifyWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:        pparent,
		Current:       pcurrent,
		RLPHashVk:     rlpKey,
		RLPHashProof:  stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyCcs),
		ToG2HashVk:    g2Key,
		ToG2HashProof: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](toG2HashVerifyCcs),
		ToG2Hash:      make([]frontend.Variable, 96),
	}

	assignment := VerifyWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:        pparent,
		Current:       pcurrent,
		RLPHashProof:  rlpProof,
		ToG2HashProof: g2Proof,
		ToG2Hash:      ToG2Hash,
		/*		Hash:    sw_bls12381.NewG2Affine(hash),
				Sig:     sw_bls12381.NewG2Affine(sig),
				Pub:     sw_bls12381.NewG1Affine(pub),*/
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
