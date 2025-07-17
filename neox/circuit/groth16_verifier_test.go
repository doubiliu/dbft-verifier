package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"math/big"
	"os"
	"testing"
)

func TestGroth16RlpVerifier(t *testing.T) {

	_, current := HeaderTestData(ExtraV1)
	//pparent := GetHeaderParamter(parent)
	pcurrent, err := GetCompressedHeaderParameters(current)
	if err != nil {
		t.Fatal(err)
	}
	pdata, err := encodeHeader(current, false)
	if err != nil {
		panic(err)
	}
	pdata = common.BytesToHash(crypto.Keccak256(pdata)).Bytes()
	//fmt.Printf("%v\n", data)
	r1 := new(big.Int).SetBytes(pdata[:16])
	r2 := new(big.Int).SetBytes(pdata[16:])
	readProof := func(filepath string) groth16.Proof {
		file, err := os.Open(filepath)
		if err != nil {
			panic(err)
		}
		proof := groth16.NewProof(ecc.BN254)
		_, err = proof.ReadFrom(file)
		if err != nil {
			panic(err)
		}
		return proof
	}
	rlpHashVerifyCcs, err := helper.ReadCCS("rlp_encode_hash_extra_v1_test.ccs")
	if err != nil {
		panic(err)
	}
	var rlpHashVerifyVk groth16.VerifyingKey
	rlpHashVerifyVk, err = helper.ReadVerifyingKey("rlp_encode_hash_extra_v1_test.vk")
	if err != nil {
		panic(err)
	}
	rlpKey, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashVerifyVk)
	if err != nil {
		panic(err)
	}
	rlpHashVerifyProof1 := readProof("rlp_hash_2_v1.proof")
	rlpProof1, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyProof1)
	if err != nil {
		panic(err)
	}
	circuit := Groth16RlpVerifyWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:        stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyCcs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashVerifyCcs),
		//PublicInputs: make([]frontend.Variable, len(publicWitness)),
		//RlpHash:     [2]frontend.Variable{},
		//BlockNumber: 0,
		//Timestamp:   0,
		Current: pcurrent,
		Hash:    make([]frontend.Variable, 2),
	}
	assignment := Groth16RlpVerifyWrapper[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:        rlpProof1,
		VerifyingKey: rlpKey,
		Current:      pcurrent,
		Hash:         []frontend.Variable{r1, r2},
		//PublicInputs: publicWitness,
	}
	//fmt.Println(assignment)
	//ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println(ccs.GetNbConstraints())
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(t, err)
}

type Groth16RlpVerifyWrapper[Fr emulated.FieldParams, G1 algebra.G1ElementT, G2 algebra.G2ElementT, GT algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1, G2]
	VerifyingKey stdgroth16.VerifyingKey[G1, G2, GT]
	//RlpHash      [2]frontend.Variable
	//BlockNumber  frontend.Variable
	//Timestamp    frontend.Variable
	Current CompressHeaderParameters
	Hash    []frontend.Variable
}

func (c *Groth16RlpVerifyWrapper[Fr, G1, G2, GT]) Define(api frontend.API) error {
	//verifier := NewVerify[Fr, G1, G2, GT](api)
	//return verifier.Verify2(c.Current, c.Parent, c.Proof, c.VerifyingKey)
	verifier := NewGroth16Verifier[Fr, G1, G2, GT](api)
	//to verify parentHash=rlpencode(parent header) in sub-circuit
	input := make([]frontend.Variable, 0)
	//input = append(input, c.RlpHash[:]...)
	//input = append(input, c.BlockNumber)
	//input = append(input, c.Timestamp)
	input = append(input, c.Hash[:]...)
	input = append(input, c.Current.Serialize()...)
	fmt.Println(len(input))
	return verifier.Verify(c.Proof, c.VerifyingKey, input)
}
