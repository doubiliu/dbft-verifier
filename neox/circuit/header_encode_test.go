package circuit

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"math/big"
	"testing"
)

func TestHeaderEncoderV0(t *testing.T) {
	assert := test.NewAssert(t)
	_, current := HeaderTestData(ExtraV0)
	pheader, err := GetHeaderParamter(current)

	data, err := encodeHeader(current, false)
	//data, err := encodeSigHeader(header)
	if err != nil {
		panic(err)
	}
	fmt.Println("out of circuit encode：", data)
	data = common.BytesToHash(crypto.Keccak256(data)).Bytes()
	Data := make([]frontend.Variable, len(data))
	fmt.Println("out of circuit rlpHash", data)
	for i := 0; i < len(Data); i++ {
		Data[i] = data[i]
	}
	circuit := HeaderEncoderWrapper{
		Header:       pheader,
		Data:         make([]frontend.Variable, len(data)),
		ExtraVersion: ExtraV0,
	}
	witness := HeaderEncoderWrapper{
		Header:       pheader,
		Data:         Data,
		ExtraVersion: ExtraV0,
	}

	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)

}
func TestHeaderEncoderV1(t *testing.T) {
	assert := test.NewAssert(t)
	_, current := HeaderTestData(ExtraV1)
	pheader, err := GetHeaderParamter(current)

	data, err := encodeHeader(current, false)
	//data, err := encodeSigHeader(header)
	if err != nil {
		panic(err)
	}
	fmt.Println("out of circuit encode：", data)
	data = common.BytesToHash(crypto.Keccak256(data)).Bytes()
	Data := make([]frontend.Variable, len(data))
	fmt.Println("out of circuit rlpHash", data)
	for i := 0; i < len(Data); i++ {
		Data[i] = data[i]
	}
	circuit := HeaderEncoderWrapper{
		Header:       pheader,
		Data:         make([]frontend.Variable, len(data)),
		ExtraVersion: ExtraV1,
	}
	witness := HeaderEncoderWrapper{
		Header:       pheader,
		Data:         Data,
		ExtraVersion: ExtraV1,
	}

	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)
}
func TestHeaderEncoderV2(t *testing.T) {
	assert := test.NewAssert(t)
	_, current := HeaderTestData(ExtraV2)
	pheader, err := GetHeaderParamter(current)

	data, err := encodeHeader(current, false)
	//data, err := encodeSigHeader(header)
	if err != nil {
		panic(err)
	}
	fmt.Println("out of circuit encode：", data)
	data = common.BytesToHash(crypto.Keccak256(data)).Bytes()
	Data := make([]frontend.Variable, len(data))
	fmt.Println("out of circuit rlpHash", data)
	for i := 0; i < len(Data); i++ {
		Data[i] = data[i]
	}
	circuit := HeaderEncoderWrapper{
		Header:       pheader,
		Data:         make([]frontend.Variable, len(data)),
		ExtraVersion: ExtraV2,
	}
	witness := HeaderEncoderWrapper{
		Header:       pheader,
		Data:         Data,
		ExtraVersion: ExtraV2,
	}

	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)
}

func TestRLPEncodeVerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	extraVersion := ExtraV0
	header, _ := HeaderTestData(extraVersion)
	pheader, err := GetCompressedHeaderParameters(header)
	assert.NoError(err)
	data, err := encodeHeader(header, false)
	if err != nil {
		panic(err)
	}
	data = common.BytesToHash(crypto.Keccak256(data)).Bytes()
	r1 := new(big.Int).SetBytes(data[:16])
	r2 := new(big.Int).SetBytes(data[16:])

	circuit := HeaderRLPEncodeVerifyWrapper{
		Header:       pheader,
		RlpHash:      [2]frontend.Variable{0, 0},
		extraVersion: extraVersion,
		isNoSig:      false,
	}
	assignment := HeaderRLPEncodeVerifyWrapper{
		Header:       pheader,
		RlpHash:      [2]frontend.Variable{r1, r2},
		extraVersion: extraVersion,
		isNoSig:      false,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	//ccs, err := helper.ReadCCS("rlp_encode_hash_extra_v0.ccs")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println(ccs.GetNbConstraints())
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	var version string
	switch extraVersion {
	case ExtraV0:
		version = "extra_v0"
	case ExtraV1:
		version = "extra_v1"
	case ExtraV2:
		version = "extra_v2"
	default:
		panic("invalid extraVersion")
	}
	helper.ExportCCS(ccs, fmt.Sprintf("rlp_encode_hash_%s_test.ccs", version))
	helper.ExportProvingKey(pk.(*groth16_bn254.ProvingKey), fmt.Sprintf("rlp_encode_hash_%s_test.pk", version))
	helper.ExportVerifyingKey(vk.(*groth16_bn254.VerifyingKey), fmt.Sprintf("rlp_encode_hash_%s_test.vk", version))
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
	assert.NoError(err)
}

func TestNoSigHeaderRLPEncodeCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	header, _ := HeaderTestData(ExtraV0) // must be ExtraV0, in ExtraV1 we use hash to g2
	pheader, err := GetCompressedHeaderParameters(header)
	assert.NoError(err)
	data, err := encodeHeader(header, true) // no sig
	if err != nil {
		panic(err)
	}
	data = common.BytesToHash(crypto.Keccak256(data)).Bytes()
	r1 := new(big.Int).SetBytes(data[:16])
	r2 := new(big.Int).SetBytes(data[16:])

	circuit := HeaderRLPEncodeVerifyWrapper{
		RlpHash:      [2]frontend.Variable{0, 0},
		Header:       pheader,
		extraVersion: ExtraV0,
		isNoSig:      true,
	}
	assignment := HeaderRLPEncodeVerifyWrapper{
		RlpHash:      [2]frontend.Variable{r1, r2},
		Header:       pheader,
		extraVersion: ExtraV0,
		isNoSig:      true,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	//ccs, err := helper.ReadCCS("rlp_encode_hash_extra_v0.ccs")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	fmt.Println(ccs.GetNbConstraints())
	proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	helper.ExportCCS(ccs, "rlp_encode_hash_no_sig_extra_v0.ccs")
	helper.ExportProvingKey(pk.(*groth16_bn254.ProvingKey), "rlp_encode_hash_no_sig_extra_v0.pk")
	helper.ExportVerifyingKey(vk.(*groth16_bn254.VerifyingKey), "rlp_encode_hash_no_sig_extra_v0.vk")
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
	assert.NoError(err)

}

func TestHeaderHashToG2VerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	_, header := HeaderTestData(ExtraV1)
	cheader, err := GetCompressedHeaderParameters(header)
	assert.NoError(err)
	data, err := encodeHeader(header, true)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("%v\n", data)
	hash, err := bls12381.HashToG2(data, BLSDomain)
	if err != nil {
		panic(err)
	}
	g2HashBytes := hash.Bytes()
	toG2HashCompressed := [4]frontend.Variable{}
	for i := 0; i < 4; i++ {
		toG2HashCompressed[i] = new(big.Int).SetBytes(g2HashBytes[i*24 : (i+1)*24])
	}
	circuit := HeaderHashToG2VerifyWrapper{
		Header:   cheader,
		ToG2Hash: [4]frontend.Variable{0, 0, 0, 0},
	}
	assignment := HeaderHashToG2VerifyWrapper{
		Header:   cheader,
		ToG2Hash: toG2HashCompressed,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	helper.ExportCCS(ccs, "to_g2_hash.ccs")
	helper.ExportProvingKey(pk.(*groth16_bn254.ProvingKey), "to_g2_hash.pk")
	helper.ExportVerifyingKey(vk.(*groth16_bn254.VerifyingKey), "to_g2_hash.vk")
	helper.GetGroth16ContractInput(proof.(*groth16_bn254.Proof))
	//err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	//if err != nil {
	//	panic(err)
	//}
	assert.NoError(err)
}

type HeaderEncoderWrapper struct {
	Header       HeaderParameters
	Data         []frontend.Variable
	ExtraVersion byte
}

// Define declares the circuit's constraints
func (c *HeaderEncoderWrapper) Define(api frontend.API) error {
	encode := NewHeaderEncoder(api)
	edata, err := encode.Encode(c.Header, c.ExtraVersion)
	if err != nil {
		return err
	}
	fmt.Println("in circuit encode: ", edata)
	for i := 0; i < len(edata); i++ {
		api.AssertIsEqual(edata[i], c.Data[i])
	}
	return nil
}
