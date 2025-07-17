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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"math/big"
	"slices"
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

// HeaderRLPEncodeVerifyWrapper is used in V0/V1/V2, generate a proof of rlpHash(header)
// we use header.NoSigHeader() to get a NoSigHeaderRLPEncodeVerifyWrapper which is used in V0, generates a proof of rlpHash(NoSigHeader)
// To reduce the number of public input, we use CompressHeadParameters instead of HeadParameters
type HeaderRLPEncodeVerifyWrapper struct {
	RlpHash      [2]frontend.Variable     `gnark:",public"` // we use 2 frontend.Variable to present a 256-variables rlp-hash
	Header       CompressHeaderParameters `gnark:",public"` // we do not reveal the whole header
	extraVersion byte
	isNoSig      bool
}

func (c *HeaderRLPEncodeVerifyWrapper) Define(api frontend.API) error {
	encode := NewHeaderEncoder(api)
	header := c.Header.Decompressed(api)
	var toEncodeHeader HeaderParameters
	var err error
	if c.isNoSig {
		toEncodeHeader, err = header.NoSigHeader()
		if err != nil {
			return err
		}
	} else {
		toEncodeHeader = header

	}
	rlpHash, err := encode.Encode(toEncodeHeader, c.extraVersion)
	api.Println(rlpHash)
	if err != nil {
		return err
	}
	// rlpHash = [r1 00] [r2 00]
	api.AssertIsEqual(len(rlpHash), 32)
	slices.Reverse(rlpHash)
	rlpBits := make([]frontend.Variable, 0)
	for _, r := range rlpHash {
		rlpBits = append(rlpBits, api.ToBinary(r, 8)...)
	}
	// r1 = [rlpBits[:128], 0000...00]
	r1 := make([]frontend.Variable, 254)
	r2 := make([]frontend.Variable, 254)
	for i := 0; i < 254; i++ {
		if i < 128 {
			r1[i] = rlpBits[i]
			r2[i] = rlpBits[128+i]
		} else {
			r1[i] = 0
			r2[i] = 0
		}
	}

	api.AssertIsEqual(c.RlpHash[1], api.FromBinary(r1...))
	api.AssertIsEqual(c.RlpHash[0], api.FromBinary(r2...))
	return nil
}

// HeaderHashToG2VerifyWrapper is used in V1/V2, generate a proof of HashToG2(NoSigHeader)
// This is only used for computing V1/V2 No-sig header's G2Hash
// To reduce the number of public input, we use CompressHeadParameters instead of HeadParameters
// We use 4 frontend.Variable to present a 96-byte(768-bit) G2Hash, each variable have 192-bit
type HeaderHashToG2VerifyWrapper struct {
	ToG2Hash [4]frontend.Variable     `gnark:",public"`
	Header   CompressHeaderParameters `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *HeaderHashToG2VerifyWrapper) Define(api frontend.API) error {
	header := c.Header.Decompressed(api)
	encode := NewHeaderEncoder(api)
	noSigHeader, err := header.NoSigHeader()
	if err != nil {
		return err
	}
	toG2Hash := encode.HashToG2(api, noSigHeader)
	/*	api.Println(toG2Hash)
		api.Println(ToG2Hash)*/
	// toG2Hash is 96-byte
	slices.Reverse(toG2Hash)
	toG2HashBits := make([]frontend.Variable, 0)
	for _, g := range toG2Hash {
		toG2HashBits = append(toG2HashBits, api.ToBinary(g, 8)...)
	}
	r := make([]frontend.Variable, 4)
	for i := 0; i < 4; i++ {
		r[3-i] = api.FromBinary(toG2HashBits[192*i : (i+1)*192]...)
	}
	for i := 0; i < len(c.ToG2Hash); i++ {
		api.AssertIsEqual(c.ToG2Hash[i], r[i])
	}
	return nil
}

func HeaderTestData(extraVersion byte) (parent, current *types.Header) {
	switch extraVersion {
	case ExtraV0:
		parent = new(types.Header)
		err := parent.UnmarshalJSON([]byte(
			`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x1",
			"extraData": "0x000fa7e10abc3b4c9dc768f0fa0a043feb987e21772952f909b98424f1e99f641212951c350ea78a0c4ea2a4697d40247c8be1f2b9ffa03a0e92dcbacca2617fcd447e2932857696c707055f517bbdb2eaa51fe05b0183d01607bf48c1718d1168a1c11171cbbeca26e89011e32ba25610520b20741b809007d10f47396dc6c76ad53546158751582d3e2683ef120f17ca9a284e245123266794e84a9b7837c063efbabb9fa0493bdfef639b4c1bd435671bdc994e3fcb1a49215724846df81dfb053aef81546c09ab9716b5a3004a14579ed10f83daa2bde98917c2ece6a96e44751d09c5d6ae3b142d97896b60386fa6e124fee91bad6db620706e0e7c2c8c164b18b5aca96e6e92e74dfed9c90112634ee0f5e3ac574e6b9d448e63049c21be1918888e0281d125a65be23a64d478af4e920eb98b127ce558210d82617e220cadf53718fc96a4f8c978d9a9f3f500005eb0a3d3d6891e93eea2c265586da39bbaa37340f1314adccb7b412e8bc590518ad65d82ed5e25683e0482f4658918244625dfedff1dce99ec68ea548cdf3a0078034253bd9182d011eeab022da45dd9d92e031655a6f0c16215674496762bd540ccc5e684f92651df31e8233a9b4206b002157a45999d1bc85f13c3dfc11a0800",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0x5651954a9691194b40ec6fa173a7f7d2ca86c4b30c6dd1af331eaeee079c1e78",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0x229c4ebaddc5f4824218d2ec9839f61e984ada15408b8c304a8fbde45a9d12fa",
			"nonce": "0x0000000000000002",
			"number": "0x11",
			"parentHash": "0x8f19bb26cf4e2f3f19a0cb2ad318a3539419c8a1fec46b14ba46a68e6514f085",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x3f9",
			"stateRoot": "0xdb2f7ede2ec991c786df6ac4672817f1608b4893484238d06da8a2278924e8e9",
			"timestamp": "0x668fb56c",
			"totalDifficulty": "0x1d",	
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
		))
		if err != nil {
			panic(err)
		}
		current = new(types.Header)
		err = current.UnmarshalJSON([]byte(
			`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x2",
			"extraData": "0x000fa7e10abc3b4c9dc768f0fa0a043feb987e21772952f909b98424f1e99f641212951c350ea78a0c4ea2a4697d40247c8be1f2b9ffa03a0e92dcbacca2617fcd447e2932857696c707055f517bbdb2eaa51fe05b0183d01607bf48c1718d1168a1c11171cbbeca26e89011e32ba25610520b20741b809007d10f47396dc6c76ad53546158751582d3e2683ef328f82d2587fb1e58e3cb5fdc1b789f15b4acd6101458614b2f13ab5c822eede4e21a3d265868692073432ad9df7a902a2bf2088721999aad8dddc39e853de6c0110bca64701039749bcb404bc1c1f42efa38975507a7c94316acb681b6776064067918c3c98d340ffa623d509209a42bfc199b7d8a117f6ee007dc458199ecc4b0016d999c0420fcf9df7da68a60e6b82a0c8af62386b538265eb2e589e8bc9a553004700c2d4bd1cf4291390c369ad1dd94d0cbbf271b3c206de1fe9086df359e300c33ce941969e864b1d36434248bc96ce24cb5ab75e48daa3a1a64cb927a3326f0b5546d4d5b813b56b4aee42f32b06703db5b6734da5eb575ef0e33a9fcbd0a800687fb01563327200cc68921d349e6ec8a9c04a5b33729bb51a32077dabd85b5274ae9bf95799318e5fc3e566709a5c65b96a5566c3bec4626f9087320886a97501",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0x69d097c89f2f94f33640e8689ecb3b4715fcfca44a16f8c6710c0d29a47e01b1",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0x229c4ebaddc5f4824218d2ec9839f61e984ada15408b8c304a8fbde45a9d12fa",
			"nonce": "0x0000000000000004",
			"number": "0x12",
			"parentHash": "0x5651954a9691194b40ec6fa173a7f7d2ca86c4b30c6dd1af331eaeee079c1e78",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x3f9",
			"stateRoot": "0xdb2f7ede2ec991c786df6ac4672817f1608b4893484238d06da8a2278924e8e9",
			"timestamp": "0x668fb5a9",
			"totalDifficulty": "0x1f",
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
		))
		if err != nil {
			panic(err)
		}

	case ExtraV1:
		parent = new(types.Header)
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
		if err != nil {
			panic(err)
		}
		current = new(types.Header)
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
		if err != nil {
			panic(err)
		}
	case ExtraV2:
		parent = new(types.Header)
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
		if err != nil {
			panic(err)
		}
		current = new(types.Header)
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
		if err != nil {
			panic(err)
		}
	default:
		panic("invalid extra version")
	}
	return
}
