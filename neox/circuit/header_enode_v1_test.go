package circuit

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"testing"
)

func TestHeaderEncodeV1Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	header := new(types.Header)
	err := header.UnmarshalJSON([]byte(
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
	pheader := GetHeaderParamter(header)
	data, err := encodeHeader(header)
	//data, err := encodeSigHeader(header)
	if err != nil {
		panic(err)
	}
	fmt.Println("电路外endoce结果：")
	fmt.Printf("%v\n", data)
	data = common.BytesToHash(crypto.Keccak256(data)).Bytes()
	Data := make([]frontend.Variable, len(data))
	for i := 0; i < len(Data); i++ {
		Data[i] = data[i]
	}
	fmt.Printf("%v\n", data)
	circuit := HeaderEncodeWrapper{
		Header: pheader,
		Data:   make([]frontend.Variable, len(data)),
	}
	witness := HeaderEncodeWrapper{
		Header: pheader,
		Data:   Data,
	}

	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)
}

type HeaderEncodeWrapper struct {
	Header HeaderParameters
	Data   []frontend.Variable
}

// Define declares the circuit's constraints
func (c *HeaderEncodeWrapper) Define(api frontend.API) error {
	encode := NewHeaderEncode(api)
	edata := encode.RlpHash(api, c.Header)
	for i := 0; i < len(edata); i++ {
		api.AssertIsEqual(edata[i], c.Data[i])
	}
	return nil
}

func TestRLPEncodeVerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	header := new(types.Header)
	err := header.UnmarshalJSON([]byte(
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
	circuit := HeaderRLPEncodeVerifyWrapper{
		Input: input,
	}
	assignment := HeaderRLPEncodeVerifyWrapper{
		Input: input,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())

	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
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
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))

	helper.ExportCSS(css, "rlphash_css")
	helper.ExportProvingKey(pk.(*groth16_bn254.ProvingKey), "rlphash_pk")
	helper.ExportVerifyingKey(vk.(*groth16_bn254.VerifyingKey), "rlphash_vk")
	proofData, cmts, cmtPok := helper.GetGroth16ContractInput(proof.(*groth16_bn254.Proof))
	// proof.Ar, proof.Bs, proof.Krs
	fmt.Printf("Proof:")
	for i := 0; i < 8; i++ {
		fmt.Printf(proofData[i].String())
	}
	// commitments
	fmt.Printf("Commitments:")
	for i := 0; i < len(cmts); i++ {
		fmt.Printf(cmts[i].String())
	}
	// commitmentPok
	fmt.Printf("CommitmentPok:")
	for i := 0; i < len(cmtPok); i++ {
		fmt.Printf(cmtPok[i].String())
	}
	/*	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}*/
	assert.NoError(err)
}

func TestHeaderHashToG2VerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	header := new(types.Header)
	err := header.UnmarshalJSON([]byte(
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
	circuit := HeaderHashToG2VerifyWrapper{
		Input: input,
	}
	assignment := HeaderHashToG2VerifyWrapper{
		Input: input,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
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
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	helper.ExportCSS(css, "tog2hash_css")
	helper.ExportProvingKey(pk.(*groth16_bn254.ProvingKey), "tog2hash_pk")
	helper.ExportVerifyingKey(vk.(*groth16_bn254.VerifyingKey), "tog2hash_vk")
	helper.GetGroth16ContractInput(proof.(*groth16_bn254.Proof))
	/*	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}*/
	assert.NoError(err)
}
