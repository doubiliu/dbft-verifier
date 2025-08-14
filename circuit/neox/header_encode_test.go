package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/mod"
	"testing"
)

func TestHeaderEncoderV0(t *testing.T) {
	assert := test.NewAssert(t)
	_, current := HeaderTestData(ExtraV0)
	header := NewNeoxBlockHeader(current)
	pheader, err := header.ToHeaderParameter()

	data, err := header.Encode(false)
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
	header := NewNeoxBlockHeader(current)
	pheader, err := header.ToHeaderParameter()

	data, err := header.Encode(false)
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
	header := NewNeoxBlockHeader(current)
	pheader, err := header.ToHeaderParameter()

	data, err := header.Encode(false)
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
	extraVersion := ExtraV0
	var version string
	switch extraVersion {
	case ExtraV0:
		version = "v0"
	case ExtraV1:
		version = "v1"
	case ExtraV2:
		version = "v2"
	default:
		panic("unknown extra version")
	}
	instanceConfig := mod.InstanceConfig{
		CcsPath: fmt.Sprintf("../../cmd/meta/test/%s/rlp_encode_hash_extra_%s_test.ccs", version, version),
		PkPath:  fmt.Sprintf("../../cmd/meta/test/%s/rlp_encode_hash_extra_%s_test.pk", version, version),
		VkPath:  fmt.Sprintf("../../cmd/meta/test/%s/rlp_encode_hash_extra_%s_test.vk", version, version),
	}
	err := TestSubCircuitSetup(circuit.RlpHash, extraVersion, true, instanceConfig)
	if err != nil {
		panic(err)
	}
}

func TestNoSigHeaderRLPEncodeCircuit(t *testing.T) {
	instanceConfig := mod.InstanceConfig{
		CcsPath: "../../cmd/meta/test/v0/rlp_encode_noSig_hash_extra_v0_test.ccs",
		PkPath:  "../../cmd/meta/test/v0/rlp_encode_noSig_hash_extra_v0_test.pk",
		VkPath:  "../../cmd/meta/test/v0/rlp_encode_noSig_hash_extra_v0_test.vk",
	}
	err := TestSubCircuitSetup(circuit.NoSigRlp, ExtraV0, true, instanceConfig)
	if err != nil {
		panic(err)
	}

}

func TestHeaderHashToG2VerifyCircuit(t *testing.T) {
	extraVersion := ExtraV1
	instanceConfig := mod.InstanceConfig{
		CcsPath: "../../cmd/meta/test/v1/to_g2_hash.ccs",
		PkPath:  "../../cmd/meta/test/v1/to_g2_hash.pk",
		VkPath:  "../../cmd/meta/test/v1/to_g2_hash.vk",
	}
	err := TestSubCircuitSetup(circuit.ToG2Hash, extraVersion, true, instanceConfig)
	if err != nil {
		panic(err)
	}
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
