package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

func TestKecc256Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	header := new(EthBlockHeader)
	err := header.UnmarshalJSON([]byte(
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
	rlpBytes, err := header.Encode(false)
	assert.NoError(err)
	k := common.BytesToHash(crypto.Keccak256(rlpBytes))
	fmt.Println(crypto.Keccak256(rlpBytes))

	var kHash [32]frontend.Variable
	for i := 0; i < len(kHash); i++ {
		kHash[i] = k[i]
	}
	pB := make([]frontend.Variable, len(rlpBytes))
	for i := 0; i < len(rlpBytes); i++ {
		pB[i] = rlpBytes[i]
	}
	circuit := Keccak256Wrapper{
		PreImage: pB,
		Hash:     [32]frontend.Variable{},
	}
	witness := Keccak256Wrapper{
		PreImage: pB,
		Hash:     kHash,
	}
	//_, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)
}

type Keccak256Wrapper struct {
	PreImage []frontend.Variable   // byte array
	Hash     [32]frontend.Variable `gnark:",public"` // each variable is 64 bit
}

func (c *Keccak256Wrapper) Define(api frontend.API) error {
	kecczk256 := NewKeccak256(api)
	computeHash, err := kecczk256.Compute(c.PreImage)
	if err != nil {
		return err
	}
	for j := 0; j < 32; j++ {
		api.AssertIsEqual(computeHash[j], c.Hash[j])
	}
	return nil
}
