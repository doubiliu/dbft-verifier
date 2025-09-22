package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"log"
	"testing"
)

func TestMultiSigVerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	header := new(NeoxBlockHeader)
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

	data, err := header.Encode(true)
	if err != nil {
		panic(err)
	}
	hash, _ := bls12381.HashToG2(data, BLSDomain)

	pubBytes := header.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
	sigBytes := header.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]
	var pk bls12381.G1Affine
	_, err = pk.SetBytes(pubBytes)
	if err != nil {
		panic(err)
	}
	xBytes := make([]frontend.Variable, len(pk.Bytes()))
	for i := 0; i < len(xBytes); i++ {
		xBytes[i] = frontend.Variable(pk.Bytes()[i])
	}
	_, _, g1, _ := bls12381.Generators()
	g1.Neg(&g1)
	var sig bls12381.G2Affine
	_, err = sig.SetBytes(sigBytes)
	circuit := BlsSigVerifyWrapper{
		Pub:  sw_bls12381.NewG1Affine(pk),
		Sig:  sw_bls12381.NewG2Affine(sig),
		Hash: sw_bls12381.NewG2Affine(hash),
	}
	witness := BlsSigVerifyWrapper{
		Pub:  sw_bls12381.NewG1Affine(pk),
		Sig:  sw_bls12381.NewG2Affine(sig),
		Hash: sw_bls12381.NewG2Affine(hash),
	}
	/*	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}*/
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}
	p, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	//_, err := plonk.Setup(r1cs, kate, &publicWitness)
	if err != nil {
		log.Fatal(err)
	}
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witnessPublic, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatal(err)
	}
	proof, err := plonk.Prove(ccs, p, witnessFull)
	if err != nil {
		log.Fatal(err)
	}

	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal("Error: wrong proof is accepted")
	}
	assert.NoError(err)
}

type BlsSigVerifyWrapper struct {
	Hash sw_bls12381.G2Affine
	Sig  sw_bls12381.G2Affine
	Pub  sw_bls12381.G1Affine
}

// Define declares the circuit's constraints
func (c *BlsSigVerifyWrapper) Define(api frontend.API) error {
	verify := NewBlsSigVerify(api)
	verify.Verify(api, &c.Hash, &c.Sig, &c.Pub)
	return nil
}
