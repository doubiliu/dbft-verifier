package circuit

import (
	"fmt"
	btc_ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
	"testing"
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

	data, err := encodeHeader(current, true)
	fmt.Println("sigHeader RLP: ", data)
	assert.NoError(t, err)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	//hash := crypto.Keccak256(data)
	fmt.Println("signature message hash: ", hash)
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
	circuit := ExtraV0HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:         parentParameters,
		Current:        currentParameters,
		PublicKeys:     publicKeys,
		AddressIndices: indexVariables,
	}
	//assignment := ExtraV0HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
	//	Parent:         parentParameters,
	//	Current:        currentParameters,
	//	PublicKeys:     publicKeys,
	//	AddressIndices: indexVariables,
	//}

	//witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	//ccs, err := helper.ReadCCS("rlp_encode_hash_extra_v0.ccs")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println(ccs.GetNbConstraints())

	//pk, vk, err := groth16.Setup(ccs)
	//if err != nil {
	//	panic(err)
	//}
	////pk, err := helper.ReadProvingKey("rlp_encode_hash_extra_v0.pk")
	////if err != nil {
	////	panic(err)
	////}
	////vk, err := helper.ReadVerifyingKey("rlp_encode_hash_extra_v0.vk")
	////if err != nil {
	////	panic(err)
	////}
	//proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	//if err != nil {
	//	panic(err)
	//}
	//publicWitness, err := witness.Public()
	//if err != nil {
	//	panic(err)
	//}
	//err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	//helper.ExportCCS(ccs, "verify_header_extra_v0.ccs")
	//helper.ExportProvingKey(pk.(*groth16_bn254.ProvingKey), "verify_header_extra_v0.pk")
	//helper.ExportVerifyingKey(vk.(*groth16_bn254.VerifyingKey), "verify_header_extra_v0.vk")
	//proofData, cmts, cmtPok := helper.GetGroth16ContractInput(proof.(*groth16_bn254.Proof))
	//// proof.Ar, proof.Bs, proof.Krs
	//fmt.Printf("Proof:")
	//for i := 0; i < 8; i++ {
	//	fmt.Printf(proofData[i].String())
	//}
	//fmt.Println()
	//// commitments
	//fmt.Printf("Commitments:")
	//for i := 0; i < len(cmts); i++ {
	//	fmt.Printf(cmts[i].String())
	//}
	//fmt.Println()
	//// commitmentPok
	//fmt.Printf("CommitmentPok:")
	//for i := 0; i < len(cmtPok); i++ {
	//	fmt.Printf(cmtPok[i].String())
	//}
	////err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	////if err != nil {
	////	panic(err)
	////}
	//assert.NoError(t, err)
}

func TestVerifyHeaderV1(t *testing.T) {

}

type ExtraV0HeaderVerifyWrapper[ECDSAFp, ECDSAFr emulated.FieldParams, FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Parent         HeaderParameters
	Current        HeaderParameters
	PublicKeys     []ecdsa.PublicKey[ECDSAFp, ECDSAFr]
	AddressIndices []frontend.Variable
}

func (c *ExtraV0HeaderVerifyWrapper[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier := NewHeaderVerifier[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl](api)
	return verifier.VerifyV0(c.Parent, c.Current, c.PublicKeys, c.AddressIndices)
}
