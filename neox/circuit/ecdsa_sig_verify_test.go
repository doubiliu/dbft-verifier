package circuit

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/frontend"
	//"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

func TestMultiECDSASignatureVerify(t *testing.T) {
	assert := test.NewAssert(t)
	// generate a public key
	privKey, err := secp.GeneratePrivateKey()
	assert.NoError(err)
	publicKey := privKey.PubKey()
	pubBytes := publicKey.SerializeUncompressed()[1:]
	address := common.BytesToAddress(crypto.Keccak256(pubBytes)[12:])
	fmt.Println("address: ", address)
	testAddress := [20]frontend.Variable{}
	for i := 0; i < 20; i++ {
		testAddress[i] = address[19-i]
	}
	message := "test multi signature verify"
	hasher := sha256.New()
	hasher.Write([]byte(message))
	hash := hasher.Sum(nil)
	fmt.Println("hash: ", hash)
	signature, err := crypto.Sign(hash, privKey.ToECDSA())
	assert.NoError(err)
	testPublicKeys := make([]ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], 0)
	var px fp.Element
	px.SetBigInt(publicKey.X())
	var py fp.Element
	py.SetBigInt(publicKey.Y())
	pub := secp256k1.G1Affine{
		X: px,
		Y: py,
	}
	testSignare := [65]frontend.Variable{}
	for i := 0; i < 65; i++ {
		testSignare[i] = signature[i]
	}
	testPublicKeys = append(testPublicKeys,
		ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pub.Y),
		})
	testHash := [32]frontend.Variable{}
	if len(hash) != 32 {
		assert.NoError(fmt.Errorf("expected hash to be 32 bytes, got %d", len(hash)))
	}
	for i := 0; i < len(testHash); i++ {
		testHash[i] = hash[i]
	}
	circuit := MultiECDSASigVerifyingWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Hash:      testHash,                             // hash bytes
		Signature: [][65]frontend.Variable{testSignare}, // compact signature(of hash) bytes
		PublicKey: testPublicKeys,
		Addresses: [][20]frontend.Variable{testAddress},
	}
	assignment := MultiECDSASigVerifyingWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Hash:      testHash,                             // hash bytes
		Signature: [][65]frontend.Variable{testSignare}, // compact signature(of hash) bytes
		PublicKey: testPublicKeys,
		Addresses: [][20]frontend.Variable{testAddress},
	}

	//ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	//assert.NoError(err)
	//fmt.Println(ccs.GetNbConstraints())
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)
}
