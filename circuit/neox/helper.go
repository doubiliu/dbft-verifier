package circuit

import (
	"bytes"
	"encoding/binary"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"math/big"
)

func rangeCheck(api frontend.API, x frontend.Variable, limits []frontend.Variable) {
	flag := frontend.Variable(0)
	for i := 0; i < len(limits); i++ {
		subValue := api.Sub(x, limits[i])
		f := api.IsZero(subValue)
		flag = api.Select(f, f, flag)
	}
	//check if x is in limits
	api.AssertIsEqual(flag, frontend.Variable(1))
}
func intToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func BytesToIntVarible(api frontend.API, x []frontend.Variable) (frontend.Variable, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	xbytes := make([]uints.U8, len(x))
	for i := 0; i < len(x); i++ {
		xbytes[i] = uapi.ByteValueOf(x[i])
	}
	msb := uapi.PackMSB(xbytes...)
	value := uapi.ToValue(msb)
	return value, nil
}

func publicKeyToVariable(publicKey btcec.PublicKey) ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr] {
	var px fp.Element
	px.SetBigInt(publicKey.X())
	var py fp.Element
	py.SetBigInt(publicKey.Y())
	pub := secp256k1.G1Affine{
		X: px,
		Y: py,
	}

	return ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](pub.X),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](pub.Y),
	}
}

func ComputeRLPProof(field, outer *big.Int, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, header *types.Header, IsNoSig bool) (groth16.Proof, witness.Witness, error) {
	assignment, err := new(HeaderRLPEncodeVerifyWrapper).Assignment(
		func() (circuit.HashableBlockHeader, error) {
			return NewNeoxBlockHeader(header), nil
		}, IsNoSig,
	)
	if err != nil {
		return nil, nil, err
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	pubWitness, err := w.Public()
	if err != nil {
		return nil, nil, err
	}
	innerProof, err := groth16.Prove(ccs, pk, w, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	err = groth16.Verify(innerProof, vk, pubWitness, stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}

	return innerProof, pubWitness, nil
}

func ComputeToG2HashProof(field, outer *big.Int, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, header *types.Header) (groth16.Proof, witness.Witness, error) {
	assignment, err := new(HeaderHashToG2VerifyWrapper).Assignment(
		func() (circuit.HashableBlockHeader, error) {
			return NewNeoxBlockHeader(header), nil
		},
	)
	w, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return nil, nil, err
	}
	innerPubWitness, err := w.Public()
	if err != nil {
		return nil, nil, err
	}
	innerProof, err := groth16.Prove(ccs, pk, w, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	err = groth16.Verify(innerProof, vk, innerPubWitness, stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	return innerProof, innerPubWitness, nil
}
