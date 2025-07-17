package circuit

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"slices"
)

type MultiECDSASigVerifyingWrapper[Fp, Fr emulated.FieldParams] struct {
	Hash      [32]frontend.Variable     // hash bytes
	Signature [][65]frontend.Variable   // compact signature(of hash) bytes
	PublicKey []ecdsa.PublicKey[Fp, Fr] `gnark:",publicKeys"`
	Addresses [][20]frontend.Variable   `gnark:",public"` // each address is a [20]byte
}

func (c *MultiECDSASigVerifyingWrapper[Fp, Fr]) Define(api frontend.API) error {
	batch := len(c.PublicKey)
	if len(c.Addresses) != batch || len(c.Signature) != batch {
		return fmt.Errorf("unmatched parameters")
	}
	verifier := NewECDSASigVerifier[Fp, Fr](api)

	for i := 0; i < batch; i++ {
		if err := verifier.Verify(c.Hash, c.Signature[i], c.PublicKey[i], c.Addresses[i]); err != nil {
			return err
		}
	}
	return nil
}

type ECDSASigVerifier[Fp, Fr emulated.FieldParams] struct {
	api frontend.API
}

func NewECDSASigVerifier[Fp, Fr emulated.FieldParams](api frontend.API) ECDSASigVerifier[Fp, Fr] {
	return ECDSASigVerifier[Fp, Fr]{api: api}
}

// Verify gives a method to verify sig(hash, pk) = signature
// here the public keys is input to avoid compute jacobian point
func (v *ECDSASigVerifier[Fp, Fr]) Verify(hash [32]frontend.Variable, signature [65]frontend.Variable, publicKey ecdsa.PublicKey[Fp, Fr], address [20]frontend.Variable) error {
	// first we need to binding the public key and address
	// 1. get 64-byte format pubkey bytes, ignore the first bit(take the remain 64 bit)
	api := v.api
	field, err := emulated.NewField[Fp](api)
	if err != nil {
		return err
	}
	// here we try to use curve.MarshalG1 but failed
	xBits := field.ToBits(&publicKey.X)
	xBytes := make([]frontend.Variable, 32)
	for i := 0; i < len(xBytes); i++ {
		index := i * 8
		xBytes[31-i] = api.FromBinary(xBits[index : index+8]...)
	}
	yBits := field.ToBits(&publicKey.Y)
	yBytes := make([]frontend.Variable, 32)
	for i := 0; i < len(yBytes); i++ {
		index := i * 8
		yBytes[31-i] = api.FromBinary(yBits[index : index+8]...)
	}
	pubBytes := append(xBytes, yBytes...)
	api.Println(pubBytes)
	keccak256 := NewKeccak256(v.api)
	//2. address = keccak256(pubBytes)[12:], len = 20
	keyHashBytes, err := keccak256.Compute(pubBytes)
	if err != nil {
		return err
	}

	for i := 0; i < 20; i++ {
		api.AssertIsEqual(address[19-i], keyHashBytes[12+i])
	}
	// then we need to verify the signature, sign(hash, pk) = signature
	// 3. transform signature([65]frontend.variable) to Signature[Fr]
	// [65] = [R | S | 0/1], we take the first 64 byte(R/S)
	R, S := signature[:32], signature[32:64]
	frField, err := emulated.NewField[Fr](api)
	if err != nil {
		return err
	}
	transformToFrElement := func(item [32]frontend.Variable) *emulated.Element[Fr] {
		slices.Reverse(item[:])
		bits := make([]frontend.Variable, 0)
		for i := 0; i < len(item); i++ {
			bits = append(bits, api.ToBinary(item[i], 8)...)
		}
		return frField.FromBits(bits...)

	}
	sig := ecdsa.Signature[Fr]{
		R: *transformToFrElement([32]frontend.Variable(R)),
		S: *transformToFrElement([32]frontend.Variable(S)),
	}
	// 4. transform hash to element
	publicKey.Verify(api, sw_emulated.GetCurveParams[Fp](), transformToFrElement(hash), &sig)
	return nil
}
