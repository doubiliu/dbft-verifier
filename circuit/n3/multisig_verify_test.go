package n3

import (
	native_crypto "crypto/ecdsa"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/nspcc-dev/neo-go/pkg/crypto/hash"
	"math/big"
	_ "math/big"
	"testing"
)

func TestMultiSigVerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	header := new(block.Header)
	err := header.UnmarshalJSON([]byte(
		`{
			"hash": "0x580ede92e9c41f6e0edd491d66bfac11cb38749744f725117636b0f600ac0bda",
			"size": 696,
			"version": 0,
			"previousblockhash": "0x92661b2985f7649edad5465f0a3fb19d4289051f43bd242f60660cb49594f19d",
			"merkleroot": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"time": 1628062127819,
			"nonce": "EB9DB8F0012A3C1E",
			"index": 9999,
			"primary": 3,
			"nextconsensus": "NVg7LjGcUSrgxgjX3zEgqaksfMaiS8Z6e1",
			"witnesses": [
				{
					"invocation": "DEDCjfeKUw2coerAOvs12ffgbaXZf0LK3zl9XdBlFWfsqxajuVK41g3hjiZCp2THdrvPD0VWmbz8wSZbNMO+vGP5DECR2m0A8VPtPNEhqg+ozlcnO5+SRDpDuzvZdJuVp4W+we37U9rjaR21GRYOua4gLIyfNhqKxEOI22zquu6rjPDPDEArOI2hfb2CmzK2HhTm4Yt2UBUb0wv6vTB88y+p/famfLq+czL2Y7k97zEPZM7or7bv59/Yx3XDSiB7+PqCBiPTDEDP5qcfswgIxSxBD5JC0gt35NCii3gNKYRBriFTBIJiKXR1sbYiXfYPr6uVmKjJ/NYgfHHGXfR4+F1+ycn8JYZcDEArw7JN1A2iEmq3XCQ5Kvl8uc4VWJ/I0KHD0i/sTW8834/AkrLML+XGY4pmNr4kqENJNULEi4ZOBRQawiOn0LiZ",
					"verification": "FQwhAkhv0VcCxEkKJnAxEqXMHQkj/Wl6M0Br1aHADgATsJpwDCECTHt/tsMQ/M8bozsIJRnYKWTqk4aNZ2Zi1KWa1UjfDn0MIQKq7DhHD2qtAELG6HfP2Ah9Jnaw9Rb93TYoAbm9OTY5ngwhA7IJ/U9TpxcOpERODLCmu2pTwr0BaSaYnPhfmw+6F6cMDCEDuNnVdx2PUTqghpucyNUJhkA7eMbaNokGOMPUalrc4EoMIQLKDidpe5wkj28W4IX9AGHib0TahbWO6DXBEMql7DulVAwhAt9I9g6PPgHEj/QLm38TENeosqGTGIvv4cLj33QOiVCTF0Ge0Nw6"
				}
			],
			"confirmations": 7198226,
			"nextblockhash": "0xd0e2c5cd98d58eeb66c4f8413a798a75e4adaca7f1e8862bf6c3ad9d671ee6f5"
		}`,
	))
	hash := hash.NetSha256(860833102, header)
	VerificationScript := header.Script.VerificationScript
	InvocationScript := header.Script.InvocationScript
	bytesToVariables := func(input []byte) []uints.U8 {
		output := make([]uints.U8, len(input))
		for i := 0; i < len(input); i++ {
			output[i] = uints.NewU8(input[i])
		}
		return output
	}
	pubPoints := make([]ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], 7)
	pubKeys := make([]native_crypto.PublicKey, 7)
	for i := 0; i < 7; i++ {
		// Key data
		pubs := VerificationScript[i*PublicKeyDataLen+3 : (i+1)*PublicKeyDataLen+1]
		pubkey, err := DecompressPubkey(pubs)
		if err != nil {
			panic(err)
		}
		pubKeys[i] = *pubkey
		pubPoints[i] = ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](pubkey.X),
			Y: emulated.ValueOf[emulated.P256Fp](pubkey.Y),
		}
	}
	MappingRules := make([]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		sig := InvocationScript[i*SignatureDataLen+2 : (i+1)*SignatureDataLen]
		r, s := new(big.Int), new(big.Int)
		r.SetBytes(sig[:32])
		s.SetBytes(sig[32:64])
		for j := 0; j < len(pubKeys); j++ {
			flag := native_crypto.Verify(&pubKeys[j], hash[:], r, s)
			if flag {
				MappingRules[i] = frontend.Variable(j)
			}
		}
	}

	circuit := MultiSigVerifyWrapper[emulated.P256Fp, emulated.P256Fr]{
		Hash:               [32]uints.U8(uints.NewU8Array(hash[:])),
		PubKeys:            pubPoints,
		MappingRules:       MappingRules,
		VerificationScript: bytesToVariables(VerificationScript),
		InvocationScript:   bytesToVariables(InvocationScript),
	}

	witness := MultiSigVerifyWrapper[emulated.P256Fp, emulated.P256Fr]{
		Hash:               [32]uints.U8(uints.NewU8Array(hash[:])),
		PubKeys:            pubPoints,
		MappingRules:       MappingRules,
		VerificationScript: bytesToVariables(VerificationScript),
		InvocationScript:   bytesToVariables(InvocationScript),
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestCheckPubKeyFormatCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	header := new(block.Header)
	err := header.UnmarshalJSON([]byte(
		`{
			"hash": "0x580ede92e9c41f6e0edd491d66bfac11cb38749744f725117636b0f600ac0bda",
			"size": 696,
			"version": 0,
			"previousblockhash": "0x92661b2985f7649edad5465f0a3fb19d4289051f43bd242f60660cb49594f19d",
			"merkleroot": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"time": 1628062127819,
			"nonce": "EB9DB8F0012A3C1E",
			"index": 9999,
			"primary": 3,
			"nextconsensus": "NVg7LjGcUSrgxgjX3zEgqaksfMaiS8Z6e1",
			"witnesses": [
				{
					"invocation": "DEDCjfeKUw2coerAOvs12ffgbaXZf0LK3zl9XdBlFWfsqxajuVK41g3hjiZCp2THdrvPD0VWmbz8wSZbNMO+vGP5DECR2m0A8VPtPNEhqg+ozlcnO5+SRDpDuzvZdJuVp4W+we37U9rjaR21GRYOua4gLIyfNhqKxEOI22zquu6rjPDPDEArOI2hfb2CmzK2HhTm4Yt2UBUb0wv6vTB88y+p/famfLq+czL2Y7k97zEPZM7or7bv59/Yx3XDSiB7+PqCBiPTDEDP5qcfswgIxSxBD5JC0gt35NCii3gNKYRBriFTBIJiKXR1sbYiXfYPr6uVmKjJ/NYgfHHGXfR4+F1+ycn8JYZcDEArw7JN1A2iEmq3XCQ5Kvl8uc4VWJ/I0KHD0i/sTW8834/AkrLML+XGY4pmNr4kqENJNULEi4ZOBRQawiOn0LiZ",
					"verification": "FQwhAkhv0VcCxEkKJnAxEqXMHQkj/Wl6M0Br1aHADgATsJpwDCECTHt/tsMQ/M8bozsIJRnYKWTqk4aNZ2Zi1KWa1UjfDn0MIQKq7DhHD2qtAELG6HfP2Ah9Jnaw9Rb93TYoAbm9OTY5ngwhA7IJ/U9TpxcOpERODLCmu2pTwr0BaSaYnPhfmw+6F6cMDCEDuNnVdx2PUTqghpucyNUJhkA7eMbaNokGOMPUalrc4EoMIQLKDidpe5wkj28W4IX9AGHib0TahbWO6DXBEMql7DulVAwhAt9I9g6PPgHEj/QLm38TENeosqGTGIvv4cLj33QOiVCTF0Ge0Nw6"
				}
			],
			"confirmations": 7198226,
			"nextblockhash": "0xd0e2c5cd98d58eeb66c4f8413a798a75e4adaca7f1e8862bf6c3ad9d671ee6f5"
		}`,
	))
	VerificationScript := header.Script.VerificationScript
	for i := 0; i < 7; i++ {
		// Key data
		pubs := VerificationScript[i*PublicKeyDataLen+3 : (i+1)*PublicKeyDataLen+1]
		pubU8s := make([]frontend.Variable, len(pubs))
		for j := 0; j < len(pubs); j++ {
			pubU8s[j] = pubs[j]
		}
		pubkey, err := DecompressPubkey(pubs)
		if err != nil {
			panic(err)
		}
		circuit := TempForamtCheckStruct[emulated.P256Fp, emulated.P256Fr]{
			Pubs: pubU8s,
			PubsPoint: ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
				X: emulated.ValueOf[emulated.P256Fp](pubkey.X),
				Y: emulated.ValueOf[emulated.P256Fp](pubkey.Y),
			},
		}

		witness := TempForamtCheckStruct[emulated.P256Fp, emulated.P256Fr]{
			Pubs: pubU8s,
			PubsPoint: ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
				X: emulated.ValueOf[emulated.P256Fp](pubkey.X),
				Y: emulated.ValueOf[emulated.P256Fp](pubkey.Y),
			},
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	}
	assert.NoError(err)
}

type TempForamtCheckStruct[T, S emulated.FieldParams] struct {
	PubsPoint ecdsa.PublicKey[T, S]
	Pubs      []frontend.Variable
}

func (c *TempForamtCheckStruct[T, S]) Define(api frontend.API) error {
	verify := NewMultiSigVerify[T, S](api)
	verify.CheckPubKeyFormat(c.PubsPoint, c.Pubs)
	return nil
}
