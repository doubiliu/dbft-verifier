package n3

import (
	native_crypto "crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/nspcc-dev/neo-go/pkg/crypto/hash"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"math/big"
)

func GetN3VerifierHeaderWrapper() (frontend.Circuit, error) {
	network, parent, current := HeaderTestData()
	return new(N3VerifyHeaderWrapper).Circuit(
		func() ([]circuit.HashableBlockHeader, error) {
			return []circuit.HashableBlockHeader{NewN3BlockHeader(parent), NewN3BlockHeader(current)}, nil
		}, network)
}

type N3VerifyHeaderWrapper struct {
	Parent       HeaderParameters
	Current      HeaderParameters
	PubsPoint    []ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	MappingRules []frontend.Variable
	Network      uints.U32  `gnark:",public"`
	ParentHash   []uints.U8 `gnark:",public"`
	CurrentHash  []uints.U8 `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *N3VerifyHeaderWrapper) Define(api frontend.API) error {
	verify := NewHeaderVerifier(api)
	verify.Verify(c.Parent, c.Current, c.ParentHash, c.CurrentHash, c.PubsPoint, c.MappingRules, c.Network)
	return nil
}
func (c *N3VerifyHeaderWrapper) Circuit(headerGenerator func() ([]circuit.HashableBlockHeader, error), params ...any) (frontend.Circuit, error) {
	return c.instance(headerGenerator, params...)
}
func (c *N3VerifyHeaderWrapper) Assignment(headerGenerator func() ([]circuit.HashableBlockHeader, error), params ...any) (frontend.Circuit, error) {
	return c.instance(headerGenerator, params...)
}

func (c *N3VerifyHeaderWrapper) instance(headerGenerator func() ([]circuit.HashableBlockHeader, error), params ...any) (frontend.Circuit, error) {
	headers, err := headerGenerator()
	if err != nil {
		return nil, err
	}
	parent, ok := headers[0].(*N3BlockHeader)
	if !ok {
		return nil, errors.New("invalid header")
	}
	current, ok := headers[1].(*N3BlockHeader)
	if !ok {
		return nil, errors.New("invalid header")
	}
	network := uint32(860833102) // todo ?
	if len(params) != 0 {
		network, ok = params[0].(uint32)
		if !ok {
			return nil, errors.New("invalid parameters")
		}
	}
	pparent, err := parent.ToHeaderParameter()
	if err != nil {
		return nil, err
	}
	pcurrent, err := current.ToHeaderParameter()
	if err != nil {
		return nil, err
	}
	VerificationScript := current.Script.VerificationScript
	InvocationScript := current.Script.InvocationScript
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
	hashData := hash.NetSha256(network, current.Header)
	fmt.Println(hashData)
	mappingRules := make([]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		sig := InvocationScript[i*SignatureDataLen+2 : (i+1)*SignatureDataLen]
		r, s := new(big.Int), new(big.Int)
		r.SetBytes(sig[:32])
		s.SetBytes(sig[32:64])
		for j := 0; j < len(pubKeys); j++ {
			flag := native_crypto.Verify(&pubKeys[j], hashData[:], r, s)
			if flag {
				mappingRules[i] = frontend.Variable(j)
			}
		}
	}
	fmt.Println(mappingRules)
	pHash, err := parent.Hash()
	if err != nil {
		return nil, err
	}
	cHash, err := current.Hash()
	if err != nil {
		return nil, err
	}
	parentHash := uints.NewU8Array(pHash)
	currentHash := uints.NewU8Array(cHash)

	return &N3VerifyHeaderWrapper{
		Parent:       pparent,
		Current:      pcurrent,
		PubsPoint:    pubPoints,
		MappingRules: mappingRules,
		Network:      uints.NewU32(network),
		ParentHash:   parentHash,
		CurrentHash:  currentHash,
	}, nil
}

func NewHeaderVerifier(api frontend.API) HeaderVerifier {
	return HeaderVerifier{api: api}
}

func HeaderTestData() (network uint32, parent, current *block.Header) {
	network = uint32(860833102)
	parent = new(block.Header)
	err := parent.UnmarshalJSON([]byte(
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
	if err != nil {
		panic(err)
	}
	current = new(block.Header)
	err = current.UnmarshalJSON([]byte(
		`{
			"hash": "0xd0e2c5cd98d58eeb66c4f8413a798a75e4adaca7f1e8862bf6c3ad9d671ee6f5",
			"size": 696,
			"version": 0,
			"previousblockhash": "0x580ede92e9c41f6e0edd491d66bfac11cb38749744f725117636b0f600ac0bda",
			"merkleroot": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"time": 1628062144879,
			"nonce": "7796968F9028CE3B",
			"index": 10000,
			"primary": 4,
			"nextconsensus": "NVg7LjGcUSrgxgjX3zEgqaksfMaiS8Z6e1",
			"witnesses": [
				{
					"invocation": "DECY2CGlKOpDLVwHn9j+EqB2OFW1hpuy0SZubdmf6Ggiu+PTKxTU4yTi7HYQEceROv91BYTyKGf0WxVVd9XhZxCtDECO3t113PC6I3456CrmbQRn3rlL7fvv5jDlCRMPpNRO7pH59VsG6yfvpnyqjmfl2D6NtIUcePM9CYBFTDG8WzUfDED7Guu6CT0LDKKEXUuarc9UaCyFOE9/nit7qDwY/YD/A04Nxxy604xbcLrgNjYFBCO0zrLwNaZVMuRGDKwdCGYCDED11qlTYFpj0BGsT4o1eh93Xz1BC1UU65gebQTW9+ZzVQbqYbZi8hEUZChBV9Fhw1R6Wm2ZLZGUjYV5woGLQRYGDEAMmnC3AGvGd2VXcH9+d5eOnNrLOFp9686E62OrxWget7D60ND4fsaCANyT/Gd9eZWbiQbJPHh9SO+lex96ssKZ",
					"verification": "FQwhAkhv0VcCxEkKJnAxEqXMHQkj/Wl6M0Br1aHADgATsJpwDCECTHt/tsMQ/M8bozsIJRnYKWTqk4aNZ2Zi1KWa1UjfDn0MIQKq7DhHD2qtAELG6HfP2Ah9Jnaw9Rb93TYoAbm9OTY5ngwhA7IJ/U9TpxcOpERODLCmu2pTwr0BaSaYnPhfmw+6F6cMDCEDuNnVdx2PUTqghpucyNUJhkA7eMbaNokGOMPUalrc4EoMIQLKDidpe5wkj28W4IX9AGHib0TahbWO6DXBEMql7DulVAwhAt9I9g6PPgHEj/QLm38TENeosqGTGIvv4cLj33QOiVCTF0Ge0Nw6"
				}
			],
			"confirmations": 7198223,
			"nextblockhash": "0xf884452a7b7aea2710e03e02f2e53a232ae986453c81df00fc8d095190177a74"
		}`,
	))
	if err != nil {
		panic(err)
	}
	return
}
