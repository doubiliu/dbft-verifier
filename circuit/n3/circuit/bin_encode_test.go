package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/nspcc-dev/neo-go/pkg/io"
	"testing"
)

func TestRlpEncodeCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	parent := new(block.Header)
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
	assert.NoError(err)
	buf := io.NewBufBinWriter()
	// No error can occur while encoding hashable fields.
	EncodeHashableFields(*parent, buf.BinWriter)
	ref := buf.Bytes()
	fmt.Println(ref)
	circuit := BinEncodeWrapper{
		Version:       uints.NewU32(parent.Version),
		PrevHash:      uints.NewU8Array(parent.PrevHash[:]),
		MerkleRoot:    uints.NewU8Array(parent.MerkleRoot[:]),
		Timestamp:     uints.NewU64(parent.Timestamp),
		Nonce:         uints.NewU64(parent.Nonce),
		Index:         uints.NewU32(parent.Index),
		PrimaryIndex:  uints.NewU8(parent.PrimaryIndex),
		NextConsensus: uints.NewU8Array(parent.NextConsensus[:]),
		PrevStateRoot: uints.NewU8Array(parent.PrevStateRoot[:]),
	}
	witness := BinEncodeWrapper{
		Version:       uints.NewU32(parent.Version),
		PrevHash:      uints.NewU8Array(parent.PrevHash[:]),
		MerkleRoot:    uints.NewU8Array(parent.MerkleRoot[:]),
		Timestamp:     uints.NewU64(parent.Timestamp),
		Nonce:         uints.NewU64(parent.Nonce),
		Index:         uints.NewU32(parent.Index),
		PrimaryIndex:  uints.NewU8(parent.PrimaryIndex),
		NextConsensus: uints.NewU8Array(parent.NextConsensus[:]),
		PrevStateRoot: uints.NewU8Array(parent.PrevStateRoot[:]),
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
}

type BinEncodeWrapper struct {
	Version       uints.U32
	PrevHash      []uints.U8
	MerkleRoot    []uints.U8
	Timestamp     uints.U64
	Nonce         uints.U64
	Index         uints.U32
	PrimaryIndex  uints.U8
	NextConsensus []uints.U8
	PrevStateRoot []uints.U8
}

// Define declares the circuit's constraints
func (c *BinEncodeWrapper) Define(api frontend.API) error {
	binEncode := NewBinEncode(api)
	ref := make([]uints.U8, 0)
	ref = append(ref, binEncode.WriteU32LE(c.Version)...)
	ref = append(ref[:], binEncode.WriteU32LE(c.Version)...)
	ref = append(ref[:], binEncode.WriteBytes(c.PrevHash[:])...)
	ref = append(ref[:], binEncode.WriteBytes(c.MerkleRoot[:])...)
	ref = append(ref[:], binEncode.WriteU64LE(c.Timestamp)...)
	ref = append(ref[:], binEncode.WriteU64LE(c.Nonce)...)
	ref = append(ref[:], binEncode.WriteU32LE(c.Index)...)
	ref = append(ref[:], binEncode.WriteB(c.PrimaryIndex))
	ref = append(ref[:], binEncode.WriteBytes(c.NextConsensus[:])...)
	ref = append(ref[:], binEncode.WriteBytes(c.PrevStateRoot[:])...)
	api.Println(ref)
	return nil
}
