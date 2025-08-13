package circuit

import (
	"github.com/consensys/gnark/std/math/uints"
	"github.com/nspcc-dev/neo-go/pkg/core/block"
)

const (
	PublickeyLen     = 33               // Length of public key in bytes.
	SignatureLen     = 64               // Length of signature in bytes.
	PublicKeyDataLen = PublickeyLen + 2 // Length of public key data in script (PUSHDATA1 + key length + public key).
	SignatureDataLen = SignatureLen + 2 // Length of signature data in script (PUSHDATA1 + signature length + signature).
)

type HeaderParameters struct {
	Version            uints.U32
	PrevHash           []uints.U8
	MerkleRoot         []uints.U8
	Timestamp          uints.U64
	Nonce              uints.U64
	Index              uints.U32
	PrimaryIndex       uints.U8
	NextConsensus      []uints.U8
	PrevStateRoot      []uints.U8
	InvocationScript   []uints.U8
	VerificationScript []uints.U8
}

func GetHeaderParamter(header *block.Header) (HeaderParameters, error) {
	return HeaderParameters{
		Version:            uints.NewU32(header.Version),
		PrevHash:           uints.NewU8Array(header.PrevHash[:]),
		MerkleRoot:         uints.NewU8Array(header.MerkleRoot[:]),
		Timestamp:          uints.NewU64(header.Timestamp),
		Nonce:              uints.NewU64(header.Nonce),
		Index:              uints.NewU32(header.Index),
		PrimaryIndex:       uints.NewU8(header.PrimaryIndex),
		NextConsensus:      uints.NewU8Array(header.NextConsensus[:]),
		PrevStateRoot:      uints.NewU8Array(header.PrevStateRoot[:]),
		InvocationScript:   uints.NewU8Array(header.Script.InvocationScript),
		VerificationScript: uints.NewU8Array(header.Script.VerificationScript),
	}, nil
}
