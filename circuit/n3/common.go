package n3

import (
	"github.com/consensys/gnark/std/math/uints"
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
