package n3

import (
	"github.com/consensys/gnark/std/math/uints"
	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/nspcc-dev/neo-go/pkg/io"
)

type N3BlockHeader struct {
	*block.Header
}

func NewN3BlockHeader(header *block.Header) *N3BlockHeader {
	return &N3BlockHeader{header}
}

func (header *N3BlockHeader) Height() uint64 {
	return uint64(header.Header.Index)
}
func (header *N3BlockHeader) Encode(...any) ([]byte, error) {
	buf := io.NewBufBinWriter()
	// No error can occur while encoding hashable fields.
	EncodeHashableFields(*header.Header, buf.BinWriter)
	return buf.Bytes(), nil
}

func (header *N3BlockHeader) Hash(...any) ([]byte, error) {
	return header.Header.Hash().BytesBE(), nil // big endian
}

func (header *N3BlockHeader) ToHeaderParameter() (HeaderParameters, error) {
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
