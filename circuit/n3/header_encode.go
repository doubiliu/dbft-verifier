package n3

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

type HeaderEncoder struct {
	api frontend.API
}

func NewHeaderEncoder(api frontend.API) HeaderEncoder {
	return HeaderEncoder{api: api}
}

func (h *HeaderEncoder) Encode(header HeaderParameters) ([]uints.U8, error) {
	api := h.api
	binEncode := NewBinEncode(api)
	data := make([]uints.U8, 0)
	data = append(data, binEncode.WriteU32LE(header.Version)...)
	data = append(data, binEncode.WriteBytes(header.PrevHash[:])...)
	data = append(data, binEncode.WriteBytes(header.MerkleRoot[:])...)
	data = append(data, binEncode.WriteU64LE(header.Timestamp)...)
	data = append(data, binEncode.WriteU64LE(header.Nonce)...)
	data = append(data, binEncode.WriteU32LE(header.Index)...)
	data = append(data, binEncode.WriteB(header.PrimaryIndex))
	data = append(data, binEncode.WriteBytes(header.NextConsensus[:])...)
	//data = append(data, binEncode.WriteBytes(header.PrevStateRoot[:])...)
	api.Println("Preimage:")
	api.Println(len(data))
	hasher, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	hasher.Write(data)
	ref := hasher.Sum()
	return ref, nil
}
