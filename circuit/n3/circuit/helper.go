package circuit

import (
	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/nspcc-dev/neo-go/pkg/io"
)

func EncodeHashableFields(b block.Header, bw *io.BinWriter) {
	bw.WriteU32LE(b.Version)
	bw.WriteBytes(b.PrevHash[:])
	bw.WriteBytes(b.MerkleRoot[:])
	bw.WriteU64LE(b.Timestamp)
	bw.WriteU64LE(b.Nonce)
	bw.WriteU32LE(b.Index)
	bw.WriteB(b.PrimaryIndex)
	bw.WriteBytes(b.NextConsensus[:])
	if b.StateRootEnabled {
		bw.WriteBytes(b.PrevStateRoot[:])
	}
}
