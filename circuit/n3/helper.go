package n3

import (
	native_crypto "crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/nspcc-dev/neo-go/pkg/io"
	"math/big"
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

func DecompressPubkey(pubkey []byte) (*native_crypto.PublicKey, error) {
	x, y := new(big.Int), new(big.Int)
	if len(pubkey) != 33 {
		return nil, fmt.Errorf("invalid public key")
	}
	if (pubkey[0] != 0x02) && (pubkey[0] != 0x03) {
		return nil, fmt.Errorf("invalid public key")
	}
	if x == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	x.SetBytes(pubkey[1:])

	xxx := new(big.Int).Mul(x, x)
	xxx.Mul(xxx, x)

	ax := new(big.Int).Mul(big.NewInt(3), x)

	yy := new(big.Int).Sub(xxx, ax)
	yy.Add(yy, elliptic.P256().Params().B)

	y1 := new(big.Int).ModSqrt(yy, elliptic.P256().Params().P)
	if y1 == nil {
		return nil, fmt.Errorf("can not revcovery public key")
	}

	y2 := new(big.Int).Neg(y1)
	y2.Mod(y2, elliptic.P256().Params().P)

	if pubkey[0] == 0x02 {
		if y1.Bit(0) == 0 {
			y = y1
		} else {
			y = y2
		}
	} else {
		if y1.Bit(0) == 1 {
			y = y1
		} else {
			y = y2
		}
	}
	//fmt.Println("dx:",x)
	//fmt.Println("dy:",y)
	return &native_crypto.PublicKey{X: x, Y: y, Curve: elliptic.P256()}, nil
}
