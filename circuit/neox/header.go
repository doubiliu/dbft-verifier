package circuit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"slices"
)

type NeoxBlockHeader struct {
	*types.Header
}

func NewNeoxBlockHeader(header *types.Header) *NeoxBlockHeader {
	return &NeoxBlockHeader{header}
}
func (header *NeoxBlockHeader) Encode(params ...any) ([]byte, error) {
	if len(params) != 0 {
		isNoSig, ok := params[0].(bool)
		if !ok {
			return nil, errors.New("invalid param type")
		}
		return encodeEthHeader(header, isNoSig)
	}
	return encodeEthHeader(header, false)
}

func (header *NeoxBlockHeader) Hash(params ...any) ([]byte, error) {
	encode, err := header.Encode(params...)
	if err != nil {
		return nil, err
	}
	return common.BytesToHash(crypto.Keccak256(encode)).Bytes(), nil
}

func (header *NeoxBlockHeader) ToHeaderParameter() (HeaderParameters, error) {
	hashableExtraLen := len(header.Extra)
	switch v := header.Extra[0]; v {
	case ExtraV0:
		hashableExtraLen = HashableExtraV0Len
	case ExtraV1, ExtraV2:
		hashableExtraLen = HashableExtraV1Len
	default:
		return HeaderParameters{}, errors.New("unexpected extra version")
	}
	bytesToVariables := func(input []byte) []frontend.Variable {
		output := make([]frontend.Variable, len(input))
		for i := 0; i < len(input); i++ {
			output[i] = input[i]
		}
		return output
	}
	IntToFilledLengthBytes := func(num uint64) ([]byte, error) {
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.BigEndian, num)
		if err != nil {
			return []byte{}, err
		}
		return buf.Bytes(), nil
	}
	difficulty, err := IntToFilledLengthBytes(header.Difficulty.Uint64())
	if err != nil {
		return HeaderParameters{}, err
	}
	number, err := IntToFilledLengthBytes(header.Number.Uint64())
	if err != nil {
		return HeaderParameters{}, err
	}
	gasLimit, err := IntToFilledLengthBytes(header.GasLimit)
	if err != nil {
		return HeaderParameters{}, err
	}
	gasUsed, err := IntToFilledLengthBytes(header.GasUsed)
	if err != nil {
		return HeaderParameters{}, err
	}
	t, err := IntToFilledLengthBytes(header.Time)
	if err != nil {
		return HeaderParameters{}, err
	}
	baseFee, err := IntToFilledLengthBytes(header.BaseFee.Uint64())
	if err != nil {
		return HeaderParameters{}, err
	}
	//if err != nil {
	//	return HeaderParameters{}, err
	//}
	return HeaderParameters{
		ParentHash:       [32]frontend.Variable(bytesToVariables(header.ParentHash[:])),
		UncleHash:        [32]frontend.Variable(bytesToVariables(header.UncleHash[:])),
		Coinbase:         [20]frontend.Variable(bytesToVariables(header.Coinbase[:])),
		Root:             [32]frontend.Variable(bytesToVariables(header.Root[:])),
		TxHash:           [32]frontend.Variable(bytesToVariables(header.TxHash[:])),
		ReceiptHash:      [32]frontend.Variable(bytesToVariables(header.ReceiptHash[:])),
		Bloom:            [256]frontend.Variable(bytesToVariables(header.Bloom[:])),
		Difficulty:       [8]frontend.Variable(bytesToVariables(difficulty)),
		Number:           [8]frontend.Variable(bytesToVariables(number)),
		GasLimit:         [8]frontend.Variable(bytesToVariables(gasLimit)),
		GasUsed:          [8]frontend.Variable(bytesToVariables(gasUsed)),
		Time:             [8]frontend.Variable(bytesToVariables(t)),
		Extra:            bytesToVariables(header.Extra[:]),
		MixDigest:        [32]frontend.Variable(bytesToVariables(header.MixDigest[:])),
		Nonce:            [8]frontend.Variable(bytesToVariables(header.Nonce[:])),
		BaseFee:          [8]frontend.Variable(bytesToVariables(baseFee)),
		WithdrawalsHash:  [32]frontend.Variable(bytesToVariables(header.WithdrawalsHash[:])),
		hashableExtraLen: hashableExtraLen,
	}, nil
}

func (header *NeoxBlockHeader) ToCompressedHeaderParameters() (CompressHeaderParameters, error) {
	hashableExtraLen := len(header.Extra)
	switch v := header.Extra[0]; v {
	case ExtraV0:
		hashableExtraLen = HashableExtraV0Len
	case ExtraV1, ExtraV2:
		hashableExtraLen = HashableExtraV1Len
	default:
		return CompressHeaderParameters{}, errors.New("unexpected extra version")
	}
	compressHashBytes := func(hash common.Hash) CompressedHash {
		r1Bytes := hash[:16]
		slices.Reverse(r1Bytes)
		r1 := new(big.Int).SetBytes(r1Bytes)

		r2Bytes := hash[16:]
		slices.Reverse(r2Bytes)
		r2 := new(big.Int).SetBytes(r2Bytes)
		return CompressedHash{r1, r2}
	}
	compressU64 := func(u64 uint64) CompressedU64 {
		return frontend.Variable(u64)
	}
	compressBytes := func(bytes []byte) CompressedBytes {
		input := slices.Clone(bytes)
		for len(input)%31 != 0 {
			input = append(input, 0)
		}
		v := make([]frontend.Variable, 0)
		for i := 0; i < len(input)/31; i++ {
			b := slices.Clone(input[i*31 : (i+1)*31])
			slices.Reverse(b)
			v = append(v, frontend.Variable(new(big.Int).SetBytes(b)))
		}
		return CompressedBytes{
			Variables: v,
			Length:    len(bytes),
		}
	}

	coinBaseBytes := slices.Clone(header.Coinbase[:])

	slices.Reverse(coinBaseBytes)
	return CompressHeaderParameters{
		ParentHash:       compressHashBytes(header.ParentHash),
		UncleHash:        compressHashBytes(header.UncleHash),
		Coinbase:         new(big.Int).SetBytes(coinBaseBytes),
		Root:             compressHashBytes(header.Root),
		TxHash:           compressHashBytes(header.TxHash),
		ReceiptHash:      compressHashBytes(header.ReceiptHash),
		Bloom:            compressBytes(header.Bloom[:]),
		Difficulty:       compressU64(header.Difficulty.Uint64()),
		Number:           compressU64(header.Number.Uint64()),
		GasLimit:         compressU64(header.GasLimit),
		GasUsed:          compressU64(header.GasUsed),
		Time:             compressU64(header.Time),
		Extra:            compressBytes(header.Extra),
		MixDigest:        compressHashBytes(header.MixDigest),
		Nonce:            compressU64(header.Nonce.Uint64()),
		BaseFee:          compressU64(header.BaseFee.Uint64()),
		WithdrawalsHash:  compressHashBytes(*header.WithdrawalsHash),
		hashableExtraLen: hashableExtraLen,
	}, nil

}

func (header *NeoxBlockHeader) ExtraVersion() byte {
	return header.Extra[0]
}

func encodeEthHeader(header *NeoxBlockHeader, noSig bool) ([]byte, error) {
	hashableExtraLen := len(header.Extra)
	if noSig {
		switch v := header.Extra[0]; v {
		case ExtraV0:
			hashableExtraLen = HashableExtraV0Len
		case ExtraV1, ExtraV2:
			hashableExtraLen = HashableExtraV1Len
		default:
			return nil, errors.New("unexpected extra version")
		}
	}

	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:hashableExtraLen], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if header.WithdrawalsHash != nil {
		enc = append(enc, header.WithdrawalsHash)
	}
	return rlp.EncodeToBytes(enc)
}
