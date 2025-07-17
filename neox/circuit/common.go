package circuit

import (
	"bytes"
	"encoding/binary"
	"errors"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"slices"
)

const (
	// ExtraV0 is the zero version of block's Extra. Extra of this version includes sorted
	// list of validators addresses followed by BFT number validators signatures.
	ExtraV0 byte = 0x00
	// ExtraV1 is the 1-st version of block's Extra. Extra of this version includes global
	// TPKE public key followed by aggregated validators' threshold signature.
	ExtraV1 byte = 0x01
	// ExtraV2 is the 2-nd version of block's Extra. Extra of this version includes global
	// TPKE public key followed by aggregated validators' threshold signature compatible
	// with Ethereum CL.
	ExtraV2 byte = 0x02
	// ExtraV1ECDSAScheme denotes fallback ECDSA multisignature block signing scheme
	// for ExtraV1 extra.
	ExtraV1ECDSAScheme byte = 0x00
	// ExtraV1ThresholdScheme denotes primary threshold signature block signing scheme
	// for ExtraV1 extra.
	ExtraV1ThresholdScheme byte = 0x01
	// HashableExtraV0Len is the length of hashable part of block extra data for
	// ExtraV0 extra version.
	HashableExtraV0Len = 1
	// HashableExtraV1Len is the length of hashable part of block extra data for
	// ExtraV1 extra version.
	HashableExtraV1Len = 1 + 1 + common.HashLength
	// BLSPublicKeyLen is the length of global public key for signature verification.
	BLSPublicKeyLen = bls12381.SizeOfG1AffineCompressed
	// BLSSignatureLen is the length of block signature.
	BLSSignatureLen = bls12381.SizeOfG2AffineCompressed
)

var (
	BLSDomain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
)

type CompressedHash = [2]frontend.Variable // CompressedHash is a 256-bit Variable, we use 2 frontend.Variables
func ToCompressedHash(api frontend.API, hash [32]frontend.Variable) CompressedHash {
	// here Hash is in big-endian(for rlp encode)
	// we do not change the order between bytes and we process the logic in decompress
	// in each byte, we use little-endian
	noOrderBits := make([]frontend.Variable, 0)
	for _, v := range hash {
		noOrderBits = append(noOrderBits, api.ToBinary(v, 8)...)
	}
	// thus len(noOrderBits) = 256
	r1 := api.FromBinary(noOrderBits[:128]...)
	r2 := api.FromBinary(noOrderBits[128:]...)
	return [2]frontend.Variable{r1, r2}
}
func DecompressHash(api frontend.API, hash CompressedHash) [32]frontend.Variable {
	process := func(r frontend.Variable) []frontend.Variable {
		rBits := api.ToBinary(r, 128)
		res := make([]frontend.Variable, 16)
		for i := 0; i < 16; i++ {
			res[i] = api.FromBinary(rBits[i*8 : (i+1)*8]...)
		}
		return res
	}
	r1Bytes := process(hash[0])
	r2Bytes := process(hash[1])
	return [32]frontend.Variable(append(r1Bytes, r2Bytes...))
}

type CompressedU64 = frontend.Variable // CompressedU64 is a 64-bit Variable, we use one frontend.Variables
func ToCompressedU64(api frontend.API, u64 [8]frontend.Variable) CompressedU64 {
	input := slices.Clone(u64[:])
	slices.Reverse(input)
	bits := make([]frontend.Variable, 0)
	for i := 0; i < 8; i++ {
		bits = append(bits, api.ToBinary(input[i], 8)...)
	}
	return api.FromBinary(bits...)
}
func DecompressU64(api frontend.API, u64 CompressedU64) [8]frontend.Variable {
	bits := api.ToBinary(u64, 64)
	res := make([]frontend.Variable, 8)
	for i := 0; i < 8; i++ {
		res[i] = api.FromBinary(bits[i*8 : (i+1)*8]...)
	}
	slices.Reverse(res)
	return [8]frontend.Variable(res)
}

// CompressedBytes when we use this, the length is fixed
type CompressedBytes struct {
	Variables []frontend.Variable
	Length    int
}

// CompressBytes we compress a-byte v to a/248-variable
func CompressBytes(api frontend.API, v []frontend.Variable) CompressedBytes {
	// each variable in v is a byte(8-bit), we accumulate 31 variable together
	input := slices.Clone(v)
	for len(input)%31 != 0 {
		input = append(input, 0)
	}
	res := make([]frontend.Variable, 0)
	for i := 0; i < len(input)/31; i++ {
		bits := make([]frontend.Variable, 0)
		for j := i * 31; j < (i+1)*31; j++ {
			bits = append(bits, api.ToBinary(input[j], 8)...)
		}
		res = append(res, api.FromBinary(bits...))
	}
	return CompressedBytes{
		Variables: res,
		Length:    len(v),
	}
}
func DecompressBytes(api frontend.API, v CompressedBytes) []frontend.Variable {
	// each variable in v is 31 * 8 bit
	res := make([]frontend.Variable, 0)
	for _, b := range v.Variables {
		bits := api.ToBinary(b, 31*8)
		for i := 0; i < 31; i++ {
			res = append(res, api.FromBinary(bits[i*8:(i+1)*8]...))
		}
	}
	for i := v.Length; i < len(res); i++ {
		api.AssertIsEqual(res[i], 0)
	}
	return res[:v.Length]
}

type CompressHeaderParameters struct {
	ParentHash       CompressedHash
	UncleHash        CompressedHash    // uncleHash 256-bit
	Coinbase         frontend.Variable // coinBase 160-bit, we use one frontend.Variable
	Root             CompressedHash
	TxHash           CompressedHash
	ReceiptHash      CompressedHash
	Bloom            CompressedBytes // not a hash, but can reuse CompressedHash
	Difficulty       CompressedU64
	Number           CompressedU64
	GasLimit         CompressedU64
	GasUsed          CompressedU64
	Time             CompressedU64
	Extra            CompressedBytes
	MixDigest        CompressedHash
	Nonce            CompressedU64
	BaseFee          CompressedU64
	WithdrawalsHash  CompressedHash
	hashableExtraLen int
}

func (header *CompressHeaderParameters) Serialize() []frontend.Variable {
	input := make([]frontend.Variable, 0)
	input = append(input, header.ParentHash[:]...)
	input = append(input, header.UncleHash[:]...)
	input = append(input, header.Coinbase)
	input = append(input, header.Root[:]...)
	input = append(input, header.TxHash[:]...)
	input = append(input, header.ReceiptHash[:]...)
	input = append(input, header.Bloom.Variables...)
	input = append(input, header.Difficulty)
	input = append(input, header.Number)
	input = append(input, header.GasLimit)
	input = append(input, header.GasUsed)
	input = append(input, header.Time)
	input = append(input, header.Extra.Variables...)
	input = append(input, header.MixDigest[:]...)
	input = append(input, header.Nonce)
	input = append(input, header.BaseFee)
	input = append(input, header.WithdrawalsHash[:]...)
	return input
}
func (h *CompressHeaderParameters) Decompressed(api frontend.API) HeaderParameters {
	header := new(HeaderParameters)
	// v is a bits-variables
	BitsToBytes := func(v []frontend.Variable) []frontend.Variable {
		input := slices.Clone(v)
		for len(input)%8 != 0 {
			input = append(input, 0)
		}
		res := make([]frontend.Variable, 0)
		for i := 0; i < len(input)/8; i++ {
			res = append(res, api.FromBinary(input[i*8:(i+1)*8]...))
		}
		return res
	}
	header.ParentHash = DecompressHash(api, h.ParentHash)
	header.UncleHash = DecompressHash(api, h.UncleHash)
	header.Coinbase = [20]frontend.Variable(BitsToBytes(api.ToBinary(h.Coinbase, 160)))
	header.Root = DecompressHash(api, h.Root)
	header.TxHash = DecompressHash(api, h.TxHash)
	header.ReceiptHash = DecompressHash(api, h.ReceiptHash)
	// for bloom, we treat it as a hash, and then transform to bits
	bloomHashBytes := DecompressBytes(api, h.Bloom) // 32-byte
	bloom := make([]frontend.Variable, 0)
	for i := 0; i < 32; i++ {
		bloom = append(bloom, api.ToBinary(bloomHashBytes[i], 8)...)
	}
	header.Bloom = [256]frontend.Variable(bloom)
	header.Difficulty = DecompressU64(api, h.Difficulty)
	header.Number = DecompressU64(api, h.Number)
	header.GasLimit = DecompressU64(api, h.GasLimit)
	header.GasUsed = DecompressU64(api, h.GasUsed)
	header.Time = DecompressU64(api, h.Time)
	header.Extra = DecompressBytes(api, h.Extra)
	header.MixDigest = DecompressHash(api, h.MixDigest)
	header.Nonce = DecompressU64(api, h.Nonce)
	header.BaseFee = DecompressU64(api, h.BaseFee)
	header.WithdrawalsHash = DecompressHash(api, h.WithdrawalsHash)
	header.hashableExtraLen = h.hashableExtraLen
	return *header
}

type HeaderParameters struct {
	ParentHash       [32]frontend.Variable
	UncleHash        [32]frontend.Variable
	Coinbase         [20]frontend.Variable
	Root             [32]frontend.Variable
	TxHash           [32]frontend.Variable
	ReceiptHash      [32]frontend.Variable
	Bloom            [256]frontend.Variable
	Difficulty       [8]frontend.Variable
	Number           [8]frontend.Variable
	GasLimit         [8]frontend.Variable
	GasUsed          [8]frontend.Variable
	Time             [8]frontend.Variable
	Extra            []frontend.Variable
	MixDigest        [32]frontend.Variable
	Nonce            [8]frontend.Variable
	BaseFee          [8]frontend.Variable
	WithdrawalsHash  [32]frontend.Variable
	hashableExtraLen int
}

func (header *HeaderParameters) Compress(api frontend.API) CompressHeaderParameters {
	h := new(CompressHeaderParameters)
	h.ParentHash = ToCompressedHash(api, header.ParentHash)
	h.UncleHash = ToCompressedHash(api, header.UncleHash)
	coinbaseBits := make([]frontend.Variable, 0)
	for i := 0; i < 20; i++ {
		coinbaseBits = append(coinbaseBits, api.ToBinary(header.Coinbase[i], 8)...)
	}
	h.Coinbase = api.FromBinary(coinbaseBits...)
	h.Root = ToCompressedHash(api, header.Root)
	h.TxHash = ToCompressedHash(api, header.TxHash)
	h.ReceiptHash = ToCompressedHash(api, header.ReceiptHash)
	BloomBytes := make([]frontend.Variable, 0)
	for i := 0; i < 32; i++ {
		BloomBytes = append(BloomBytes, api.ToBinary(header.Bloom[i], 8)...)
	}
	h.Bloom = CompressBytes(api, BloomBytes[:])
	h.Difficulty = ToCompressedU64(api, header.Difficulty)
	h.Number = ToCompressedU64(api, header.Number)
	h.GasLimit = ToCompressedU64(api, header.GasLimit)
	h.GasUsed = ToCompressedU64(api, header.GasUsed)
	h.Time = ToCompressedU64(api, header.Time)

	h.Extra = CompressBytes(api, header.Extra)
	h.MixDigest = ToCompressedHash(api, header.MixDigest)
	h.Nonce = ToCompressedU64(api, header.Nonce)
	h.BaseFee = ToCompressedU64(api, header.BaseFee)
	h.WithdrawalsHash = ToCompressedHash(api, header.WithdrawalsHash)
	h.hashableExtraLen = header.hashableExtraLen
	return *h
}

// NoSigHeader return a header which has a no-signature extra term
func (header *HeaderParameters) NoSigHeader() (HeaderParameters, error) {
	return HeaderParameters{
		ParentHash:       [32]frontend.Variable(slices.Clone(header.ParentHash[:])),
		UncleHash:        [32]frontend.Variable(slices.Clone(header.UncleHash[:])),
		Coinbase:         [20]frontend.Variable(slices.Clone(header.Coinbase[:])),
		Root:             [32]frontend.Variable(slices.Clone(header.Root[:])),
		TxHash:           [32]frontend.Variable(slices.Clone(header.TxHash[:])),
		ReceiptHash:      [32]frontend.Variable(slices.Clone(header.ReceiptHash[:])),
		Bloom:            [256]frontend.Variable(slices.Clone(header.Bloom[:])),
		Difficulty:       [8]frontend.Variable(slices.Clone(header.Difficulty[:])),
		Number:           [8]frontend.Variable(slices.Clone(header.Number[:])),
		GasLimit:         [8]frontend.Variable(slices.Clone(header.GasLimit[:])),
		GasUsed:          [8]frontend.Variable(slices.Clone(header.GasUsed[:])),
		Time:             [8]frontend.Variable(slices.Clone(header.Time[:])),
		MixDigest:        [32]frontend.Variable(slices.Clone(header.MixDigest[:])),
		Nonce:            [8]frontend.Variable(slices.Clone(header.Nonce[:])),
		BaseFee:          [8]frontend.Variable(slices.Clone(header.BaseFee[:])),
		WithdrawalsHash:  [32]frontend.Variable(slices.Clone(header.WithdrawalsHash[:])),
		Extra:            slices.Clone(header.Extra[:header.hashableExtraLen]),
		hashableExtraLen: header.hashableExtraLen,
	}, nil
}

func (header *HeaderParameters) Serialize() []frontend.Variable {
	input := make([]frontend.Variable, 0)
	input = append(input, header.ParentHash[:]...)
	input = append(input, header.UncleHash[:]...)
	input = append(input, header.Coinbase[:]...)
	input = append(input, header.Root[:]...)
	input = append(input, header.TxHash[:]...)
	input = append(input, header.ReceiptHash[:]...)
	input = append(input, header.Bloom[:]...)
	input = append(input, header.Difficulty[:]...)
	input = append(input, header.Number[:]...)
	input = append(input, header.GasLimit[:]...)
	input = append(input, header.GasUsed[:]...)
	input = append(input, header.Time[:]...)
	input = append(input, header.Extra...)
	input = append(input, header.MixDigest[:]...)
	input = append(input, header.Nonce[:]...)
	input = append(input, header.BaseFee[:]...)
	input = append(input, header.WithdrawalsHash[:]...)
	return input
}

//func (header *HeaderParameters) Deserialize(input []frontend.Variable) {
//	index := 0
//	copy(header.ParentHash[:], input[index:index+len(header.ParentHash)])
//	index += len(header.ParentHash)
//	copy(header.UncleHash[:], input[index:index+len(header.UncleHash)])
//	index += len(header.UncleHash)
//	copy(header.Coinbase[:], input[index:index+len(header.Coinbase)])
//	index += len(header.Coinbase)
//	copy(header.Root[:], input[index:index+len(header.Root)])
//	index += len(header.Root)
//	copy(header.TxHash[:], input[index:index+len(header.TxHash)])
//	index += len(header.TxHash)
//	copy(header.ReceiptHash[:], input[index:index+len(header.ReceiptHash)])
//	index += len(header.ReceiptHash)
//	copy(header.Bloom[:], input[index:index+len(header.Bloom)])
//	index += len(header.Bloom)
//	copy(header.Difficulty[:], input[index:index+len(header.Difficulty)])
//	index += len(header.Difficulty)
//	copy(header.Number[:], input[index:index+len(header.Number)])
//	index += len(header.Number)
//	copy(header.GasLimit[:], input[index:index+len(header.GasLimit)])
//	index += len(header.GasLimit)
//	copy(header.GasUsed[:], input[index:index+len(header.GasUsed)])
//	index += len(header.GasUsed)
//	copy(header.Time[:], input[index:index+len(header.Time)])
//	index += len(header.Time)
//	copy(header.Extra[:], input[index:index+len(header.Extra)])
//	copy(header.MixDigest[:], input[index:index+len(header.MixDigest)])
//	index += len(header.MixDigest)
//	copy(header.Nonce[:], input[index:index+len(header.Nonce)])
//	index += len(header.Nonce)
//	copy(header.BaseFee[:], input[index:index+len(header.BaseFee)])
//	index += len(header.BaseFee)
//	copy(header.WithdrawalsHash[:], input[index:index+len(header.WithdrawalsHash)])
//	index += len(header.WithdrawalsHash)
//	header.Extra = make([]frontend.Variable, len(input[index:]))
//	copy(header.Extra[:], input[index:])
//}

func GetCompressedHeaderParameters(header *types.Header) (CompressHeaderParameters, error) {
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

func GetHeaderParamter(header *types.Header) (HeaderParameters, error) {
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
