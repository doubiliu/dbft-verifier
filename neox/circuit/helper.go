package circuit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

func encodeSigHeader(header *types.Header) ([]byte, error) {
	var hashableExtraLen int
	switch v := header.Extra[0]; v {
	case ExtraV0:
		hashableExtraLen = HashableExtraV0Len
	case ExtraV1, ExtraV2:
		hashableExtraLen = HashableExtraV1Len
	default:
		return nil, errors.New("unexpected extra version")
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

func encodeHeader(header *types.Header) ([]byte, error) {
	var hashableExtraLen int
	switch v := header.Extra[0]; v {
	case ExtraV0:
		hashableExtraLen = HashableExtraV0Len
	case ExtraV1, ExtraV2:
		hashableExtraLen = HashableExtraV1Len
	default:
		return nil, errors.New("unexpected extra version")
	}
	fmt.Println(hashableExtraLen)
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
		header.Extra, // Yes, this will panic if extra is too short
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

func GetHeaderParamter(header *types.Header) HeaderParameters {
	ParentHash := make([]frontend.Variable, len(header.ParentHash))
	for i := 0; i < len(header.ParentHash); i++ {
		ParentHash[i] = header.ParentHash[i]
	}
	UncleHash := make([]frontend.Variable, len(header.UncleHash))
	for i := 0; i < len(header.UncleHash); i++ {
		UncleHash[i] = header.UncleHash[i]
	}
	Coinbase := make([]frontend.Variable, len(header.Coinbase))
	for i := 0; i < len(header.Coinbase); i++ {
		Coinbase[i] = header.Coinbase[i]
	}
	Root := make([]frontend.Variable, len(header.Root))
	for i := 0; i < len(header.Root); i++ {
		Root[i] = header.Root[i]
	}
	TxHash := make([]frontend.Variable, len(header.TxHash))
	for i := 0; i < len(header.TxHash); i++ {
		TxHash[i] = header.TxHash[i]
	}
	ReceiptHash := make([]frontend.Variable, len(header.ReceiptHash))
	for i := 0; i < len(header.ReceiptHash); i++ {
		ReceiptHash[i] = header.ReceiptHash[i]
	}
	Bloom := make([]frontend.Variable, len(header.Bloom))
	for i := 0; i < len(header.Bloom); i++ {
		Bloom[i] = header.Bloom[i]
	}
	difficulty := header.Difficulty.Bytes()
	Difficulty := make([]frontend.Variable, len(difficulty))
	for i := 0; i < len(difficulty); i++ {
		Difficulty[i] = difficulty[i]
	}
	buf0 := new(bytes.Buffer)
	err := binary.Write(buf0, binary.BigEndian, header.Number.Uint64())
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		panic(err)
	}
	number := buf0.Bytes()
	Number := make([]frontend.Variable, len(number))
	for i := 0; i < len(number); i++ {
		Number[i] = number[i]
	}
	buf1 := new(bytes.Buffer)
	err = binary.Write(buf1, binary.BigEndian, header.GasLimit)
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		panic(err)
	}
	gl := buf1.Bytes()
	gl = removeUnusedZeroBytes(gl)
	GasLimit := make([]frontend.Variable, len(gl))
	for i := 0; i < len(gl); i++ {
		GasLimit[i] = gl[i]
	}
	buf2 := new(bytes.Buffer)
	err = binary.Write(buf2, binary.BigEndian, header.GasUsed)
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		panic(err)
	}
	gu := buf2.Bytes()
	gu = removeUnusedZeroBytes(gu)
	GasUsed := make([]frontend.Variable, len(gu))
	for i := 0; i < len(gu); i++ {
		GasUsed[i] = gu[i]
	}
	buf3 := new(bytes.Buffer)
	err = binary.Write(buf3, binary.BigEndian, header.Time)
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		panic(err)
	}
	time := buf3.Bytes()
	Time := make([]frontend.Variable, len(time))
	for i := 0; i < len(time); i++ {
		Time[i] = time[i]
	}
	Extra := make([]frontend.Variable, len(header.Extra))
	for i := 0; i < len(header.Extra); i++ {
		Extra[i] = header.Extra[i]
	}
	MixDigest := make([]frontend.Variable, len(header.MixDigest))
	for i := 0; i < len(header.MixDigest); i++ {
		MixDigest[i] = header.MixDigest[i]
	}
	Nonce := make([]frontend.Variable, len(header.Nonce))
	for i := 0; i < len(header.Nonce); i++ {
		Nonce[i] = header.Nonce[i]
	}
	bf := header.BaseFee.Bytes()
	BaseFee := make([]frontend.Variable, len(bf))
	for i := 0; i < len(bf); i++ {
		BaseFee[i] = bf[i]
	}
	WithdrawalsHash := make([]frontend.Variable, len(header.WithdrawalsHash))
	for i := 0; i < len(header.WithdrawalsHash); i++ {
		WithdrawalsHash[i] = header.WithdrawalsHash[i]
	}
	pheader := HeaderParameters{
		ParentHash:  ParentHash,
		UncleHash:   UncleHash,
		Coinbase:    Coinbase,
		Root:        Root,
		TxHash:      TxHash,
		ReceiptHash: ReceiptHash,
		Bloom:       Bloom,
		Difficulty:  Difficulty,
		Number:      Number,
		GasLimit:    GasLimit,
		GasUsed:     GasUsed,
		Time:        Time,
		Extra:       Extra,
		MixDigest:   MixDigest,
		Nonce:       Nonce,

		BaseFee:         BaseFee,
		WithdrawalsHash: WithdrawalsHash,
	}
	return pheader
}

func removeUnusedZeroBytes(in []byte) []byte {
	//remove 0x00 byte
	tin := make([]byte, 0)
	for i := 0; i < len(in); i++ {
		if in[i] != 0x00 {
			tin = in[i:]
			break
		}
	}
	in = tin
	return in
}
