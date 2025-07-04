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
	var ParentHash [len(header.ParentHash)]frontend.Variable
	for i := 0; i < len(header.ParentHash); i++ {
		ParentHash[i] = header.ParentHash[i]
	}
	var UncleHash [len(header.UncleHash)]frontend.Variable
	for i := 0; i < len(header.UncleHash); i++ {
		UncleHash[i] = header.UncleHash[i]
	}
	var Coinbase [len(header.Coinbase)]frontend.Variable
	for i := 0; i < len(header.Coinbase); i++ {
		Coinbase[i] = header.Coinbase[i]
	}
	var Root [len(header.Root)]frontend.Variable
	for i := 0; i < len(header.Root); i++ {
		Root[i] = header.Root[i]
	}
	var TxHash [len(header.TxHash)]frontend.Variable
	for i := 0; i < len(header.TxHash); i++ {
		TxHash[i] = header.TxHash[i]
	}
	var ReceiptHash [len(header.ReceiptHash)]frontend.Variable
	for i := 0; i < len(header.ReceiptHash); i++ {
		ReceiptHash[i] = header.ReceiptHash[i]
	}
	var Bloom [len(header.Bloom)]frontend.Variable
	for i := 0; i < len(header.Bloom); i++ {
		Bloom[i] = header.Bloom[i]
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, header.Difficulty.Uint64())
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		panic(err)
	}
	difficulty := buf.Bytes()
	var Difficulty [8]frontend.Variable
	for i := 0; i < len(difficulty); i++ {
		Difficulty[i] = difficulty[i]
	}
	buf0 := new(bytes.Buffer)
	err = binary.Write(buf0, binary.BigEndian, header.Number.Uint64())
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		panic(err)
	}
	number := buf0.Bytes()
	var Number [8]frontend.Variable
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
	//gl = removeUnusedZeroBytes(gl)
	var GasLimit [8]frontend.Variable
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
	//gu = removeUnusedZeroBytes(gu)
	var GasUsed [8]frontend.Variable
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
	var Time [8]frontend.Variable
	for i := 0; i < len(time); i++ {
		Time[i] = time[i]
	}
	Extra := make([]frontend.Variable, len(header.Extra))
	for i := 0; i < len(header.Extra); i++ {
		Extra[i] = header.Extra[i]
	}
	var MixDigest [len(header.MixDigest)]frontend.Variable
	for i := 0; i < len(header.MixDigest); i++ {
		MixDigest[i] = header.MixDigest[i]
	}
	var Nonce [len(header.Nonce)]frontend.Variable
	for i := 0; i < len(header.Nonce); i++ {
		Nonce[i] = header.Nonce[i]
	}
	buf4 := new(bytes.Buffer)
	err = binary.Write(buf4, binary.BigEndian, header.BaseFee.Uint64())
	if err != nil {
		fmt.Println("Error encoding uint64:", err)
		panic(err)
	}
	bf := buf4.Bytes()
	var BaseFee [8]frontend.Variable
	for i := 0; i < len(bf); i++ {
		BaseFee[i] = bf[i]
	}
	var WithdrawalsHash [32]frontend.Variable
	for i := 0; i < len(header.WithdrawalsHash); i++ {
		WithdrawalsHash[i] = header.WithdrawalsHash[i]
	}
	pheader := HeaderParameters{
		ParentHash:      ParentHash,
		UncleHash:       UncleHash,
		Coinbase:        Coinbase,
		Root:            Root,
		TxHash:          TxHash,
		ReceiptHash:     ReceiptHash,
		Bloom:           Bloom,
		Difficulty:      Difficulty,
		Number:          Number,
		GasLimit:        GasLimit,
		GasUsed:         GasUsed,
		Time:            Time,
		Extra:           Extra,
		MixDigest:       MixDigest,
		Nonce:           Nonce,
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
