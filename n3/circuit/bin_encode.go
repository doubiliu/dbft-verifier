package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func NewBinEncode(api frontend.API) BinEncode {
	return BinEncode{api: api}
}

type BinEncode struct {
	api frontend.API
}

// WriteBytes  encode uint32 data to byte[]
func (binEncode *BinEncode) WriteBytes(data []uints.U8) []uints.U8 {
	return data
}

// WriteU64LE  encode uint64 data to byte[]
func (binEncode *BinEncode) WriteU64LE(data uints.U64) []uints.U8 {
	api := binEncode.api
	dataLength := len(data)
	api.AssertIsEqual(frontend.Variable(dataLength), frontend.Variable(8))
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		panic(err)
	}
	ret := uapi.UnpackLSB(data)
	return ret
}

func (binEncode *BinEncode) WriteU32LE(data uints.U32) []uints.U8 {
	api := binEncode.api
	dataLength := len(data)
	api.AssertIsEqual(frontend.Variable(dataLength), frontend.Variable(4))
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	ret := uapi.UnpackLSB(data)
	return ret
}

func (binEncode *BinEncode) WriteB(data uints.U8) uints.U8 {
	return data
}
