package circuit

import (
	"github.com/consensys/gnark/frontend"
	"slices"
)

func NewRlpEncode(api frontend.API) RlpEncode {
	return RlpEncode{api: api}
}

type RlpEncode struct {
	api frontend.API
}

// EncodeRule1  when we use this rule, len(data) is fixed
// 1: data length =1, data <= 127
// 2. data length = 1, data >= 128, we move this logic to rule2
func (rlpEncode *RlpEncode) EncodeRule1(data []frontend.Variable) []frontend.Variable {
	api := rlpEncode.api
	dataLength := len(data)
	api.AssertIsEqual(frontend.Variable(dataLength), frontend.Variable(1))
	api.AssertIsLessOrEqual(data[0], 127)
	return data
}

// EncodeRule2 1 <= data length <=55, when we use this rule, len(data) is fixed
// 1. data length = 1, data >= 128
// 2. 1 < data length <= 55
func (rlpEncode *RlpEncode) EncodeRule2(data []frontend.Variable) []frontend.Variable {
	api := rlpEncode.api
	dataLength := len(data)
	// is not short enough
	isLenOne := api.IsZero(api.Sub(dataLength, 1))
	// if len(data) == 1, data[0] >= 128
	isNotShortEnough := api.Cmp(data[0], 127)                                     // if data[0] >= 128, = 1
	api.AssertIsEqual(api.Mul(isLenOne, api.Sub(1, isNotShortEnough)), 0)         // isLenOne * (1 - isNotShortEnough)
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(55)) // <= 55
	prefix := frontend.Variable(byte(128) + byte(dataLength))

	var result []frontend.Variable
	result = append(result, prefix)
	result = append(result, data...)
	return result
}

// Rule3: data length >55,data length can be expressed in one byte
func (rlpEncode *RlpEncode) EncodeRule3_OneByte(data []frontend.Variable) []frontend.Variable {
	api := rlpEncode.api
	dataLength := len(data)
	api.AssertIsLessOrEqual(frontend.Variable(55), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(255))
	prefix1 := frontend.Variable(byte(183) + 1)
	prefix2 := frontend.Variable(byte(dataLength))
	var result []frontend.Variable
	result = append(result, prefix1)
	result = append(result, prefix2)
	result = append(result, data...)
	return result
}

// Rule3: data length >55,data length can be expressed in two byte
func (rlpEncode *RlpEncode) EncodeRule3_TwoBytes(data []frontend.Variable) []frontend.Variable {
	api := rlpEncode.api
	dataLength := len(data)
	api.AssertIsLessOrEqual(frontend.Variable(55), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(255), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(65535))
	prefix1 := frontend.Variable(byte(183) + 2)
	dataLengthBytes := intToBytes(dataLength)
	prefix2 := frontend.Variable(dataLengthBytes[2])
	prefix3 := frontend.Variable(dataLengthBytes[3])
	var result []frontend.Variable
	result = append(result, prefix1)
	result = append(result, prefix2)
	result = append(result, prefix3)
	result = append(result, data...)
	return result
}

// Rule4: data list length <55
func (rlpEncode *RlpEncode) EncodeRule4(data [][]frontend.Variable) []frontend.Variable {
	api := rlpEncode.api
	dataLength := 0
	for i := 0; i < len(data); i++ {
		dataLength = dataLength + len(data[i])
	}
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(55))
	prefix1 := frontend.Variable(byte(192) + byte(dataLength))
	var result []frontend.Variable
	result = append(result, prefix1)
	for i := 0; i < len(data); i++ {
		result = append(result, data[i]...)
	}
	return result
}

// Rule5: data list length >55,data list length can be expressed in one byte
func (rlpEncode *RlpEncode) EncodeRule5_OneByte(data [][]frontend.Variable) []frontend.Variable {
	api := rlpEncode.api
	dataLength := 0
	for i := 0; i < len(data); i++ {
		dataLength = dataLength + len(data[i])
	}
	api.AssertIsLessOrEqual(frontend.Variable(55), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(255))
	prefix1 := frontend.Variable(byte(247) + 1)
	prefix2 := frontend.Variable(byte(dataLength))
	var result []frontend.Variable
	result = append(result, prefix1)
	result = append(result, prefix2)
	for i := 0; i < len(data); i++ {
		result = append(result, data[i]...)
	}
	return result
}

// Rule5: data list length >55,data list length can be expressed in two bytes
func (rlpEncode *RlpEncode) EncodeRule5_TwoBytes(data [][]frontend.Variable) []frontend.Variable {
	api := rlpEncode.api
	dataLength := 0
	for i := 0; i < len(data); i++ {
		dataLength = dataLength + len(data[i])
	}
	api.AssertIsLessOrEqual(frontend.Variable(55), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(255), frontend.Variable(dataLength))
	api.AssertIsLessOrEqual(frontend.Variable(dataLength), frontend.Variable(65535))
	prefix1 := frontend.Variable(byte(247) + 2)
	dataLengthBytes := intToBytes(dataLength)
	prefix2 := frontend.Variable(dataLengthBytes[2])
	prefix3 := frontend.Variable(dataLengthBytes[3])
	var result []frontend.Variable
	result = append(result, prefix1)
	result = append(result, prefix2)
	result = append(result, prefix3)
	for i := 0; i < len(data); i++ {
		result = append(result, data[i]...)
	}
	return result
}

// EncodeRule1And2Slice Rule1 and 2: 1 <= data length <=55, but the length is unfixed(has pre-0)
// we write this together, we can use PaddingSlice to delete the pre-0 in rule 1
// prefix:
// rule 1: len(data) = 1 and data <= 127 then prefix = 0 else prefix = 129
// rule 2: 1 < len(dataLength) <= 55
func (rlpEncode *RlpEncode) EncodeRule1And2Slice(data PaddingSlice) PaddingSlice {
	api := rlpEncode.api
	dataLength := data.Len(api)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(55))
	isOne := api.IsZero(api.Sub(dataLength, 1)) // if len(data) = 1 or len(data) = 0, then prefix = 0
	// data <= 127
	// we just need to take data[0]
	isShortEnough := api.IsZero(api.Sub(api.Mul(isOne, api.Cmp(128, data.Last())), 1)) // data <= 127 and len(data) = 1
	//prefix := api.Select(api.Or(api.IsZero(dataLength), isOne), 0, api.Add(dataLength, 128))
	prefixBytes := IntToBytesVarible(api, api.Select(isShortEnough, 0, api.Add(dataLength, 128)))
	prefix := prefixBytes[len(prefixBytes)-1]
	sApi := NewSliceApi(api)
	prefixSlice := sApi.New(api, []frontend.Variable{prefix}, false)
	result := sApi.concat(prefixSlice, data, false)
	return result
}

// Rule3: data length >55,data length can be expressed in one byte
func (rlpEncode *RlpEncode) EncodeRule3_OneByteSlice(data PaddingSlice) PaddingSlice {
	api := rlpEncode.api
	dataLength := data.Len(api)
	api.AssertIsLessOrEqual(frontend.Variable(55), dataLength)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(255))
	prefix1 := frontend.Variable(byte(183) + 1)
	prefix2 := dataLength
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	prefixArray = append(prefixArray, prefix2)
	sliceApi := NewSliceApi(api)
	return sliceApi.Append(data, prefixArray, data.IsLittleEndian, true)
}

// Rule3: data length >55,data length can be expressed in two byte
func (rlpEncode *RlpEncode) EncodeRule3_TwoBytesSlice(data PaddingSlice) PaddingSlice {
	api := rlpEncode.api
	dataLength := data.Len(api)
	api.AssertIsLessOrEqual(frontend.Variable(55), dataLength)
	api.AssertIsLessOrEqual(frontend.Variable(255), dataLength)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(65535))
	prefix1 := frontend.Variable(183 + 2)
	dataLengthBytes := IntToBytesVarible(api, dataLength)
	prefix2 := dataLengthBytes[2]
	prefix3 := dataLengthBytes[3]
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	prefixArray = append(prefixArray, prefix2)
	prefixArray = append(prefixArray, prefix3)
	sliceApi := NewSliceApi(api)
	return sliceApi.Append(data, prefixArray, data.IsLittleEndian, true)
}

// Rule4: data list length <55
func (rlpEncode *RlpEncode) EncodeRule4Slice(data []PaddingSlice) PaddingSlice {
	api := rlpEncode.api
	dataLength := frontend.Variable(0)
	for i := 0; i < len(data); i++ {
		dataLength = api.Add(dataLength, data[i].Len(api))
	}
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(55))
	prefix1 := IntToBytesVarible(api, api.Add(frontend.Variable(192), dataLength))[3]
	sliceApi := NewSliceApi(api)
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	var result = data[0]
	for i := 0; i < len(data); i++ {
		result = sliceApi.concat(result, data[i], data[i].IsLittleEndian)
	}
	return sliceApi.Append(result, prefixArray, result.IsLittleEndian, true)
}

// Rule5: data list length >55,data list length can be expressed in one byte
func (rlpEncode *RlpEncode) EncodeRule5_OneByteSlice(data []PaddingSlice) PaddingSlice {
	api := rlpEncode.api
	dataLength := frontend.Variable(0)
	for i := 0; i < len(data); i++ {
		dataLength = api.Add(dataLength, data[i].Len(api))
	}
	api.AssertIsLessOrEqual(frontend.Variable(55), dataLength)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(255))
	prefix1 := frontend.Variable(byte(247) + 1)
	dataLengthBytes := IntToBytesVarible(api, dataLength)
	prefix2 := dataLengthBytes[3]
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	prefixArray = append(prefixArray, prefix2)
	var result = data[0]
	sliceApi := NewSliceApi(api)
	for i := 0; i < len(data); i++ {
		result = sliceApi.concat(result, data[i], data[i].IsLittleEndian)
	}
	return sliceApi.Append(result, prefixArray, result.IsLittleEndian, true)
}

// Rule5: data list length >55,data list length can be expressed in two bytes
func (rlpEncode *RlpEncode) EncodeRule5_TwoBytesSlice(data []PaddingSlice) PaddingSlice {
	api := rlpEncode.api
	dataLength := frontend.Variable(0)
	for i := 0; i < len(data); i++ {
		dataLength = api.Add(dataLength, data[i].Len(api))
	}
	api.AssertIsLessOrEqual(frontend.Variable(55), dataLength)
	api.AssertIsLessOrEqual(frontend.Variable(255), dataLength)
	api.AssertIsLessOrEqual(dataLength, frontend.Variable(65535))
	prefix1 := frontend.Variable(byte(247) + 2)
	dataLengthBytes := IntToBytesVarible(api, dataLength)
	prefix2 := dataLengthBytes[2]
	prefix3 := dataLengthBytes[3]
	var prefixArray []frontend.Variable
	prefixArray = append(prefixArray, prefix1)
	prefixArray = append(prefixArray, prefix2)
	prefixArray = append(prefixArray, prefix3)
	sliceApi := NewSliceApi(api)
	var result = data[0]
	for i := 0; i < len(data); i++ {
		result = sliceApi.concat(result, data[i], data[i].IsLittleEndian)
	}
	return sliceApi.Append(result, prefixArray, result.IsLittleEndian, true)
}

func IntToBytesVarible(api frontend.API, x frontend.Variable) []frontend.Variable {
	xbits := api.ToBinary(x)
	xbits = append(xbits, frontend.Variable(0), frontend.Variable(0))
	result := make([]frontend.Variable, len(xbits)/8)
	for i := 0; i < len(result); i++ {
		result[i] = api.FromBinary(xbits[i*8 : (i+1)*8]...)
	}
	slices.Reverse(result)
	return result
}
