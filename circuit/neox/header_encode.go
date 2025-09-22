package circuit

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/selector"
)

type HeaderEncoder struct {
	api frontend.API
}

func NewHeaderEncoder(api frontend.API) HeaderEncoder {
	return HeaderEncoder{api: api}
}
func (h *HeaderEncoder) Encode(header HeaderParameters, extraVersion byte) ([]frontend.Variable, error) {
	switch extraVersion {
	case ExtraV0:
		return h.encodeV0Header(header)
	case ExtraV1, ExtraV2:
		return h.encodeV1OrV2Header(header)
	default:
		return nil, fmt.Errorf("unknown header version %v", extraVersion)
	}
}

func (h *HeaderEncoder) encodeV0Header(header HeaderParameters) ([]frontend.Variable, error) {
	api := h.api
	v := header.Extra[0]
	// Extra[0] == 0

	api.AssertIsEqual(v, ExtraV0)
	rlp := NewRlpEncode(api)
	encodeHeader1 := make([][]frontend.Variable, 8)
	encodeHeader1[0] = rlp.EncodeRule2(header.ParentHash[:])
	encodeHeader1[1] = rlp.EncodeRule2(header.UncleHash[:])
	encodeHeader1[2] = rlp.EncodeRule2(header.Coinbase[:])
	encodeHeader1[3] = rlp.EncodeRule2(header.Root[:])
	encodeHeader1[4] = rlp.EncodeRule2(header.TxHash[:])
	encodeHeader1[5] = rlp.EncodeRule2(header.ReceiptHash[:])
	encodeHeader1[6] = rlp.EncodeRule3_TwoBytes(header.Bloom[:])
	encodeHeader1[7] = rlp.EncodeRule1([]frontend.Variable{header.Difficulty[7]})

	encodeHeader2 := make([][]frontend.Variable, 5)
	// here hashableExtraLen is fixed in circuit
	// so we can use "if"
	if len(header.Extra) == 1 {
		encodeHeader2[0] = rlp.EncodeRule1(header.Extra[:]) // here v0 and v1/v2 is different
	} else {
		encodeHeader2[0] = rlp.EncodeRule3_TwoBytes(header.Extra[:])
	}
	encodeHeader2[1] = rlp.EncodeRule2(header.MixDigest[:])
	encodeHeader2[2] = rlp.EncodeRule2(header.Nonce[:])
	encodeHeader2[3] = rlp.EncodeRule2(header.BaseFee[3:])
	encodeHeader2[4] = rlp.EncodeRule2(header.WithdrawalsHash[:])

	unfixSlice := make([]PaddingSlice, 4)
	sApi := NewSliceApi(api)
	numberSlice := sApi.New(api, header.Number[:], false)
	unfixSlice[0] = rlp.EncodeRule1And2Slice(numberSlice)
	gasLimitSlice := sApi.New(api, header.GasLimit[:], false)
	unfixSlice[1] = rlp.EncodeRule1And2Slice(gasLimitSlice)
	gasUsedSlice := sApi.New(api, header.GasUsed[:], false)
	unfixSlice[2] = rlp.EncodeRule1And2Slice(gasUsedSlice)
	timeSlice := sApi.New(api, header.Time[:], false)
	unfixSlice[3] = rlp.EncodeRule1And2Slice(timeSlice)

	resultSlice := unfixSlice[0]
	for i := 1; i < 4; i++ {
		resultSlice = sApi.concat(resultSlice, unfixSlice[i], false)
	}
	generator := func(api frontend.API) []UndeterminedSlice {
		slices := make([]UndeterminedSlice, 0)
		isEmpty := api.And(api.IsZero(api.Sub(len(resultSlice.Slice)-2, resultSlice.Padding)), api.IsZero(selector.Mux(api, len(resultSlice.Slice)-1, resultSlice.Slice...))) // == 0
		for i := 0; i < len(resultSlice.Slice); i++ {
			slices = append(slices, UndeterminedSlice{
				Variables: resultSlice.Slice[i:],
				// zeroNumber == len(hbytes) - 1 - i && !isZero
				// isZero == 1 -> isSelect = 0
				// isZero == 0, len(hbytes) - 1 - i - zeroNumber == 0 -> isSelect = 1
				IsSelected: api.Mul(api.IsZero(isEmpty), api.IsZero(api.Sub(i-1, resultSlice.Padding))), // suffix = 1, and current = 1
			})
		}
		slices = append(slices, UndeterminedSlice{
			Variables:  []frontend.Variable{},
			IsSelected: isEmpty,
		})
		return slices
	}

	sliceComposer := NewSliceComposer(api)
	fn := func(api frontend.API, slices ...UndeterminedSlice) (DeterminedSlice, error) {
		data := slices[0].Variables
		r := append(encodeHeader1, data)
		r = append(r, encodeHeader2...)
		result := rlp.EncodeRule5_TwoBytes(r)
		kecczk256 := NewKeccak256(api)

		computeHash, err := kecczk256.Compute(result)
		//api.Println(slices[0].IsSelected, result)
		if err != nil {
			return nil, err
		}
		return computeHash[:], nil
	}
	result, err := sliceComposer.Process(32, fn, generator)
	//fmt.Println(result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (h *HeaderEncoder) encodeV1OrV2Header(header HeaderParameters) ([]frontend.Variable, error) {
	api := h.api
	v := header.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})

	rlp := NewRlpEncode(api)
	encodeHeader1 := make([][]frontend.Variable, 8)
	encodeHeader1[0] = rlp.EncodeRule2(header.ParentHash[:])
	encodeHeader1[1] = rlp.EncodeRule2(header.UncleHash[:])
	encodeHeader1[2] = rlp.EncodeRule2(header.Coinbase[:])
	encodeHeader1[3] = rlp.EncodeRule2(header.Root[:])
	encodeHeader1[4] = rlp.EncodeRule2(header.TxHash[:])
	encodeHeader1[5] = rlp.EncodeRule2(header.ReceiptHash[:])
	encodeHeader1[6] = rlp.EncodeRule3_TwoBytes(header.Bloom[:])
	encodeHeader1[7] = rlp.EncodeRule1([]frontend.Variable{header.Difficulty[7]})

	encodeHeader2 := make([][]frontend.Variable, 5)
	encodeHeader2[0] = rlp.EncodeRule3_OneByte(header.Extra)
	encodeHeader2[1] = rlp.EncodeRule2(header.MixDigest[:])
	encodeHeader2[2] = rlp.EncodeRule2(header.Nonce[:])
	encodeHeader2[3] = rlp.EncodeRule2(header.BaseFee[3:])
	encodeHeader2[4] = rlp.EncodeRule2(header.WithdrawalsHash[:])

	unfixSlice := make([]PaddingSlice, 4)
	sApi := NewSliceApi(api)
	numberSlice := sApi.New(api, header.Number[:], false)
	unfixSlice[0] = rlp.EncodeRule1And2Slice(numberSlice)
	gasLimitSlice := sApi.New(api, header.GasLimit[:], false)
	unfixSlice[1] = rlp.EncodeRule1And2Slice(gasLimitSlice)
	gasUsedSlice := sApi.New(api, header.GasUsed[:], false)
	unfixSlice[2] = rlp.EncodeRule1And2Slice(gasUsedSlice)
	timeSlice := sApi.New(api, header.Time[:], false)
	unfixSlice[3] = rlp.EncodeRule1And2Slice(timeSlice)

	resultSlice := unfixSlice[0]
	sliceApi := NewSliceApi(api)
	resultSlice = sliceApi.concat(resultSlice, unfixSlice[1], resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, unfixSlice[2], resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, unfixSlice[3], resultSlice.IsLittleEndian)
	generator := func(api frontend.API) []UndeterminedSlice {
		slices := make([]UndeterminedSlice, 0)
		isEmpty := api.And(api.IsZero(api.Sub(len(resultSlice.Slice)-2, resultSlice.Padding)), api.IsZero(selector.Mux(api, len(resultSlice.Slice)-1, resultSlice.Slice...))) // == 0
		for i := 0; i < len(resultSlice.Slice); i++ {
			slices = append(slices, UndeterminedSlice{
				Variables: resultSlice.Slice[i:],
				// zeroNumber == len(hbytes) - 1 - i && !isZero
				// isZero == 1 -> isSelect = 0
				// isZero == 0, len(hbytes) - 1 - i - zeroNumber == 0 -> isSelect = 1
				IsSelected: api.Mul(api.IsZero(isEmpty), api.IsZero(api.Sub(i-1, resultSlice.Padding))), // suffix = 1, and current = 1
			})
		}
		slices = append(slices, UndeterminedSlice{
			Variables:  []frontend.Variable{},
			IsSelected: isEmpty,
		})
		return slices
	}
	sliceComposer := NewSliceComposer(api)
	fn := func(api frontend.API, slices ...UndeterminedSlice) (DeterminedSlice, error) {
		data := slices[0].Variables
		r := append(encodeHeader1, data)
		r = append(r, encodeHeader2[0])
		r = append(r, encodeHeader2[1])
		r = append(r, encodeHeader2[2])
		r = append(r, encodeHeader2[3])
		r = append(r, encodeHeader2[4])

		result := rlp.EncodeRule5_TwoBytes(r)

		kecczk256 := NewKeccak256(api)
		computeHash, err := kecczk256.Compute(result)
		if err != nil {
			panic(err)
		}
		return computeHash[:], nil
	}
	result, err := sliceComposer.Process(32, fn, generator)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (h *HeaderEncoder) HashToG2(api frontend.API, header HeaderParameters) []frontend.Variable {
	hashableExtraLen := HashableExtraV1Len
	v := header.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})
	api.AssertIsEqual(hashableExtraLen, len(header.Extra))
	rlp := NewRlpEncode(api)
	encodeHeader1 := make([][]frontend.Variable, 8)
	encodeHeader1[0] = rlp.EncodeRule2(header.ParentHash[:])
	encodeHeader1[1] = rlp.EncodeRule2(header.UncleHash[:])
	encodeHeader1[2] = rlp.EncodeRule2(header.Coinbase[:])
	encodeHeader1[3] = rlp.EncodeRule2(header.Root[:])
	encodeHeader1[4] = rlp.EncodeRule2(header.TxHash[:])
	encodeHeader1[5] = rlp.EncodeRule2(header.ReceiptHash[:])
	encodeHeader1[6] = rlp.EncodeRule3_TwoBytes(header.Bloom[:])
	encodeHeader1[7] = rlp.EncodeRule1([]frontend.Variable{header.Difficulty[7]})

	encodeHeader2 := make([][]frontend.Variable, 5)
	encodeHeader2[0] = rlp.EncodeRule2(header.Extra[:hashableExtraLen])
	encodeHeader2[1] = rlp.EncodeRule2(header.MixDigest[:])
	encodeHeader2[2] = rlp.EncodeRule2(header.Nonce[:])
	encodeHeader2[3] = rlp.EncodeRule2(header.BaseFee[3:])
	encodeHeader2[4] = rlp.EncodeRule2(header.WithdrawalsHash[:])

	unfixSlice := make([]PaddingSlice, 4)
	sApi := NewSliceApi(api)
	numberSlice := sApi.New(api, header.Number[:], false)
	unfixSlice[0] = rlp.EncodeRule1And2Slice(numberSlice)
	gasLimitSlice := sApi.New(api, header.GasLimit[:], false)
	unfixSlice[1] = rlp.EncodeRule1And2Slice(gasLimitSlice)
	gasUsedSlice := sApi.New(api, header.GasUsed[:], false)
	unfixSlice[2] = rlp.EncodeRule1And2Slice(gasUsedSlice)
	timeSlice := sApi.New(api, header.Time[:], false)
	unfixSlice[3] = rlp.EncodeRule1And2Slice(timeSlice)

	resultSlice := unfixSlice[0]
	sliceApi := NewSliceApi(api)
	resultSlice = sliceApi.concat(resultSlice, unfixSlice[1], resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, unfixSlice[2], resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, unfixSlice[3], resultSlice.IsLittleEndian)
	generator := func(api frontend.API) []UndeterminedSlice {
		slices := make([]UndeterminedSlice, 0)
		isEmpty := api.And(api.IsZero(api.Sub(len(resultSlice.Slice)-2, resultSlice.Padding)), api.IsZero(selector.Mux(api, len(resultSlice.Slice)-1, resultSlice.Slice...))) // == 0
		for i := 0; i < len(resultSlice.Slice); i++ {
			slices = append(slices, UndeterminedSlice{
				Variables: resultSlice.Slice[i:],
				// zeroNumber == len(hbytes) - 1 - i && !isZero
				// isZero == 1 -> isSelect = 0
				// isZero == 0, len(hbytes) - 1 - i - zeroNumber == 0 -> isSelect = 1
				IsSelected: api.Mul(api.IsZero(isEmpty), api.IsZero(api.Sub(i-1, resultSlice.Padding))), // suffix = 1, and current = 1
			})
		}
		slices = append(slices, UndeterminedSlice{
			Variables:  []frontend.Variable{},
			IsSelected: isEmpty,
		})
		return slices
	}
	sliceComposer := NewSliceComposer(api)
	fn := func(api frontend.API, slices ...UndeterminedSlice) (DeterminedSlice, error) {
		s := slices[0].Variables
		r := append(encodeHeader1, s)
		r = append(r, encodeHeader2[0])
		r = append(r, encodeHeader2[1])
		r = append(r, encodeHeader2[2])
		r = append(r, encodeHeader2[3])
		r = append(r, encodeHeader2[4])

		data := rlp.EncodeRule5_TwoBytes(r)
		//api.Println(data)
		u8data := make([]uints.U8, len(data))
		uapi, err := uints.New[uints.U32](api)
		if err != nil {
			panic(err)
		}
		for i := 0; i < len(data); i++ {
			u8data[i] = uapi.ByteValueOf(data[i])
		}
		g2, err := sw_bls12381.NewG2(api)
		if err != nil {
			panic(err)
		}
		hash, err := g2.HashToG2(api, u8data, BLSDomain)
		if err != nil {
			panic(err)
		}
		hashBytes, err := g2.ToCompressedBytes(*hash)
		if err != nil {
			panic(err)
		}
		hashArry := make([]frontend.Variable, len(hashBytes))
		for i := 0; i < len(hashBytes); i++ {
			hashArry[i] = hashBytes[i].Val
		}
		return hashArry, nil
	}
	result, err := sliceComposer.Process(96, fn, generator)
	if err != nil {
		panic(err)
	}
	return result
}
