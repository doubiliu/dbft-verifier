package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/selector"
)

type HeaderParameters struct {
	ParentHash  []frontend.Variable
	UncleHash   []frontend.Variable
	Coinbase    []frontend.Variable
	Root        []frontend.Variable
	TxHash      []frontend.Variable
	ReceiptHash []frontend.Variable
	Bloom       []frontend.Variable
	Difficulty  []frontend.Variable
	Number      []frontend.Variable
	GasLimit    []frontend.Variable
	GasUsed     []frontend.Variable
	Time        []frontend.Variable
	Extra       []frontend.Variable
	MixDigest   []frontend.Variable
	Nonce       []frontend.Variable

	BaseFee         []frontend.Variable
	WithdrawalsHash []frontend.Variable
}

func NewHeaderEncode(api frontend.API) HeaderEncode {
	return HeaderEncode{api: api}
}

type HeaderEncode struct {
	api frontend.API
}

func switchFilter2(api frontend.API, x frontend.Variable, limits []frontend.Variable, results []frontend.Variable) frontend.Variable {
	fbits := make([]frontend.Variable, len(limits))
	xbits := bits.ToBinary(api, x)
	for i := 0; i < len(limits); i++ {
		//if x is a member within the value range, the result of XOR with the member of the value range is 0
		lbits := bits.ToBinary(api, limits[i])
		tbits := make([]frontend.Variable, len(lbits))
		for j := 0; j < len(lbits); j++ {
			tbits[j] = api.Xor(xbits[j], lbits[j])
		}
		ri := frontend.Variable(false)
		for j := 0; j < len(tbits)-1; j++ {
			ri = api.Or(ri, api.And(tbits[j], tbits[j+1]))
		}
		fbits[i] = ri
	}
	flag := frontend.Variable(true)
	result := results[0]
	//If an XOR result is 0, then x is within the value range
	for i := 0; i < len(fbits); i++ {
		flag = api.And(flag, fbits[i])
		result = api.Select(fbits[i], result, results[i])
	}
	//neg
	flag = api.Select(flag, frontend.Variable(false), frontend.Variable(true))
	//check if x is in limits
	api.AssertIsEqual(flag, frontend.Variable(true))
	return result
}

func rangeCheck(api frontend.API, x frontend.Variable, limits []frontend.Variable) {
	flag := frontend.Variable(0)
	for i := 0; i < len(limits); i++ {
		subValue := api.Sub(x, limits[i])
		f := api.IsZero(subValue)
		flag = api.Select(f, f, flag)
	}
	//check if x is in limits
	api.AssertIsEqual(flag, frontend.Variable(1))
}

func (headerEncode *HeaderEncode) EncodeSigHeader(api frontend.API, header HeaderParameters) []frontend.Variable {
	hashableExtraLen := HashableExtraV1Len
	v := header.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})

	rlp := NewRlpEncode(api)
	encodeHeader := make([][]frontend.Variable, 17)
	encodeHeader[0] = rlp.EncodeRule2(api, header.ParentHash)
	encodeHeader[1] = rlp.EncodeRule2(api, header.UncleHash)
	encodeHeader[2] = rlp.EncodeRule2(api, header.Coinbase)
	encodeHeader[3] = rlp.EncodeRule2(api, header.Root)
	encodeHeader[4] = rlp.EncodeRule2(api, header.TxHash)
	encodeHeader[5] = rlp.EncodeRule2(api, header.ReceiptHash)
	encodeHeader[6] = rlp.EncodeRule3_TwoBytes(api, header.Bloom)
	encodeHeader[7] = rlp.EncodeRule1(api, header.Difficulty)
	encodeHeader[8] = rlp.EncodeRule2(api, header.Number)
	encodeHeader[9] = rlp.EncodeRule2(api, header.GasLimit)
	encodeHeader[10] = rlp.EncodeRule2(api, header.GasUsed)
	encodeHeader[11] = rlp.EncodeRule2(api, header.Time)
	encodeHeader[12] = rlp.EncodeRule2(api, header.Extra[:hashableExtraLen])
	encodeHeader[13] = rlp.EncodeRule2(api, header.MixDigest)
	encodeHeader[14] = rlp.EncodeRule2(api, header.Nonce)
	encodeHeader[15] = rlp.EncodeRule2(api, header.BaseFee)
	encodeHeader[16] = rlp.EncodeRule2(api, header.WithdrawalsHash)

	return rlp.EncodeRule5_TwoBytes(api, encodeHeader)
	//api.Println(extraData)
}

func (headerEncode *HeaderEncode) RlpHash(api frontend.API, header HeaderParameters) []frontend.Variable {
	v := header.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})

	rlp := NewRlpEncode(api)
	encodeHeader1 := make([][]frontend.Variable, 8)
	encodeHeader1[0] = rlp.EncodeRule2(api, header.ParentHash)
	encodeHeader1[1] = rlp.EncodeRule2(api, header.UncleHash)
	encodeHeader1[2] = rlp.EncodeRule2(api, header.Coinbase)
	encodeHeader1[3] = rlp.EncodeRule2(api, header.Root)
	encodeHeader1[4] = rlp.EncodeRule2(api, header.TxHash)
	encodeHeader1[5] = rlp.EncodeRule2(api, header.ReceiptHash)
	encodeHeader1[6] = rlp.EncodeRule3_TwoBytes(api, header.Bloom)
	encodeHeader1[7] = rlp.EncodeRule1(api, header.Difficulty)

	encodeHeader2 := make([][]frontend.Variable, 5)
	encodeHeader2[0] = rlp.EncodeRule3_OneByte(api, header.Extra)
	encodeHeader2[1] = rlp.EncodeRule2(api, header.MixDigest)
	encodeHeader2[2] = rlp.EncodeRule2(api, header.Nonce)
	encodeHeader2[3] = rlp.EncodeRule2(api, header.BaseFee)
	encodeHeader2[4] = rlp.EncodeRule2(api, header.WithdrawalsHash)

	unfixSlice := make([]PaddingSlice, 2)
	sApi := NewSliceApi(api)
	numberSlice := sApi.New(api, header.Number, false)
	unfixSlice[0] = rlp.EncodeRule2Slice(api, numberSlice)
	/*	gasLimitSlice := sApi.New(api, header.GasLimit, false)
		unfixSlice[1] = rlp.EncodeRule2Slice(api, gasLimitSlice)*/
	gaslimite := rlp.EncodeRule2(api, header.GasLimit)
	gasUsed := rlp.EncodeRule2(api, header.GasUsed)
	/*	gasUsedSlice := sApi.New(api, header.GasUsed, false)
		unfixSlice[1] = rlp.EncodeRule2Slice(api, gasUsedSlice)*/
	timeSlice := sApi.New(api, header.Time, false)
	unfixSlice[1] = rlp.EncodeRule2Slice(api, timeSlice)

	resultSlice := unfixSlice[0]
	sliceApi := NewSliceApi(api)
	resultSlice = sliceApi.Append(resultSlice, gaslimite, false, false)
	//api.Println(resultSlice.Slice)
	resultSlice = sliceApi.Append(resultSlice, gasUsed, false, false)
	resultSlice = sliceApi.concat(resultSlice, unfixSlice[1], resultSlice.IsLittleEndian)
	//resultSlice = sliceApi.concat(resultSlice, unfixSlice[2], resultSlice.IsLittleEndian)
	//resultSlice = sliceApi.concat(resultSlice, unfixSlice[3], resultSlice.IsLittleEndian)
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

		result := rlp.EncodeRule5_TwoBytes(api, r)

		//fmt.Println(result)

		kecczk256 := NewKeccak256(api)
		computeHash := kecczk256.Compute(result)
		return computeHash[:], nil
	}
	result, err := sliceComposer.Process(32, fn, generator)
	if err != nil {
		panic(err)
	}
	return result
}

func (headerEncode *HeaderEncode) HashToG2(api frontend.API, header HeaderParameters) []frontend.Variable {
	hashableExtraLen := HashableExtraV1Len
	v := header.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})

	rlp := NewRlpEncode(api)
	encodeHeader1 := make([][]frontend.Variable, 8)
	encodeHeader1[0] = rlp.EncodeRule2(api, header.ParentHash)
	encodeHeader1[1] = rlp.EncodeRule2(api, header.UncleHash)
	encodeHeader1[2] = rlp.EncodeRule2(api, header.Coinbase)
	encodeHeader1[3] = rlp.EncodeRule2(api, header.Root)
	encodeHeader1[4] = rlp.EncodeRule2(api, header.TxHash)
	encodeHeader1[5] = rlp.EncodeRule2(api, header.ReceiptHash)
	encodeHeader1[6] = rlp.EncodeRule3_TwoBytes(api, header.Bloom)
	encodeHeader1[7] = rlp.EncodeRule1(api, header.Difficulty)

	encodeHeader2 := make([][]frontend.Variable, 5)
	encodeHeader2[0] = rlp.EncodeRule2(api, header.Extra[:hashableExtraLen])
	encodeHeader2[1] = rlp.EncodeRule2(api, header.MixDigest)
	encodeHeader2[2] = rlp.EncodeRule2(api, header.Nonce)
	encodeHeader2[3] = rlp.EncodeRule2(api, header.BaseFee)
	encodeHeader2[4] = rlp.EncodeRule2(api, header.WithdrawalsHash)

	unfixSlice := make([]PaddingSlice, 2)
	sApi := NewSliceApi(api)
	numberSlice := sApi.New(api, header.Number, false)
	unfixSlice[0] = rlp.EncodeRule2Slice(api, numberSlice)

	/*	gasLimitSlice := sApi.New(api, header.GasLimit, false)
		unfixSlice[1] = rlp.EncodeRule2Slice(api, gasLimitSlice)*/
	gaslimit := rlp.EncodeRule2(api, header.GasLimit)
	gasUsed := rlp.EncodeRule2(api, header.GasUsed)
	/*	gasUsedSlice := sApi.New(api, header.GasUsed, false)
		unfixSlice[1] = rlp.EncodeRule2Slice(api, gasUsedSlice)*/
	timeSlice := sApi.New(api, header.Time, false)
	unfixSlice[1] = rlp.EncodeRule2Slice(api, timeSlice)

	resultSlice := unfixSlice[0]
	sliceApi := NewSliceApi(api)
	resultSlice = sliceApi.Append(resultSlice, gaslimit, false, false)
	//api.Println(resultSlice.Slice)
	resultSlice = sliceApi.Append(resultSlice, gasUsed, false, false)
	resultSlice = sliceApi.concat(resultSlice, unfixSlice[1], resultSlice.IsLittleEndian)
	//resultSlice = sliceApi.concat(resultSlice, unfixSlice[2], resultSlice.IsLittleEndian)
	//resultSlice = sliceApi.concat(resultSlice, unfixSlice[3], resultSlice.IsLittleEndian)
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

		data := rlp.EncodeRule5_TwoBytes(api, r)
		//fmt.Println(result)
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
		marshaBits := g2.Marshal(*hash)
		hashBytes := make([]frontend.Variable, len(marshaBits)/8)
		for i := 0; i < len(hashBytes); i++ {
			tbits := marshaBits[i*8 : (i+1)*8]
			treversebits := make([]frontend.Variable, len(tbits))
			for j := 0; j < len(tbits); j++ {
				treversebits[j] = tbits[len(tbits)-j-1]
			}
			hashBytes[i] = api.FromBinary(treversebits...)
		}
		return hashBytes, nil
	}
	result, err := sliceComposer.Process(192, fn, generator)
	if err != nil {
		panic(err)
	}
	return result
}

func (headerEncode *HeaderEncode) EncodeHeader(api frontend.API, header HeaderParameters) []frontend.Variable {
	//hashableExtraLen := HashableExtraV1Len
	v := header.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})

	rlp := NewRlpEncode(api)
	encodeHeader := make([][]frontend.Variable, 17)
	encodeHeader[0] = rlp.EncodeRule2(api, header.ParentHash)
	encodeHeader[1] = rlp.EncodeRule2(api, header.UncleHash)
	encodeHeader[2] = rlp.EncodeRule2(api, header.Coinbase)
	encodeHeader[3] = rlp.EncodeRule2(api, header.Root)
	encodeHeader[4] = rlp.EncodeRule2(api, header.TxHash)
	encodeHeader[5] = rlp.EncodeRule2(api, header.ReceiptHash)
	encodeHeader[6] = rlp.EncodeRule3_TwoBytes(api, header.Bloom)
	encodeHeader[7] = rlp.EncodeRule1(api, header.Difficulty)
	encodeHeader[8] = rlp.EncodeRule2(api, header.Number)
	encodeHeader[9] = rlp.EncodeRule2(api, header.GasLimit)
	encodeHeader[10] = rlp.EncodeRule2(api, header.GasUsed)
	encodeHeader[11] = rlp.EncodeRule2(api, header.Time)
	encodeHeader[12] = rlp.EncodeRule3_OneByte(api, header.Extra)
	encodeHeader[13] = rlp.EncodeRule2(api, header.MixDigest)
	encodeHeader[14] = rlp.EncodeRule2(api, header.Nonce)
	encodeHeader[15] = rlp.EncodeRule2(api, header.BaseFee)
	encodeHeader[16] = rlp.EncodeRule2(api, header.WithdrawalsHash)

	return rlp.EncodeRule5_TwoBytes(api, encodeHeader)
	//api.Println(extraData)
	/*	enc := make([]frontend.Variable, 0)
		enc = append(enc, header.ParentHash...)
		enc = append(enc, header.UncleHash...)
		enc = append(enc, header.Coinbase...)
		enc = append(enc, header.Root...)
		enc = append(enc, header.TxHash...)
		enc = append(enc, header.ReceiptHash...)
		enc = append(enc, header.Bloom...)
		enc = append(enc, header.Difficulty)
		enc = append(enc, header.Number)
		enc = append(enc, header.GasLimit)
		enc = append(enc, header.GasUsed)
		enc = append(enc, header.Time)
		enc = append(enc, header.Extra[:hashableExtraLen]...) // Yes, this will panic if extra is too short
		enc = append(enc, header.MixDigest...)
		enc = append(enc, header.Nonce...)
		/*	if header.BaseFee != nil {
			enc = append(enc, header.BaseFee)
		}*/
	//enc = append(enc, header.BaseFee)
	/*	if header.WithdrawalsHash != nil {
		enc = append(enc, header.WithdrawalsHash)
	}*/
	//enc = append(enc, header.WithdrawalsHash...)
	//return rlp.EncodeToBytes(enc)
	//return enc*/
}
