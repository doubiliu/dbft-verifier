package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/selector"
)

type HeaderParameters struct {
	ParentHash  [32]frontend.Variable
	UncleHash   [32]frontend.Variable
	Coinbase    [20]frontend.Variable
	Root        [32]frontend.Variable
	TxHash      [32]frontend.Variable
	ReceiptHash [32]frontend.Variable
	Bloom       [256]frontend.Variable
	Difficulty  [8]frontend.Variable
	Number      [8]frontend.Variable
	GasLimit    [8]frontend.Variable
	GasUsed     [8]frontend.Variable
	Time        [8]frontend.Variable
	Extra       []frontend.Variable
	MixDigest   [32]frontend.Variable
	Nonce       [8]frontend.Variable

	BaseFee         [8]frontend.Variable
	WithdrawalsHash [32]frontend.Variable
}

type CutHeaderParameters struct {
	ParentHash []frontend.Variable
	Number     []frontend.Variable
	Time       []frontend.Variable
	Extra      []frontend.Variable
	MixDigest  []frontend.Variable
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

func (headerEncode *HeaderEncode) RlpHash(api frontend.API, header HeaderParameters) []frontend.Variable {
	v := header.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
	rangeCheck(api, v, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})

	rlp := NewRlpEncode(api)
	encodeHeader1 := make([][]frontend.Variable, 8)
	encodeHeader1[0] = rlp.EncodeRule2(api, header.ParentHash[:])
	encodeHeader1[1] = rlp.EncodeRule2(api, header.UncleHash[:])
	encodeHeader1[2] = rlp.EncodeRule2(api, header.Coinbase[:])
	encodeHeader1[3] = rlp.EncodeRule2(api, header.Root[:])
	encodeHeader1[4] = rlp.EncodeRule2(api, header.TxHash[:])
	encodeHeader1[5] = rlp.EncodeRule2(api, header.ReceiptHash[:])
	encodeHeader1[6] = rlp.EncodeRule3_TwoBytes(api, header.Bloom[:])
	encodeHeader1[7] = rlp.EncodeRule1(api, []frontend.Variable{header.Difficulty[7]})

	encodeHeader2 := make([][]frontend.Variable, 5)
	encodeHeader2[0] = rlp.EncodeRule3_OneByte(api, header.Extra)
	encodeHeader2[1] = rlp.EncodeRule2(api, header.MixDigest[:])
	encodeHeader2[2] = rlp.EncodeRule2(api, header.Nonce[:])
	encodeHeader2[3] = rlp.EncodeRule2(api, header.BaseFee[3:])
	encodeHeader2[4] = rlp.EncodeRule2(api, header.WithdrawalsHash[:])

	unfixSlice := make([]PaddingSlice, 4)
	sApi := NewSliceApi(api)
	numberSlice := sApi.New(api, header.Number[:], false)
	unfixSlice[0] = rlp.EncodeRule2Slice(api, numberSlice)
	gasLimitSlice := sApi.New(api, header.GasLimit[:], false)
	unfixSlice[1] = rlp.EncodeRule2Slice(api, gasLimitSlice)
	gasUsedSlice := sApi.New(api, header.GasUsed[:], false)
	unfixSlice[2] = rlp.EncodeRule2Slice(api, gasUsedSlice)
	timeSlice := sApi.New(api, header.Time[:], false)
	unfixSlice[3] = rlp.EncodeRule2Slice(api, timeSlice)

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

		result := rlp.EncodeRule5_TwoBytes(api, r)

		//fmt.Println(result)

		kecczk256 := NewKeccak256(api)
		computeHash, err := kecczk256.Compute(result)
		if err != nil {
			panic(err)
		}
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
	encodeHeader1[0] = rlp.EncodeRule2(api, header.ParentHash[:])
	encodeHeader1[1] = rlp.EncodeRule2(api, header.UncleHash[:])
	encodeHeader1[2] = rlp.EncodeRule2(api, header.Coinbase[:])
	encodeHeader1[3] = rlp.EncodeRule2(api, header.Root[:])
	encodeHeader1[4] = rlp.EncodeRule2(api, header.TxHash[:])
	encodeHeader1[5] = rlp.EncodeRule2(api, header.ReceiptHash[:])
	encodeHeader1[6] = rlp.EncodeRule3_TwoBytes(api, header.Bloom[:])
	encodeHeader1[7] = rlp.EncodeRule1(api, []frontend.Variable{header.Difficulty[7]})

	encodeHeader2 := make([][]frontend.Variable, 5)
	encodeHeader2[0] = rlp.EncodeRule2(api, header.Extra[:hashableExtraLen])
	encodeHeader2[1] = rlp.EncodeRule2(api, header.MixDigest[:])
	encodeHeader2[2] = rlp.EncodeRule2(api, header.Nonce[:])
	encodeHeader2[3] = rlp.EncodeRule2(api, header.BaseFee[3:])
	encodeHeader2[4] = rlp.EncodeRule2(api, header.WithdrawalsHash[:])

	unfixSlice := make([]PaddingSlice, 4)
	sApi := NewSliceApi(api)
	numberSlice := sApi.New(api, header.Number[:], false)
	unfixSlice[0] = rlp.EncodeRule2Slice(api, numberSlice)
	gasLimitSlice := sApi.New(api, header.GasLimit[:], false)
	unfixSlice[1] = rlp.EncodeRule2Slice(api, gasLimitSlice)
	gasUsedSlice := sApi.New(api, header.GasUsed[:], false)
	unfixSlice[2] = rlp.EncodeRule2Slice(api, gasUsedSlice)
	timeSlice := sApi.New(api, header.Time[:], false)
	unfixSlice[3] = rlp.EncodeRule2Slice(api, timeSlice)

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

		data := rlp.EncodeRule5_TwoBytes(api, r)
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
		/*		hashBytes := make([]frontend.Variable, len(marshaBits)/8)
				for i := 0; i < len(hashBytes); i++ {
					tbits := marshaBits[i*8 : (i+1)*8]
					treversebits := make([]frontend.Variable, len(tbits))
					for j := 0; j < len(tbits); j++ {
						treversebits[j] = tbits[len(tbits)-j-1]
					}
					hashBytes[i] = api.FromBinary(treversebits...)
				}*/
		return hashArry, nil
	}
	result, err := sliceComposer.Process(96, fn, generator)
	if err != nil {
		panic(err)
	}
	return result
}

type HeaderRLPEncodeVerifyWrapper struct {
	Input []frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *HeaderRLPEncodeVerifyWrapper) Define(api frontend.API) error {
	RLPHash := c.Input[:32]
	Input := c.Input[32:]
	header := Deserialize(Input)
	encode := NewHeaderEncode(api)
	rlpHash := encode.RlpHash(api, header)
	for i := 0; i < len(rlpHash); i++ {
		api.AssertIsEqual(rlpHash[i], RLPHash[i])
	}
	return nil
}
func Serialize(header HeaderParameters) []frontend.Variable {
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
	input = append(input, header.MixDigest[:]...)
	input = append(input, header.Nonce[:]...)
	input = append(input, header.BaseFee[:]...)
	input = append(input, header.WithdrawalsHash[:]...)
	input = append(input, header.Extra...)
	return input
}
func Deserialize(input []frontend.Variable) HeaderParameters {
	index := 0
	var header HeaderParameters
	copy(header.ParentHash[:], input[index:index+len(header.ParentHash)])
	index += len(header.ParentHash)
	copy(header.UncleHash[:], input[index:index+len(header.UncleHash)])
	index += len(header.UncleHash)
	copy(header.Coinbase[:], input[index:index+len(header.Coinbase)])
	index += len(header.Coinbase)
	copy(header.Root[:], input[index:index+len(header.Root)])
	index += len(header.Root)
	copy(header.TxHash[:], input[index:index+len(header.TxHash)])
	index += len(header.TxHash)
	copy(header.ReceiptHash[:], input[index:index+len(header.ReceiptHash)])
	index += len(header.ReceiptHash)
	copy(header.Bloom[:], input[index:index+len(header.Bloom)])
	index += len(header.Bloom)
	copy(header.Difficulty[:], input[index:index+len(header.Difficulty)])
	index += len(header.Difficulty)
	copy(header.Number[:], input[index:index+len(header.Number)])
	index += len(header.Number)
	copy(header.GasLimit[:], input[index:index+len(header.GasLimit)])
	index += len(header.GasLimit)
	copy(header.GasUsed[:], input[index:index+len(header.GasUsed)])
	index += len(header.GasUsed)
	copy(header.Time[:], input[index:index+len(header.Time)])
	index += len(header.Time)
	copy(header.MixDigest[:], input[index:index+len(header.MixDigest)])
	index += len(header.MixDigest)
	copy(header.Nonce[:], input[index:index+len(header.Nonce)])
	index += len(header.Nonce)
	copy(header.BaseFee[:], input[index:index+len(header.BaseFee)])
	index += len(header.BaseFee)
	copy(header.WithdrawalsHash[:], input[index:index+len(header.WithdrawalsHash)])
	index += len(header.WithdrawalsHash)
	header.Extra = make([]frontend.Variable, len(input[index:]))
	copy(header.Extra[:], input[index:])
	return header
}

type HeaderHashToG2VerifyWrapper struct {
	Input []frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *HeaderHashToG2VerifyWrapper) Define(api frontend.API) error {
	ToG2Hash := c.Input[:96]
	Input := c.Input[96:]
	header := Deserialize(Input)
	encode := NewHeaderEncode(api)
	toG2Hash := encode.HashToG2(api, header)
	/*	api.Println(toG2Hash)
		api.Println(ToG2Hash)*/
	for i := 0; i < len(toG2Hash); i++ {
		api.AssertIsEqual(toG2Hash[i], ToG2Hash[i])
	}
	return nil
}
