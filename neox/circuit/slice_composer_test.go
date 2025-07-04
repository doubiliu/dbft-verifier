package circuit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"slices"

	//"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

// 这里我假设有两个（可以扩展到n个）的slice，要做某个操作（比如去掉前导0）
// 每个generator需要开发者编写一个函数返回一个结构体,UndeterminedSlice,其中Variable是一个slice(长度任意), isSelect是是否选择这个
// 每个generator会返回若干个slice，其中只有一个被选
func TestUndeterminedProgram(t *testing.T) {
	blockHeight := uint64(10000213)
	difficulty := uint64(234241)
	// no pre-0
	transformBytesWithNoPreZero := func(num uint64) []byte {
		originBytes := binary.LittleEndian.AppendUint64([]byte{}, num)
		for i := len(originBytes) - 1; i >= 0; i-- {
			if originBytes[i] != 0 {
				originBytes = originBytes[:i+1]
				break
			}
		}
		return originBytes
	}
	noZeroHbytes := transformBytesWithNoPreZero(blockHeight)
	noZeroDbytes := transformBytesWithNoPreZero(difficulty)

	preImage := append(noZeroHbytes, noZeroDbytes...) // little-endian
	preImageCopy := make([]byte, len(preImage))
	copy(preImageCopy[:], preImage[:])
	fmt.Println(preImage)
	slices.Reverse(preImageCopy) // big-endian
	hash := crypto.Keccak256(preImageCopy)
	fmt.Println(preImageCopy)
	fmt.Println(hash)
	testHash := [32]frontend.Variable{}
	for i := 0; i < len(testHash); i++ {
		testHash[i] = hash[i]
	}
	Hbytes := make([]frontend.Variable, 32)
	Dbytes := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		if i < len(noZeroHbytes) {
			Hbytes[i] = noZeroHbytes[i]
		} else {
			Hbytes[i] = 0
		}
		if i < len(noZeroDbytes) {
			Dbytes[i] = noZeroDbytes[i]
		} else {
			Dbytes[i] = 0
		}
	}
	fmt.Println(Hbytes)
	fmt.Println(Dbytes)
	concat := make([]frontend.Variable, 64)
	for i := 0; i < 64; i++ {
		if i < len(preImage) {
			concat[i] = preImage[i]
		} else {
			concat[i] = 0
		}
	}
	slices.Reverse(concat)
	fmt.Println(concat)
	circuit := Keccak256UndeterminedChecker{
		BlockHeight: blockHeight,
		Difficulty:  difficulty,
		Hbytes: PaddingSlice{
			Padding:        len(noZeroHbytes),
			Slice:          Hbytes,
			IsLittleEndian: true,
		},
		Dbytes: PaddingSlice{
			Padding:        len(noZeroDbytes),
			Slice:          Dbytes,
			IsLittleEndian: true,
		},
		Concat: PaddingSlice{
			Padding:        63 - len(preImageCopy),
			Slice:          concat,
			IsLittleEndian: false,
		},

		Hash: testHash,
	}
	assignment := Keccak256UndeterminedChecker{
		BlockHeight: blockHeight,
		Difficulty:  difficulty,
		Hbytes: PaddingSlice{
			Padding: len(noZeroHbytes),
			Slice:   Hbytes,
		},
		Dbytes: PaddingSlice{
			Padding: len(noZeroDbytes),
			Slice:   Dbytes,
		},
		Concat: PaddingSlice{
			Padding: 63 - len(preImageCopy),
			Slice:   concat,
		},

		Hash: testHash,
	}
	//ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	//assert.NoError(t, err)
	//fmt.Println(ccs.GetNbConstraints())
	err := test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(t, err)

}

type Keccak256UndeterminedChecker struct {
	BlockHeight frontend.Variable // int
	Hbytes      PaddingSlice
	Difficulty  frontend.Variable // int
	Dbytes      PaddingSlice
	Concat      PaddingSlice
	Hash        [32]frontend.Variable `gnark:",public"`
}

func (c *Keccak256UndeterminedChecker) Define(api frontend.API) error {
	toBits := func(a []frontend.Variable) []frontend.Variable {
		bits := make([]frontend.Variable, 0)
		for _, v := range a {
			bits = append(bits, api.ToBinary(v, 8)...)
		}
		return bits
	}
	hbits := toBits(c.Hbytes.Slice)
	dbits := toBits(c.Dbytes.Slice)
	api.AssertIsEqual(api.FromBinary(hbits...), c.BlockHeight)
	api.AssertIsEqual(api.FromBinary(dbits...), c.Difficulty)
	sapi := NewSliceApi(api)
	err := sapi.CheckConcat(c.Concat, c.Hbytes, c.Dbytes)
	if err != nil {
		return err
	}
	// c.Concat是拼后的结果
	concatGenerator := func(api frontend.API) []UndeterminedSlice {
		slices := make([]UndeterminedSlice, 0)
		api.Println(c.Concat.Padding)
		for i := 0; i < len(c.Concat.Slice); i++ {
			slices = append(slices, UndeterminedSlice{
				Variables:  c.Concat.Slice[i:],
				IsSelected: api.IsZero(api.Sub(i-1, c.Concat.Padding)),
			})
			api.Println(slices[len(slices)-1].Variables)
			api.Println(slices[len(slices)-1].IsSelected)
		}
		return slices
	}
	//// 这里的两个generator本质上是一样的，其实可以写成一个func(api frontend.API, slice []frontend.Variable) -> func(api frontend.API) []UndeterminedSlice
	//// 函数里写return 下面把数组统一写的形式
	//// 这里考虑到只是这个例子是一样的逻辑，所以分开了
	//hBytesGenerator := func(api frontend.API) []UndeterminedSlice {
	//	fmt.Println("hBytes Selectors: ")
	//	slices := make([]UndeterminedSlice, 0)
	//	suffixSum := frontend.Variable(0)
	//	zeroNumber := frontend.Variable(0)
	//	for i := len(hBytes) - 1; i >= 0; i-- {
	//		suffixSum = api.Add(suffixSum, hBytes[i])
	//		isZero := api.IsZero(hBytes[i])
	//		slices = append(slices, UndeterminedSlice{
	//			Variables: hBytes[:i+1],
	//			// zeroNumber == len(hbytes) - 1 - i && !isZero
	//			// isZero == 1 -> isSelect = 0
	//			// isZero == 0, len(hbytes) - 1 - i - zeroNumber == 0 -> isSelect = 1
	//			IsSelected: api.Mul(api.Sub(1, isZero), api.IsZero(api.Sub(len(hBytes)-1-i, zeroNumber))), // suffix = 1, and current = 1
	//		})
	//		api.Println(slices[len(slices)-1].Variables)
	//		api.Println(slices[len(slices)-1].IsSelected)
	//		zeroNumber = api.Add(zeroNumber, isZero)
	//	}
	//	return slices
	//}
	//
	//dBytesGenerator := func(api frontend.API) []UndeterminedSlice {
	//	fmt.Println("dBytes Selectors: ")
	//	slices := make([]UndeterminedSlice, 0)
	//	suffixSum := frontend.Variable(0)
	//	zeroNumber := frontend.Variable(0)
	//	for i := len(dBytes) - 1; i >= 0; i-- {
	//		suffixSum = api.Add(suffixSum, dBytes[i])
	//		isZero := api.IsZero(dBytes[i])
	//		slices = append(slices, UndeterminedSlice{
	//			Variables: dBytes[:i+1],
	//			// zeroNumber == len(dbytes) - 1 - i && !isZero
	//			// isZero == 1 -> isSelect = 0
	//			// isZero == 0, len(dbytes) - 1 - zeroNumber == 0 -> isSelect = 1
	//			IsSelected: api.Mul(api.Sub(1, isZero), api.IsZero(api.Sub(len(dBytes)-1-i, zeroNumber))), // suffix = 1, and current = 1
	//		})
	//		api.Println(slices[len(slices)-1].Variables)
	//		api.Println(slices[len(slices)-1].IsSelected)
	//		zeroNumber = api.Add(zeroNumber, isZero)
	//	}
	//	return slices
	//
	//}
	sliceComposer := NewSliceComposer(api)
	fn := func(api frontend.API, slices ...UndeterminedSlice) (DeterminedSlice, error) {
		preImage := make([]frontend.Variable, 0)
		for _, slice := range slices {
			preImage = append(preImage, slice.Variables...)
		}
		kecczk256 := NewKeccak256(api)
		computeHash, err := kecczk256.Compute(preImage)
		if err != nil {
			return nil, err
		}
		return computeHash[:], nil
	}
	result, err := sliceComposer.Process(32, fn, concatGenerator)
	if err != nil {
		return err
	}
	if len(result) != 32 {
		return errors.New("slice affix programmer returned unexpected result")
	}

	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i], c.Hash[i])
	}
	return nil
}
