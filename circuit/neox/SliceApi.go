package circuit

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/selector"
	"slices"
)

// SliceApi is used for some operations on undetermined slice
// in little-endian
type SliceApi struct {
	api frontend.API
}

func NewSliceApi(api frontend.API) SliceApi {
	return SliceApi{api: api}
}

func (c *SliceApi) New(api frontend.API, in []frontend.Variable, isLittle bool) PaddingSlice {
	copySlice := make([]frontend.Variable, len(in))
	copy(copySlice[:], in[:])
	if isLittle {
		slices.Reverse(copySlice)
	}
	p := c.newBigEndian(api, copySlice)
	if isLittle {
		p = p.Reverse(api)
	}
	return p
}

func (c *SliceApi) newBigEndian(api frontend.API, in []frontend.Variable) PaddingSlice {
	f2 := frontend.Variable(0)
	padding := frontend.Variable(0)
	sum := make([]frontend.Variable, len(in))
	for i := 0; i < len(in); i++ {
		f1 := api.Xor(frontend.Variable(1), api.IsZero(in[i]))
		f2 = api.Or(f1, f2)
		sum[i] = api.Select(f2, frontend.Variable(1), frontend.Variable(0))
	}
	for i := 0; i < len(sum); i++ {
		padding = api.Add(padding, sum[i])
	}
	padding = api.Sub(frontend.Variable(len(in)), padding)
	padding = api.Select(api.IsZero(api.Sub(padding, len(in))), len(in), padding)
	p := PaddingSlice{
		Padding:        api.Sub(padding, 1),
		Slice:          in,
		IsLittleEndian: false,
	}
	return p
}

// AssertIsZero check all variables in slice is 0
// no matter whether big or little-endian is set
func (c *SliceApi) AssertIsZero(slice []frontend.Variable) {
	api := c.api
	for i := 0; i < len(slice); i++ {
		api.AssertIsEqual(slice[i], 0)
	}
}

// AssertIsSame check a[i] = b[i] for all i
// in little-endian, we check:
// when len(a) != len(b), we check a[:minLen] = b[:minLen] and a[minLen:] = 0, b[minLen:] = 0
// hint: here a and b should fix its length, otherwise the circuit will change

func (c *SliceApi) AssertIsSame(a []frontend.Variable, b []frontend.Variable) {
	api := c.api
	minLen := min(len(a), len(b))
	for i := 0; i < minLen; i++ {
		api.AssertIsEqual(a[i], b[i])
	}
	for i := minLen; i < len(a); i++ {
		api.AssertIsEqual(a[i], 0)
	}
	for i := minLen; i < len(b); i++ {
		api.AssertIsEqual(b[i], 0)
	}

}
func (c *SliceApi) Zeros(length int) []frontend.Variable {
	zeros := make([]frontend.Variable, length)
	for i := 0; i < len(zeros); i++ {
		zeros[i] = 0
	}
	return zeros
}

// RightShift a = [a1, a2, ... ,an] -> [0, 0, ... 0, a1, a2, .. a_{n - shift}]
func (c *SliceApi) RightShift(a []frontend.Variable, shift frontend.Variable) []frontend.Variable {
	api := c.api
	result := c.Zeros(len(a))
	for i := 0; i < len(a); i++ {
		result[i] = api.Add(result[i], api.Mul(api.IsZero(shift), a[i]))
	}
	iter := a
	for i := 0; i < len(a)-1; i++ {
		tmp := c.Zeros(len(a))
		for j := i + 1; j < len(a); j++ {
			tmp[j] = iter[j-1]
		}
		isSelect := api.IsZero(api.Sub(i+1, shift))
		for k := 0; k < len(a); k++ {
			result[k] = api.Add(result[k], api.Mul(tmp[k], isSelect))
		}
		iter = tmp
	}
	return result
}

// LefttShift a = [a1, a2, .., an] -> [a_{shift}, ...an, 0, 0, 0, 0...]

func (c *SliceApi) LeftShift(a []frontend.Variable, shift frontend.Variable) []frontend.Variable {
	reverse := make([]frontend.Variable, len(a))
	copy(reverse[:], a[:])
	slices.Reverse(reverse)
	rightShift := c.RightShift(reverse, shift)
	slices.Reverse(rightShift)
	return rightShift
}

// Concat
// in little-endian, [s, 0...0] concat [a, 0...0] -> [a, s, 0...0]
// in big-endian, [0...0, s] concat [0...0, a] -> [0...0, s, a]
// result = [s,a,0,0,0]
// hint: that is isInPaddingSide = false
func (c *SliceApi) Concat(isLittle bool, slices ...PaddingSlice) PaddingSlice {
	if len(slices) < 2 {
		panic("slices must have at least two elements")
	}
	iter := c.concat(slices[0], slices[1], isLittle)
	for i := 2; i < len(slices); i++ {
		iter = c.concat(iter, slices[i], isLittle)
	}
	return iter
}
func (c *SliceApi) concat(s PaddingSlice, a PaddingSlice, isLittle bool) PaddingSlice {
	api := c.api
	concat := make([]frontend.Variable, len(a.Slice)+len(s.Slice)) // total length
	// we use little-endian
	sCopy := s.Clone()
	if !sCopy.IsLittleEndian {
		sCopy = sCopy.Reverse(api)
	}
	aCopy := a.Clone()

	if !aCopy.IsLittleEndian {
		aCopy = aCopy.Reverse(api)
	}
	// [a, s, 0...0]
	for i := 0; i < len(concat); i++ {
		concat[i] = 0
	}
	concatPadding := api.Add(sCopy.Padding, aCopy.Padding)
	// we pad s and a
	sCopy = sCopy.PaddingWithZero(api, len(concat))
	aCopy = aCopy.PaddingWithZero(api, len(concat))
	// then we right shift sCopy, shift = a.Len()
	sApi := NewSliceApi(api)
	shiftSlice := sApi.RightShift(sCopy.Slice, aCopy.Len(api)) // [0...0, s, 0...0]
	for i := 0; i < len(concat); i++ {
		concat[i] = api.Add(aCopy.Slice[i], shiftSlice[i])
	}
	concatSlice := PaddingSlice{
		IsLittleEndian: true,
		Padding:        concatPadding,
		Slice:          concat,
	}
	if !isLittle {
		concatSlice = concatSlice.Reverse(api)
	}
	return concatSlice
}

// Append appends a into s, where isLittle is whether the little or big-endian of a is given, isInPaddingSide is the position to insert
// e.g. in little-endian s = [s, 0,0,0...] -> [a, s, 0, 0,...], when isInPaddingSide = false, else -> [s, a, 0...0]
// in big-endian s = [0,0,0..., s] -> [0,0,0, s, a] when isInPaddingSide = false, else -> [0...0, a, s]
// hint: a will be treated as a no-padding-0 slice
func (c *SliceApi) Append(s PaddingSlice, a []frontend.Variable, isLittle bool, isInPaddingSide bool) PaddingSlice {
	// we use little-endian

	aCopy := make([]frontend.Variable, len(a))
	copy(aCopy[:], a[:])
	if !isLittle {
		slices.Reverse(aCopy)
	}
	aPadding := PaddingSlice{
		IsLittleEndian: true,
		Padding:        len(aCopy),
		Slice:          aCopy,
	}
	if isInPaddingSide {
		return c.concat(aPadding, s, s.IsLittleEndian)
	} else {
		return c.concat(s, aPadding, s.IsLittleEndian)
	}
}

// CheckConcat provides a method to verify concat = connect all the slice in slices
// in little-endian, the logic is:
// [i1...0] [i2...0] [i3...0] -> [i1,i2,i3,0,...,0], i1,i2,i3 is a slice with no suffix-0
// Hint: when use this function, each slice's length and concat's length should be fixed, otherwise the circuit will change
// in big-endian, we reverse the input
func (c *SliceApi) CheckConcat(concat PaddingSlice, slices ...PaddingSlice) error {
	api := c.api
	littleConcat := concat.Clone()
	if !concat.IsLittleEndian {
		littleConcat = littleConcat.Reverse(api)
	}
	littleSlices := make([]PaddingSlice, 0)
	for _, slice := range slices {
		littleSlice := slice.Clone()
		if !slice.IsLittleEndian {
			littleSlice = slice.Reverse(api)
		}
		littleSlices = append(littleSlices, littleSlice)
	}
	return c.checkConcatInLittleEndian(littleConcat, littleSlices...)
}
func (c *SliceApi) checkConcatInLittleEndian(concat PaddingSlice, slices ...PaddingSlice) error {
	if len(slices) == 0 {
		return fmt.Errorf("len(slices) = 0")
	}
	api := c.api
	length := frontend.Variable(0) // total length = \sum (slice)
	NbSuffixZero := frontend.Variable(0)
	for _, slice := range slices {
		length = api.Add(length, len(slice.Slice))
		NbSuffixZero = api.Add(NbSuffixZero, api.Sub(len(slice.Slice), slice.Padding))
	}
	api.AssertIsEqual(length, len(concat.Slice))
	// len = len(slices) + 1
	partitions := make([]frontend.Variable, len(slices)+1) // [0, partition_0) is slice_0, [partition_0, partition_1) is slice_1, ...[partition_{n-1}, partition_{n}] is 0, partition_n = len(concat)
	// compute partition_0 ~ partition_{n}
	// partition_{n} = len(slices)
	partitions[len(partitions)-1] = len(concat.Slice)
	partitions[0] = slices[0].Padding // partition_0 = slice_0.Padding
	// partition_{i + 1}- partition_i = s.Padding, i >= 1
	for i := 0; i < len(slices); i++ {
		lastNum := frontend.Variable(0)
		if i > 0 {
			lastNum = partitions[i-1]
		}
		partitions[i] = api.Add(lastNum, slices[len(slices)-1-i].Padding)
	}
	api.AssertIsEqual(partitions[len(partitions)-1], length)
	// check concat[partition_{n - 1}, partition_n) is 0
	c.AssertIsZero(selector.Slice(api, partitions[len(partitions)-2], partitions[len(partitions)-1], concat.Slice))
	for i := 0; i < len(slices); i++ {
		var left, right frontend.Variable
		if i == 0 {
			left, right = 0, partitions[0]
		} else {
			left, right = partitions[i-1], partitions[i]
		}
		concatSlice := selector.Slice(api, left, right, concat.Slice)
		// we should left shift partitions[i + 1]
		concatSlice = c.LeftShift(concatSlice, left)
		c.AssertIsSame(concatSlice, slices[len(slices)-1-i].Slice)
	}
	return nil
}

// PaddingSlice is a slice padding with suffix 0 (e.g. little-endian)
// e.g. 3(in u8) = [1,1,0,0,0,0,0,0], padding = 2
//
//	Padding is the latest not-0 position, slice[padding + 1:] = 0
type PaddingSlice struct {
	IsLittleEndian bool
	Padding        frontend.Variable
	Slice          []frontend.Variable
}

func (s *PaddingSlice) Clone() PaddingSlice {
	copySlice := make([]frontend.Variable, len(s.Slice))
	copy(copySlice[:], s.Slice[:])
	return PaddingSlice{
		Padding:        s.Padding,
		Slice:          copySlice,
		IsLittleEndian: s.IsLittleEndian,
	}
}

// Reverse transforms a little/big-endian to big/little endian
func (s *PaddingSlice) Reverse(api frontend.API) PaddingSlice {
	newPadding := api.Sub(len(s.Slice)-1, s.Padding)
	newSlice := make([]frontend.Variable, len(s.Slice))
	copy(newSlice[:], s.Slice[:])
	slices.Reverse(newSlice)
	return PaddingSlice{
		Padding:        newPadding,
		Slice:          newSlice,
		IsLittleEndian: !s.IsLittleEndian,
	}
}
func (s *PaddingSlice) Last() frontend.Variable {
	if s.IsLittleEndian {
		return s.Slice[0]
	}
	return s.Slice[len(s.Slice)-1]
}
func (s *PaddingSlice) PaddingWithZero(api frontend.API, length int) PaddingSlice {
	paddingLength := length - len(s.Slice) // zero number
	sCopy := s.Clone()
	if s.IsLittleEndian {
		// padding will not change
		for i := 0; i < paddingLength; i++ {
			sCopy.Slice = append(sCopy.Slice, 0)
		}
	} else {
		sCopy.Padding = api.Add(sCopy.Padding, paddingLength)
		for i := 0; i < paddingLength; i++ {
			sCopy.Slice = append([]frontend.Variable{0}, sCopy.Slice...)
		}
	}
	return sCopy
}

func (s *PaddingSlice) Len(api frontend.API) frontend.Variable {
	sCopy := s.Clone()
	if !sCopy.IsLittleEndian {
		sCopy = sCopy.Reverse(api)
	}
	return sCopy.Padding
}

//// Check confirms that the padding is the correct position
//phase (s *PaddingSlice) Check(api frontend.API) {
//	toCheck := s.Clone()
//	if !s.IsLittleEndian {
//		toCheck = s.Reverse(api)
//	}
//	api.AssertIsLessOrEqual(s.Padding, len(toCheck.Slice)) // padding <= len(slice), if no-zero padding, padding=len(slice)
//	//api.AssertIsLessOrEqual(1, toCheck.Padding)            // padding >= 1
//	// special case: slice = 0, then padding = 0
//
//	// 1. check slice[padding:] is 0
//	// 2. check slice[padding - 1] != 0
//	prefixZero := selector.Partition(api, toCheck.Padding, true, toCheck.Slice) // suffix 0 slice
//	fmt.Println(len(prefixZero), len(toCheck.Slice))
//	for i := 0; i < len(prefixZero); i++ {
//		// if padding = len(slice), then no need to check, since no padding
//		api.AssertIsEqual(api.Mul(api.Sub(1, api.IsZero(api.Sub(toCheck.Padding, len(toCheck.Slice)))), prefixZero[i]), 0)
//	}
//
//	startNotZero := selector.Mux(api, api.Sub(toCheck.Padding, 1), toCheck.Slice...)
//	api.AssertIsEqual(api.Mul(api.Sub(s.Padding, 1), api.IsZero(startNotZero)), 0) // != 0 or padding == 1
//}
