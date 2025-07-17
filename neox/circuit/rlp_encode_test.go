package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/rlp"
	"testing"
)

func TestRlpEncodeCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	//test rule1
	r1Data := "a"
	r1 := []byte(r1Data)
	R1 := make([]frontend.Variable, len(r1))
	for i := 0; i < len(R1); i++ {
		R1[i] = r1[i]
	}
	result1, err := rlp.EncodeToBytes(r1)
	if err != nil {
		return
	}
	Result1 := make([]frontend.Variable, len(result1))
	for i := 0; i < len(Result1); i++ {
		Result1[i] = result1[i]
	}
	//test rule2
	r2Data := "abc"
	r2 := []byte(r2Data)
	R2 := make([]frontend.Variable, len(r2))
	for i := 0; i < len(R2); i++ {
		R2[i] = r2[i]
	}
	result2, err := rlp.EncodeToBytes(r2)
	if err != nil {
		return
	}
	Result2 := make([]frontend.Variable, len(result2))
	for i := 0; i < len(Result2); i++ {
		Result2[i] = result2[i]
	}
	//test rule3_1
	r3_1Data := "The length of this sentence is more than 55 bytes, I know it because I pre-designed it"
	r3_1 := []byte(r3_1Data)
	R3_1 := make([]frontend.Variable, len(r3_1))
	for i := 0; i < len(R3_1); i++ {
		R3_1[i] = r3_1[i]
	}
	result3_1, err := rlp.EncodeToBytes(r3_1)
	if err != nil {
		return
	}
	Result3_1 := make([]frontend.Variable, len(result3_1))
	for i := 0; i < len(Result3_1); i++ {
		Result3_1[i] = result3_1[i]
	}
	//test rule3_2
	r3_2Data := ""
	for i := 0; i < 1024; i++ {
		r3_2Data = r3_2Data + "a"
	}
	r3_2 := []byte(r3_2Data)
	R3_2 := make([]frontend.Variable, len(r3_2))
	for i := 0; i < len(R3_2); i++ {
		R3_2[i] = r3_2[i]
	}
	result3_2, err := rlp.EncodeToBytes(r3_2)
	if err != nil {
		return
	}
	Result3_2 := make([]frontend.Variable, len(result3_2))
	for i := 0; i < len(Result3_2); i++ {
		Result3_2[i] = result3_2[i]
	}
	//test rule4
	a4 := []byte("abc")
	b4 := []byte("def")
	r4Data := []interface{}{
		a4, b4,
	}
	r4 := [2][3]byte{}
	for i := 0; i < len(a4); i++ {
		r4[0][i] = a4[i]
	}
	for i := 0; i < len(b4); i++ {
		r4[1][i] = b4[i]
	}
	R4 := make([][]frontend.Variable, len(r4))
	for i := 0; i < len(r4); i++ {
		temp := make([]frontend.Variable, len(r4[i]))
		R4[i] = temp
		for j := 0; j < len(r4[i]); j++ {
			R4[i][j] = r4[i][j]
		}
	}
	result4, err := rlp.EncodeToBytes(r4Data)
	if err != nil {
		return
	}
	Result4 := make([]frontend.Variable, len(result4))
	for i := 0; i < len(Result4); i++ {
		Result4[i] = result4[i]
	}
	//test rule5_1
	a5_1 := []byte("The length of this sentence is more than 55 bytes, I know it because I pre-designed it")
	b5_1 := []byte("The length of this sentence is more than 55 bytes, I know it because I pre-designed it")
	r5_1Data := []interface{}{
		a5_1, b5_1,
	}
	a51L := len(a5_1)
	r5_1 := make([][]byte, 2)
	r5_1[0] = make([]byte, a51L)
	r5_1[1] = make([]byte, a51L)
	for i := 0; i < len(a5_1); i++ {
		r5_1[0][i] = a5_1[i]
	}
	for i := 0; i < len(b5_1); i++ {
		r5_1[1][i] = b5_1[i]
	}
	R5_1 := make([][]frontend.Variable, len(r5_1))
	for i := 0; i < len(r5_1); i++ {
		temp := make([]frontend.Variable, len(r5_1[i]))
		R5_1[i] = temp
		for j := 0; j < len(r5_1[i]); j++ {
			R5_1[i][j] = r5_1[i][j]
		}
	}
	result5_1, err := rlp.EncodeToBytes(r5_1Data)
	if err != nil {
		return
	}
	Result5_1 := make([]frontend.Variable, len(result5_1))
	for i := 0; i < len(Result5_1); i++ {
		Result5_1[i] = result5_1[i]
	}

	//test rule5_2
	r5_2string := ""
	for i := 0; i < 1024; i++ {
		r5_2string = r5_2string + "a"
	}
	a5_2 := []byte(r5_2string)
	b5_2 := []byte(r5_2string)
	r5_2Data := []interface{}{
		a5_2, b5_2,
	}
	a52L := len(a5_2)
	r5_2 := make([][]byte, 2)
	r5_2[0] = make([]byte, a52L)
	r5_2[1] = make([]byte, a52L)
	for i := 0; i < len(a5_2); i++ {
		r5_2[0][i] = a5_2[i]
	}
	for i := 0; i < len(b5_2); i++ {
		r5_2[1][i] = b5_2[i]
	}
	R5_2 := make([][]frontend.Variable, len(r5_2))
	for i := 0; i < len(r5_2); i++ {
		temp := make([]frontend.Variable, len(r5_2[i]))
		R5_2[i] = temp
		for j := 0; j < len(r5_2[i]); j++ {
			R5_2[i][j] = r5_2[i][j]
		}
	}
	result5_2, err := rlp.EncodeToBytes(r5_2Data)
	if err != nil {
		return
	}
	Result5_2 := make([]frontend.Variable, len(result5_2))
	for i := 0; i < len(Result5_2); i++ {
		Result5_2[i] = result5_2[i]
	}
	circuit := RlpEncodeWrapper{
		Rule1Data:   R1,
		Inpput1Data: Result1,

		Rule2Data:   R2,
		Inpput2Data: Result2,

		Rule3_1Data:   R3_1,
		Inpput3_1Data: Result3_1,

		Rule3_2Data:   R3_2,
		Inpput3_2Data: Result3_2,

		Rule4Data:   R4,
		Inpput4Data: Result4,

		Rule5_1Data:   R5_1,
		Inpput5_1Data: Result5_1,

		Rule5_2Data:   R5_2,
		Inpput5_2Data: Result5_2,
	}
	witness := RlpEncodeWrapper{
		Rule1Data:   R1,
		Inpput1Data: Result1,

		Rule2Data:   R2,
		Inpput2Data: Result2,

		Rule3_1Data:   R3_1,
		Inpput3_1Data: Result3_1,

		Rule3_2Data:   R3_2,
		Inpput3_2Data: Result3_2,

		Rule4Data:   R4,
		Inpput4Data: Result4,

		Rule5_1Data:   R5_1,
		Inpput5_1Data: Result5_1,

		Rule5_2Data:   R5_2,
		Inpput5_2Data: Result5_2,
	}
	//_, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	assert.NoError(err)
}

type RlpEncodeWrapper struct {
	Rule1Data   []frontend.Variable
	Rule2Data   []frontend.Variable
	Rule3_1Data []frontend.Variable
	Rule3_2Data []frontend.Variable
	Rule4Data   [][]frontend.Variable
	Rule5_1Data [][]frontend.Variable
	Rule5_2Data [][]frontend.Variable

	Inpput1Data   []frontend.Variable
	Inpput2Data   []frontend.Variable
	Inpput3_1Data []frontend.Variable
	Inpput3_2Data []frontend.Variable
	Inpput4Data   []frontend.Variable
	Inpput5_1Data []frontend.Variable
	Inpput5_2Data []frontend.Variable
}

// Define declares the circuit's constraints
func (c *RlpEncodeWrapper) Define(api frontend.API) error {
	rlpencode := NewRlpEncode(api)
	result1 := rlpencode.EncodeRule1(c.Rule1Data)
	result2 := rlpencode.EncodeRule2(c.Rule2Data)
	result3_1 := rlpencode.EncodeRule3_OneByte(c.Rule3_1Data)
	result3_2 := rlpencode.EncodeRule3_TwoBytes(c.Rule3_2Data)

	r4 := make([][]frontend.Variable, len(c.Rule4Data))
	for i := 0; i < len(c.Rule4Data); i++ {
		r4[i] = rlpencode.EncodeRule2(c.Rule4Data[i])
	}
	result4 := rlpencode.EncodeRule4(r4)

	r5_1 := make([][]frontend.Variable, len(c.Rule5_1Data))
	for i := 0; i < len(c.Rule5_1Data); i++ {
		r5_1[i] = rlpencode.EncodeRule3_OneByte(c.Rule5_1Data[i])
	}
	result5_1 := rlpencode.EncodeRule5_OneByte(r5_1)

	r5_2 := make([][]frontend.Variable, len(c.Rule5_2Data))
	for i := 0; i < len(c.Rule5_2Data); i++ {
		r5_2[i] = rlpencode.EncodeRule3_TwoBytes(c.Rule5_2Data[i])
	}
	result5_2 := rlpencode.EncodeRule5_TwoBytes(r5_2)

	api.Println(result1)
	api.Println(c.Inpput1Data)
	for i := 0; i < len(result1); i++ {
		api.AssertIsEqual(result1[i], c.Inpput1Data[i])
	}

	api.Println(result2)
	api.Println(c.Inpput2Data)
	for i := 0; i < len(result2); i++ {
		api.AssertIsEqual(result2[i], c.Inpput2Data[i])
	}

	api.Println(result3_1)
	api.Println(c.Inpput3_1Data)
	for i := 0; i < len(result3_1); i++ {
		api.AssertIsEqual(result3_1[i], c.Inpput3_1Data[i])
	}

	api.Println(result3_2)
	api.Println(c.Inpput3_2Data)
	for i := 0; i < len(result3_2); i++ {
		api.AssertIsEqual(result3_2[i], c.Inpput3_2Data[i])
	}

	api.Println(result4)
	api.Println(c.Inpput4Data)
	for i := 0; i < len(result4); i++ {
		api.AssertIsEqual(result4[i], c.Inpput4Data[i])
	}

	api.Println(result5_1)
	api.Println(c.Inpput5_1Data)
	for i := 0; i < len(result5_1); i++ {
		api.AssertIsEqual(result5_1[i], c.Inpput5_1Data[i])
	}

	api.Println(result5_2)
	api.Println(c.Inpput5_2Data)
	for i := 0; i < len(result5_2); i++ {
		api.AssertIsEqual(result5_2[i], c.Inpput5_2Data[i])
	}
	return nil
}
