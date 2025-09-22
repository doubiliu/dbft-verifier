package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

type ConcatChecker struct {
	Slices []PaddingSlice
	Concat PaddingSlice
}

func (c *ConcatChecker) Define(api frontend.API) error {
	sApi := NewSliceApi(api)
	err := sApi.CheckConcat(c.Concat, c.Slices...)
	if err != nil {
		return err
	}
	return nil
}

func TestSliceApi(t *testing.T) {
	slices := []PaddingSlice{
		{
			Padding:        frontend.Variable(2),
			Slice:          []frontend.Variable{0, 1, 0, 0, 0},
			IsLittleEndian: true,
		},
		{
			Padding:        frontend.Variable(1),
			Slice:          []frontend.Variable{0, 0, 1, 1, 1},
			IsLittleEndian: false,
		},
		{
			Padding:        frontend.Variable(1),
			Slice:          []frontend.Variable{4, 0, 0, 0, 0},
			IsLittleEndian: true,
		},
		{
			Padding:        frontend.Variable(5),
			Slice:          []frontend.Variable{4, 1, 2, 3, 4},
			IsLittleEndian: true,
		},
	}
	concat := PaddingSlice{
		Padding:        frontend.Variable(6),
		Slice:          []frontend.Variable{0, 1, 1, 1, 1, 4, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		IsLittleEndian: true,
	}
	concatCircuit := ConcatChecker{
		Slices: slices,
		Concat: concat,
	}
	concatAssgin := ConcatChecker{
		Slices: slices,
		Concat: concat,
	}
	err := test.IsSolved(&concatCircuit, &concatAssgin, ecc.BN254.ScalarField())
	assert.NoError(t, err)
}
