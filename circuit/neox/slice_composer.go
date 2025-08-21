package circuit

import (
	"errors"
	"github.com/consensys/gnark/frontend"
)

// given an array "a", we try to get its slice a[:len] (suffix can be transformed into prefix by reversing a)
// since len is not determined, so the circuit will change when len is changed

type UndeterminedSlice struct {
	Variables  []frontend.Variable
	IsSelected frontend.Variable // bool
}
type DeterminedSlice = []frontend.Variable
type SliceComposer struct {
	api frontend.API
}

func NewSliceComposer(api frontend.API) SliceComposer {
	return SliceComposer{api: api}
}

// Process compute a fn(slices...)
// each generator generates all the possible slice(UndeterminedSlice), where isSelect = 1(only one) is the slice we want
func (c *SliceComposer) Process(determinedLen int, fn func(frontend.API, ...UndeterminedSlice) (DeterminedSlice, error), generators ...func(api frontend.API) []UndeterminedSlice) (DeterminedSlice, error) {
	if len(generators) == 0 {
		return nil, errors.New("no generator function provided")
	}
	api := c.api
	result := make(DeterminedSlice, determinedLen)
	for i := 0; i < determinedLen; i++ {
		result[i] = frontend.Variable(0)
	}
	params := make([][]UndeterminedSlice, len(generators))
	for i := 0; i < len(generators); i++ {
		params[i] = generators[i](api)
	}
	testIndex := 0

	var dfs func(int, []UndeterminedSlice) error
	dfs = func(i int, slices []UndeterminedSlice) error {
		if i == len(generators) {
			testIndex++
			tmp, err := fn(api, slices...)
			if err != nil {
				return err
			}
			if len(tmp) != determinedLen {
				return errors.New("invalid len of fn")
			}
			selector := frontend.Variable(1)
			for _, slice := range slices {
				//api.Println(param.IsSelected)
				//api.Println(param.Variables...)
				selector = api.Mul(selector, slice.IsSelected)
			}
			for j := 0; j < len(result); j++ {
				result[j] = api.Add(result[j], api.Mul(selector, tmp[j]))
			}
			return nil
		}
		for _, s := range params[i] {
			if err := dfs(i+1, append(slices, s)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := dfs(0, []UndeterminedSlice{}); err != nil {
		return nil, err
	}
	return result, nil
}
