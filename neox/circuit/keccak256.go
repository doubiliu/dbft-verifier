package circuit

import (
	"github.com/consensys/gnark/frontend"
)

var (
	rate       = 1088
	blockWidth = 1600
	rho        = []int{1, 3, 6, 10, 15, 21,
		28, 36, 45, 55, 2, 14,
		27, 41, 56, 8, 25, 43,
		62, 18, 39, 61, 20, 44}
	pi = []int{10, 7, 11, 17, 18, 3,
		5, 16, 8, 21, 24, 4,
		15, 23, 19, 13, 12, 2,
		20, 14, 22, 9, 6, 1}
	RC = []uint64{1, 0x8082, 0x800000000000808a, 0x8000000080008000,
		0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009,
		0x8a, 0x88, 0x80008009, 0x8000000a,
		0x8000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x800a, 0x800000008000000a,
		0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008}
)

// SHA-3-256 (Keccak256) circuit. Equivalent with solidity keccak256() function.
// InputVariables - binary array of input
// OutputVariables - binary array of output. Should have size 256
// block - binary array of SHA-3 state should have size 1600

type Keccak256 struct {
	api            frontend.API
	InputVariables []frontend.Variable `gnark:",public"`
	//OutputVariables []frontend.Variable `gnark:",public"`
	block []frontend.Variable
}

// NewKeccak256 Creates a new keccak256 instance
// preImage is a byte array
// each variable in hash is a byte
func NewKeccak256(api frontend.API) Keccak256 {
	//	inputs := make([]frontend.Variable, 0)
	//	for i := 0; i < len(preImage); i++ {
	//		inputs = append(inputs, api.ToBinary(preImage[i], 8)...)
	//	}
	//outputs := make([]frontend.Variable, 0)
	//for i := 0; i < len(hash); i++ {
	//	outputs = append(outputs, api.ToBinary(hash[i], 8)...)
	//}
	//api.AssertIsEqual(len(outputs), 256)
	block := make([]frontend.Variable, blockWidth)

	return Keccak256{
		api: api,
		//InputVariables:  inputs,
		//OutputVariables: outputs,
		block: block,
	}
}

func (circuit *Keccak256) theta(api frontend.API) {
	b := make([][]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		b[i] = make([]frontend.Variable, 64)
		for j := 0; j < 64; j++ {
			b[i][j] = 0
		}
		for j := 0; j < 5; j++ {
			for l := 0; l < 64; l++ {
				b[i][l] = api.Xor(b[i][l], circuit.block[(i+j*5)*64+l])
			}
		}
	}
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			for l := 0; l < 64; l++ {
				xr := api.Xor(b[(i+4)%5][l], b[(i+1)%5][(l+63)%64])
				circuit.block[(i+j*5)*64+l] = api.Xor(circuit.block[(i+j*5)*64+l], xr)
			}
		}
	}
}

func (circuit *Keccak256) rho_and_phi(api frontend.API) {
	t := make([]frontend.Variable, 64)
	for i := 0; i < 64; i++ {
		t[i] = circuit.block[64+i]
	}
	for i := 0; i < 24; i++ {
		b := make([]frontend.Variable, 64)
		for j := 0; j < 64; j++ {
			b[j] = circuit.block[pi[i]*64+j]
		}
		for j := 0; j < 64; j++ {
			circuit.block[pi[i]*64+j] = t[(j+64-rho[i])%64]
		}
		for j := 0; j < 64; j++ {
			t[j] = b[j]
		}
	}
}

func (circuit *Keccak256) chi(api frontend.API) {
	for j := 0; j < 5; j++ {
		b := make([][]frontend.Variable, 5)
		for i := 0; i < 5; i++ {
			b[i] = make([]frontend.Variable, 64)
			for l := 0; l < 64; l++ {
				b[i][l] = circuit.block[(i+j*5)*64+l]
			}
		}
		for i := 0; i < 5; i++ {
			for l := 0; l < 64; l++ {
				nt_1 := api.Xor(b[(i+1)%5][l], 1)
				and_1 := api.Mul(nt_1, b[(i+2)%5][l])
				circuit.block[(i+j*5)*64+l] = api.Xor(b[i][l], and_1)
			}
		}
	}
}

func (circuit *Keccak256) iota(api frontend.API, round int) {
	for l := 0; l < 64; l++ {
		circuit.block[l] = api.Xor(circuit.block[l], ((RC[round] >> l) & 1))
	}
}

func (circuit *Keccak256) keccakPermute(api frontend.API) {
	for i := 0; i < 24; i++ {
		circuit.theta(api)
		circuit.rho_and_phi(api)
		circuit.chi(api)
		circuit.iota(api, i)
	}
}

func (circuit *Keccak256) xorIn(api frontend.API, inputOffset int, len int) {
	for i := 0; i < len; i++ {
		circuit.block[i] = api.Xor(circuit.block[i], circuit.InputVariables[i+inputOffset])
	}
}

func (circuit *Keccak256) absorb(api frontend.API) {
	sz := len(circuit.InputVariables)
	offset := 0
	for sz >= rate {
		circuit.xorIn(api, offset, rate)
		circuit.keccakPermute(api)
		offset += rate
		sz -= rate
	}
	circuit.block[sz] = api.Xor(circuit.block[sz], 1)
	circuit.block[rate-1] = api.Xor(circuit.block[rate-1], 1)
	circuit.xorIn(api, offset, sz)
	circuit.keccakPermute(api)
}

func (circuit *Keccak256) Compute(preImage []frontend.Variable) ([32]frontend.Variable, error) {
	api := circuit.api
	inputs := make([]frontend.Variable, 0)
	for i := 0; i < len(preImage); i++ {
		inputs = append(inputs, api.ToBinary(preImage[i], 8)...)
	}
	circuit.InputVariables = inputs

	circuit.block = make([]frontend.Variable, blockWidth)
	for i := 0; i < blockWidth; i++ {
		circuit.block[i] = 0
	}

	circuit.absorb(api)
	bytesOutput := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		bytesOutput[i] = api.FromBinary(circuit.block[i*8 : (i+1)*8]...)
	}
	outputs := [32]frontend.Variable{}
	for i := 0; i < 32; i++ {
		outputs[i] = api.FromBinary(circuit.block[i*8 : (i+1)*8]...)
	}

	return outputs, nil
}
