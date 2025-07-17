package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type Groth16Verifier[Fr emulated.FieldParams, G1 algebra.G1ElementT, G2 algebra.G2ElementT, GT algebra.GtElementT] struct {
	api frontend.API
}

func NewGroth16Verifier[Fr emulated.FieldParams, G1 algebra.G1ElementT, G2 algebra.G2ElementT, GT algebra.GtElementT](api frontend.API) Groth16Verifier[Fr, G1, G2, GT] {
	return Groth16Verifier[Fr, G1, G2, GT]{
		api: api,
	}
}

func (c *Groth16Verifier[Fr, G1, G2, GT]) Verify(proof stdgroth16.Proof[G1, G2], vk stdgroth16.VerifyingKey[G1, G2, GT], publicInputs []frontend.Variable) error {
	api := c.api
	field, err := emulated.NewField[Fr](api)
	if err != nil {
		panic(err)
	}
	verifier, err := stdgroth16.NewVerifier[Fr, G1, G2, GT](api)
	if err != nil {
		return err
	}

	witnessElement := make([]emulated.Element[Fr], len(publicInputs))
	for i := 0; i < len(witnessElement); i++ {
		bits := bits.ToBinary(api, publicInputs[i])
		witnessElement[i] = *field.FromBits(bits...)
	}
	return verifier.AssertProof(vk, proof, stdgroth16.Witness[Fr]{Public: witnessElement}, stdgroth16.WithCompleteArithmetic())
}
