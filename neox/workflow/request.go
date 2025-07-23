package workflow

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/txhsl/neox-dbft-verifier/circuit"
)

// BlockRequest impls Request interface
type BlockRequest struct {
	blockHeaders []types.Header
	ce           circuit.CircuitEnum
	extraVersion byte
}

func (r *BlockRequest) Serialize() ([]byte, error) {
	return []byte{}, nil // todo
}

func (r *BlockRequest) Deserialize(header []byte) error {
	return nil // todo
}

func (r *BlockRequest) Option() []backend.ProverOption {
	switch r.ce {
	case circuit.RlpHash, circuit.NoSigRlp, circuit.ToG2Hash:
		return []backend.ProverOption{stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())}
	default:
		return []backend.ProverOption{}
	}
}
func (r *BlockRequest) Witness() (witness.Witness, error) {
	if len(r.blockHeaders) == 0 {
		return nil, errors.New("no block headers provided")
	}
	switch r.ce {
	case circuit.RlpHash:
		current := r.blockHeaders[0] // todo
		_, assignment, err := new(circuit.HeaderRLPEncodeVerifyWrapper).Instance(r.extraVersion, false, func() (*types.Header, error) {
			return &current, nil
		})
		if err != nil {
			return nil, err
		}
		return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	case circuit.ToG2Hash:
		current := r.blockHeaders[0] // todo
		_, assignment, err := new(circuit.HeaderHashToG2VerifyWrapper).Instance(func() (*types.Header, error) {
			return &current, nil
		})
		if err != nil {
			return nil, err
		}
		return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	case circuit.NoSigRlp:
		current := r.blockHeaders[0] // todo
		_, assignment, err := new(circuit.HeaderRLPEncodeVerifyWrapper).Instance(r.extraVersion, true, func() (*types.Header, error) {
			return &current, nil
		})
		if err != nil {
			return nil, err
		}
		return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	//case circuit.Outer:
	//	if len(r.blockHeaders) < 2 {
	//		return nil, errors.New("outer block header is too short, expected at least 2")
	//	}
	//	switch r.extraVersion {
	//	case circuit.ExtraV0:
	//		assignment, err := circuit.GetExtraV0VerifierCircuit(func() {
	//
	//		})
	//	case circuit.ExtraV1, circuit.ExtraV2:
	//	default:
	//		return nil, errors.New("invalid extra version")
	//
	//
	//	}
	default:
		return nil, errors.New("invalid")
	}
	// todo
}
