package workflow

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/utils"
	"time"
)

// BlockRequest impls Request interface, represents a request to be proven, which needs to include
// (1) blockHeader, to know the final proof is proved for which block
// (2) isInner, if true, the node will prove RlpHash + NoSig/ToG2Hash
// else, the node will prove VerifyHeader
// todo in this mode, RlpHash and ToG2Hash will have a pipeline
// In practice, we found that RlpHash's Solve is so fast
type BlockRequest struct {
	blockHeader *types.Header // marshalJson of header, current
	isInner     bool          // In this version, we let each node prove either all the innerCircuits or the outerCircuit
	startTime   time.Time     // for test
	// todo other element
}

func (r *BlockRequest) Serialize() ([]byte, error) {
	header, err := r.blockHeader.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var flag byte
	if r.isInner {
		flag = byte(0)
	} else {
		flag = byte(1)
	}
	return append([]byte{flag}, header...), nil
}

func (r *BlockRequest) Deserialize(data []byte) error {
	// first byte is isInner
	flag := data[0]
	if flag != byte(0) && flag != byte(1) {
		return errors.New("invalid flag")
	}
	r.isInner = flag&0x80 != 0
	header := data[1:]
	r.blockHeader = new(types.Header)
	return r.blockHeader.UnmarshalJSON(header)
}

func (r *BlockRequest) Option() []backend.ProverOption {
	if r.isInner {
		return []backend.ProverOption{stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())}
	} else {
		return []backend.ProverOption{}
	}
}
func (r *BlockRequest) ExtraVersion() (byte, error) {
	return utils.GetBlockHeaderExtraVersion(r.blockHeader), nil
}

func (r *BlockRequest) GetWitness(params ...any) (witness.Witness, error) {
	if len(params) == 0 {
		return nil, errors.New("invalid number of params provided, expect a circuitEnum at least")
	}
	ce := params[0].(circuit.CircuitEnum)
	current := r.blockHeader
	extraVersion := utils.GetBlockHeaderExtraVersion(current)
	switch ce {
	case circuit.RlpHash:
		if !r.isInner {
			return nil, errors.New("Runtime Error: request is a outer-circuit request, but request to prove a inner-circuit")
		}
		_, assignment, err := new(circuit.HeaderRLPEncodeVerifyWrapper).Instance(extraVersion, false, func() (*types.Header, error) {
			return current, nil
		})
		if err != nil {
			return nil, err
		}
		return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	case circuit.ToG2Hash:
		if !r.isInner {
			return nil, errors.New("Runtime Error: request is a outer-circuit request, but request to prove a inner-circuit")
		}
		_, assignment, err := new(circuit.HeaderHashToG2VerifyWrapper).Instance(func() (*types.Header, error) {
			return current, nil
		})
		if err != nil {
			return nil, err
		}
		return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	case circuit.NoSigRlp:
		if !r.isInner {
			return nil, errors.New("Runtime Error: request is a outer-circuit request, but request to prove a inner-circuit")
		}
		_, assignment, err := new(circuit.HeaderRLPEncodeVerifyWrapper).Instance(extraVersion, true, func() (*types.Header, error) {
			return current, nil
		})
		if err != nil {
			return nil, err
		}
		return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	case circuit.OuterAgg:
		if r.isInner {
			return nil, errors.New("Runtime Error: request is a inner-circuit request, but request to prove a outer-circuit")
		}
		// outer need an another param, parent
		if len(params) < 2 {
			return nil, errors.New("invalid number of params provided, expect at least 2")
		}
		parent, ok := params[1].(*types.Header)
		if !ok {
			return nil, errors.New("invalid parentData")
		}

		switch extraVersion {
		case circuit.ExtraV0:
			// outer need an another param, parent
			if len(params) < 5 {
				return nil, errors.New("invalid number of params provided, expect at least 5")
			}
			parentRlpHashProof := func() (groth16.Proof, error) {
				proof := params[2].(groth16.Proof)
				if !ok {
					return nil, errors.New("invalid parentRlpHashProof")
				}
				return proof, nil
			}
			currentRlpHashProof := func() (groth16.Proof, error) {
				proof := params[3].(groth16.Proof)
				if !ok {
					return nil, errors.New("invalid currentRlpHashProof")
				}
				return proof, nil
			}

			noSigHashProof := func() (groth16.Proof, error) {
				proof := params[4].(groth16.Proof)
				if !ok {
					return nil, errors.New("invalid toG2HashProof")
				}
				return proof, nil
			}

			assignment, err := circuit.GetExtraV0VerifierAssignment(func() (*types.Header, *types.Header, error) {
				return current, parent, nil
			}, parentRlpHashProof, currentRlpHashProof, noSigHashProof)
			if err != nil {
				return nil, err
			}
			return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		case circuit.ExtraV1, circuit.ExtraV2:
			// outer need an another param, parent
			if len(params) < 5 {
				return nil, errors.New("invalid number of params provided, expect at least 5")
			}
			parentRlpHashProof := func() (groth16.Proof, error) {
				proof := params[2].(groth16.Proof)
				if !ok {
					return nil, errors.New("invalid parentRlpHashProof")
				}
				return proof, nil
			}
			currentRlpHashProof := func() (groth16.Proof, error) {
				proof := params[3].(groth16.Proof)
				if !ok {
					return nil, errors.New("invalid currentRlpHashProof")
				}
				return proof, nil
			}

			toG2HashProof := func() (groth16.Proof, error) {
				proof := params[4].(groth16.Proof)
				if !ok {
					return nil, errors.New("invalid toG2HashProof")
				}
				return proof, nil
			}
			assignment, err := circuit.GetExtraV1OrV2VerifierAssignment(extraVersion, func(_ byte) (*types.Header, *types.Header, error) {
				return parent, current, nil
			}, parentRlpHashProof, currentRlpHashProof, toG2HashProof)
			if err != nil {
				return nil, err
			}
			return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		default:
			return nil, errors.New("invalid extra version")

		}
	default:
		return nil, errors.New("invalid")
	}
	// todo
}
