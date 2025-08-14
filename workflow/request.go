package workflow

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/circuit/n3"
	neox "github.com/txhsl/neox-dbft-verifier/circuit/neox"
	"time"
)

// BlockRequest impls Request interface, represents a request to be proven, which needs to include
// (1) blockHeader, to know the final proof is proved for which block
// (2) isInner, if true, the node will prove RlpHash + NoSig/ToG2Hash
// else, the node will prove VerifyHeader
// todo in this mode, RlpHash and ToG2Hash will have a pipeline
// In practice, we found that RlpHash's Solve is so fast
type BlockRequest struct {
	BlockHeader circuit.HashableBlockHeader
	Ce          circuit.CircuitEnum
	//blockHeader *types.Header // marshalJson of header, current
	//isInner   bool      // In this version, we let each node prove either all the innerCircuits or the outerCircuit
	StartTime time.Time // for test
	// todo other element
}

func (r *BlockRequest) IsInner() bool {
	return r.Ce.IsInner()
}
func (r *BlockRequest) Serialize() ([]byte, error) {
	header, err := r.BlockHeader.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return append([]byte{byte(r.Ce)}, header...), nil
}

func (r *BlockRequest) Deserialize(data []byte) error {
	// first byte is ce
	flag := circuit.CircuitEnum(data[0])
	if flag.IsInvalid() {
		return errors.New("invalid flag")
	}
	r.Ce = flag
	header := data[1:]
	//r.blockHeader = new(types.Header)
	return r.BlockHeader.UnmarshalJSON(header)
}

func (r *BlockRequest) Option() []backend.ProverOption {
	if r.IsInner() {
		return []backend.ProverOption{stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())}
	} else {
		return []backend.ProverOption{}
	}
}
func (r *BlockRequest) ExtraVersion() (byte, error) {
	switch r.BlockHeader.(type) {
	case *neox.NeoxBlockHeader:
		return r.BlockHeader.(*neox.NeoxBlockHeader).ExtraVersion(), nil
	case *n3.N3BlockHeader:
		return byte(0), errors.New("n3 block has no extra version")
	default:
		return byte(0), errors.New("invalid block type")
	}
}

func (r *BlockRequest) GetWitness(params ...any) (witness.Witness, error) {
	if len(params) == 0 {
		return nil, errors.New("invalid number of params provided, expect a circuitEnum at least")
	}
	if r.Ce.IsNeox() {
		current, ok := r.BlockHeader.(*neox.NeoxBlockHeader)
		if !ok {
			return nil, errors.New("invalid block header")
		}
		extraVersion := current.ExtraVersion()
		switch r.Ce {
		case circuit.RlpHash:
			assignment, err := new(neox.HeaderRLPEncodeVerifyWrapper).Assignment(
				func() (circuit.HashableBlockHeader, error) {
					return current, nil
				})
			if err != nil {
				return nil, err
			}
			return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		case circuit.ToG2Hash:
			assignment, err := new(neox.HeaderHashToG2VerifyWrapper).Assignment(func() (circuit.HashableBlockHeader, error) {
				return current, nil
			})
			if err != nil {
				return nil, err
			}
			return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		case circuit.NoSigRlp:
			assignment, err := new(neox.HeaderRLPEncodeVerifyWrapper).Assignment(
				func() (circuit.HashableBlockHeader, error) {
					return current, nil
				}, true)
			if err != nil {
				return nil, err
			}
			return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		case circuit.NeoxOuter:
			// outer need an another param, parent
			if len(params) < 1 {
				return nil, errors.New("invalid number of params provided, expect at least 2")
			}
			parent, ok := params[0].(*neox.NeoxBlockHeader)
			if !ok {
				return nil, errors.New("invalid parentData")
			}

			switch extraVersion {
			case neox.ExtraV0:
				// outer need an another param, parent
				if len(params) < 4 {
					return nil, errors.New("invalid number of params provided, expect at least 5")
				}
				parentRlpHashProof := func() (groth16.Proof, error) {
					proof := params[1].(groth16.Proof)
					if !ok {
						return nil, errors.New("invalid parentRlpHashProof")
					}
					return proof, nil
				}
				currentRlpHashProof := func() (groth16.Proof, error) {
					proof := params[2].(groth16.Proof)
					if !ok {
						return nil, errors.New("invalid currentRlpHashProof")
					}
					return proof, nil
				}

				noSigHashProof := func() (groth16.Proof, error) {
					proof := params[3].(groth16.Proof)
					if !ok {
						return nil, errors.New("invalid toG2HashProof")
					}
					return proof, nil
				}

				assignment, err := new(neox.ExtraV0HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]).Assignment(
					func() ([]circuit.HashableBlockHeader, error) {
						return []circuit.HashableBlockHeader{parent, current}, nil
					}, parentRlpHashProof, currentRlpHashProof, noSigHashProof)
				if err != nil {
					return nil, err
				}
				return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			case neox.ExtraV1, neox.ExtraV2:
				// outer need an another param, parent
				if len(params) < 4 {
					return nil, errors.New("invalid number of params provided, expect at least 5")
				}
				parentRlpHashProof := func() (groth16.Proof, error) {
					proof := params[1].(groth16.Proof)
					if !ok {
						return nil, errors.New("invalid parentRlpHashProof")
					}
					return proof, nil
				}
				currentRlpHashProof := func() (groth16.Proof, error) {
					proof := params[2].(groth16.Proof)
					if !ok {
						return nil, errors.New("invalid currentRlpHashProof")
					}
					return proof, nil
				}

				toG2HashProof := func() (groth16.Proof, error) {
					proof := params[3].(groth16.Proof)
					if !ok {
						return nil, errors.New("invalid toG2HashProof")
					}
					return proof, nil
				}

				assignment, err := new(neox.ExtraV1OrV2HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]).Assignment(
					func() ([]circuit.HashableBlockHeader, error) {
						return []circuit.HashableBlockHeader{parent, current}, nil
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
	} else {
		current, ok := r.BlockHeader.(*n3.N3BlockHeader)
		if !ok {
			return nil, errors.New("invalid block header")
		}
		// n3
		if len(params) < 1 {
			return nil, errors.New("invalid number of params provided, expect at least 2")
		}
		parent, ok := params[0].(*n3.N3BlockHeader)
		if !ok {
			return nil, errors.New("invalid parentData")
		}
		assignment, err := new(n3.N3VerifyHeaderWrapper).Assignment(
			func() ([]circuit.HashableBlockHeader, error) {
				return []circuit.HashableBlockHeader{parent, current}, nil
			})
		if err != nil {
			return nil, err
		}
		return frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	}
}
