package pipeline

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

// BlockProvingRequest represents a request to be proven, which needs to include
// (1) The requested circuit type, to decide which circuit should be used
// (2) Block information, to know the final proof is proved for which block
type BlockProvingRequest struct {
}

type Request interface {
	Serialize() ([]byte, error) // todo
	Deserialize(b []byte) error // todo
	Witness() (witness.Witness, error)
	Option() []backend.ProverOption
}

type SolveRequest struct {
	Request
	opts []backend.ProverOption
}

func NewSolveRequest(request Request, opts ...backend.ProverOption) SolveRequest {
	return SolveRequest{
		Request: request,
		opts:    opts,
	}
}

type ProveRequest struct {
	Request
	Solution any
	opts     []backend.ProverOption
}

func NewProveRequest(request Request, solution any, opts ...backend.ProverOption) ProveRequest {
	return ProveRequest{
		Request:  request,
		Solution: solution,
		opts:     opts,
	}
}

type ProveResponse struct {
	Request
	Proof groth16.Proof
}

func NewProveResponse(request Request, proof groth16.Proof) ProveResponse {
	return ProveResponse{
		Request: request,
		Proof:   proof,
	}
}
