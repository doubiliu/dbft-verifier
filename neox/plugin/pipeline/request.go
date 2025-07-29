package pipeline

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/txhsl/neox-dbft-verifier/circuit"
)

type Request interface {
	Serialize() ([]byte, error) // todo
	Deserialize(b []byte) error // todo
	Witness(params ...any) (witness.Witness, error)
	Option() []backend.ProverOption
	CircuitEnum() circuit.CircuitEnum
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
	SolveRequest
	Solution any
}

func NewProveRequest(request SolveRequest, solution any) ProveRequest {
	return ProveRequest{
		SolveRequest: request,
		Solution:     solution,
	}
}

type ProveResponse struct {
	Request
	Proof       groth16.Proof
	CircuitType circuit.CircuitEnum
}

func NewProveResponse(request Request, proof groth16.Proof, ce circuit.CircuitEnum) ProveResponse {
	return ProveResponse{
		Request:     request,
		Proof:       proof,
		CircuitType: ce,
	}
}
