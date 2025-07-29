package pipeline

import (
	"context"
	"fmt"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"sync"
)

type PipeScheduler struct {
	nbSolve    int
	nbProve    int
	instances  []*PackedCircuitInstance
	solver     *PipelineSolver
	prover     *PipelineProver
	Response   <-chan ProveResponse
	solveInput chan<- SolveRequest
	feedback   chan error
	cancel     context.CancelFunc
	wg         *sync.WaitGroup
}

// Prove sends a new request to the pipeline.
func (scheduler *PipeScheduler) Prove(request Request) {
	opts := request.Option()
	// This can be blocking if the channel is full, which is a form of backpressure.
	scheduler.solveInput <- NewSolveRequest(request, opts...)
}

// Start initiates the pipeline workers. This is a non-blocking call.
func (scheduler *PipeScheduler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	scheduler.cancel = cancel

	scheduler.wg.Add(2) // We are waiting for solver and prover to finish
	go scheduler.solver.Start(ctx, scheduler.nbSolve)
	go scheduler.prover.Start(ctx, scheduler.nbProve)
}

// Finish gracefully shuts down the pipeline.
// It waits for all in-flight requests to be processed.
func (scheduler *PipeScheduler) Finish() {
	fmt.Println("Scheduler: Finishing...")
	// 1. Close the initial input channel to signal no more new requests are coming.
	close(scheduler.solveInput)

	// 2. Wait for all goroutines (solver and prover main loops) to finish.
	scheduler.wg.Wait()
	fmt.Println("Scheduler: All workers have stopped.")

	// 3. Close the feedback channel as no more errors can be produced.
	close(scheduler.feedback)

	// 4. Cancel context just in case, though closing channels should be sufficient.
	if scheduler.cancel != nil {
		scheduler.cancel()
	}
}

// Errors returns a channel to listen for any asynchronous errors from the pipeline.
func (scheduler *PipeScheduler) Errors() <-chan error {
	return scheduler.feedback
}

func NewPipelineScheduler(nbSolve, nbProve, pendingSize int, instanceConfig map[circuit.CircuitEnum]InstanceConfig) (*PipeScheduler, error) {
	solveInputs := make(chan SolveRequest, pendingSize)
	proveInputs := make(chan ProveRequest, pendingSize)
	responses := make(chan ProveResponse, pendingSize)
	feedback := make(chan error, pendingSize) // Buffer for potential concurrent errors

	var wg sync.WaitGroup
	// fix functions
	solveFuncs := make(map[circuit.CircuitEnum]func(w witness.Witness, opts ...backend.ProverOption) (any, error))
	proveFuncs := make(map[circuit.CircuitEnum]func(solution any) (groth16.Proof, error))
	for ce, config := range instanceConfig {
		// load ccs, pk, vk
		ccs, err := helper.ReadCCS(config.ccsPath)
		if err != nil {
			return nil, err
		}
		pk, err := helper.ReadProvingKey(config.pkPath)
		if err != nil {
			return nil, err
		}
		// todo vk can be delete
		//vk, err := helper.ReadVerifyingKey(config.vkPath)
		//if err != nil {
		//	return nil, err
		//}
		solveFuncs[ce] = func(w witness.Witness, opts ...backend.ProverOption) (any, error) {
			return groth16.Solve(ccs, pk, w, opts...)
		}
		proveFuncs[ce] = func(solution any) (groth16.Proof, error) {
			return groth16.ProofComputing(solution, pk)
		}
	}
	solver := NewPipelineSolver(&wg, solveFuncs, solveInputs, proveInputs, feedback)
	prover := NewPipelineProver(&wg, proveFuncs, proveInputs, responses, feedback)

	scheduler := &PipeScheduler{
		nbSolve:    nbSolve,
		nbProve:    nbProve,
		solver:     solver,
		prover:     prover,
		Response:   responses,
		solveInput: solveInputs,
		feedback:   feedback,
		wg:         &wg,
	}

	return scheduler, nil
}
