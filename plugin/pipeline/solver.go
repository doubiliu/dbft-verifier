package pipeline

import (
	"context"
	"fmt"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"sync"
)

// PipelineSolver processes "witness generation" and commitment
type PipelineSolver struct {
	solveFunc map[circuit.CircuitEnum]func(witness witness.Witness, opts ...backend.ProverOption) (any, error)
	input     <-chan SolveRequest
	output    chan<- ProveRequest
	feedback  chan<- error
	wg        *sync.WaitGroup
}

func (solver *PipelineSolver) Start(ctx context.Context, nbParallel int) {
	defer solver.wg.Done()
	defer close(solver.output) // When solver finishes, close the output channel for the prover

	var solverWg sync.WaitGroup
	control := make(chan struct{}, nbParallel)

	for {
		select {
		case <-ctx.Done(): // Context was cancelled
			fmt.Println("Solver: context cancelled, waiting for active solves to finish.")
			solverWg.Wait() // Wait for any in-flight solves to complete
			return
		case request, ok := <-solver.input:
			if !ok { // Input channel is closed
				fmt.Println("Solver: input channel closed, waiting for active solves to finish.")
				solverWg.Wait() // Wait for any in-flight solves to complete
				return
			}

			solverWg.Add(1)
			go solver.solve(request, control, &solverWg)
		}
	}
}

func (solver *PipelineSolver) solve(request SolveRequest, control chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	control <- struct{}{} // Acquire a semaphore slot
	defer func() {
		<-control // Release the semaphore slot
	}()
	w, err := request.Witness()
	if err != nil {
		solver.feedback <- err
		return
	}
	solve, ok := solver.solveFunc[request.CircuitEnum()]
	if !ok {
		solver.feedback <- fmt.Errorf("unsupported circuit type: %d", request.CircuitEnum())
	}
	solution, err := solve(w, request.opts...)
	//solution, err := groth16.Solve(solver.ccs, solver.pk, w, request.opts...)
	if err != nil {
		// Non-blocking send for error
		select {
		case solver.feedback <- err:
		default:
		}
		return
	}

	proveRequest := NewProveRequest(request, solution)
	solver.output <- proveRequest
}

func NewPipelineSolver(wg *sync.WaitGroup, solveFunc map[circuit.CircuitEnum]func(w witness.Witness, opts ...backend.ProverOption) (any, error), input <-chan SolveRequest, output chan<- ProveRequest, feedback chan<- error) *PipelineSolver {
	return &PipelineSolver{
		solveFunc: solveFunc,
		input:     input,
		output:    output,
		feedback:  feedback,
		wg:        wg,
	}
}
