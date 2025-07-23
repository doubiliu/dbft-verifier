package pipeline

import (
	"context"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"sync"
	"time"
)

// PipelineSolver processes "witness generation" and commitment
type PipelineSolver struct {
	pk       groth16.ProvingKey
	ccs      constraint.ConstraintSystem
	input    <-chan SolveRequest // Input is now read-only
	output   chan<- ProveRequest // Output is now write-only
	feedback chan<- error        // Feedback is now write-only
	wg       *sync.WaitGroup
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
	fmt.Println("Solver: start solve request")
	defer func() {
		<-control // Release the semaphore slot
		fmt.Println("Solver: finish solve request")
	}()
	start := time.Now()
	witness, err := request.Witness()
	if err != nil {
		solver.feedback <- err
		return
	}
	solution, err := groth16.Solve(solver.ccs, solver.pk, witness, request.opts...)
	fmt.Println("solve time: ", time.Since(start))
	if err != nil {
		// Non-blocking send for error
		select {
		case solver.feedback <- err:
		default:
		}
		return
	}

	proveRequest := NewProveRequest(request.Request, solution, request.opts...)
	solver.output <- proveRequest
}

func NewPipelineSolver(wg *sync.WaitGroup, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, input <-chan SolveRequest, output chan<- ProveRequest, feedback chan<- error) *PipelineSolver {
	return &PipelineSolver{
		pk:       pk,
		ccs:      ccs,
		input:    input,
		output:   output,
		feedback: feedback,
		wg:       wg,
	}
}
