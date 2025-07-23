package pipeline

import (
	"context"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"sync"
)

type PipeScheduler struct {
	nbSolve    int
	nbProve    int
	solver     *PipelineSolver
	prover     *PipelineProver
	Response   <-chan ProveResponse // Response is now read-only
	solveInput chan<- SolveRequest  // solveInput is now write-only
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

func NewPipelineScheduler(nbSolve, nbProve, pendingSize int, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) *PipeScheduler {
	solveInputs := make(chan SolveRequest, pendingSize)
	proveInputs := make(chan ProveRequest, pendingSize)
	responses := make(chan ProveResponse, pendingSize)
	feedback := make(chan error, nbSolve+nbProve) // Buffer for potential concurrent errors

	var wg sync.WaitGroup

	// Note: We are creating two separate feedback channels for solver and prover,
	// which will be funneled into the main scheduler feedback channel.
	solverFeedback := make(chan error, nbSolve)
	proverFeedback := make(chan error, nbProve)

	solver := NewPipelineSolver(&wg, ccs, pk, solveInputs, proveInputs, solverFeedback)
	prover := NewPipelineProver(&wg, pk, proveInputs, responses, proverFeedback)

	scheduler := &PipeScheduler{
		nbSolve:    nbSolve,
		nbProve:    nbProve,
		solver:     solver,
		prover:     prover,
		Response:   responses,
		solveInput: solveInputs,
		feedback:   feedback, // This is the main, unified feedback channel
		wg:         &wg,
	}

	// This is a bit of a hack to wire the internal feedback channels to the main one.
	// We need to do this because the solver/prover don't know about the main scheduler.
	// A better design might involve passing the main feedback channel directly,
	// but this works and keeps components decoupled.
	scheduler.solver.feedback = solverFeedback
	scheduler.prover.feedback = proverFeedback

	return scheduler
}
