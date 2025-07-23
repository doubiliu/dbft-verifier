package pipeline

import (
	"context"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"sync"
	"time"
)

type PipelineProver struct {
	pk       groth16.ProvingKey
	input    <-chan ProveRequest  // Input is now read-only
	output   chan<- ProveResponse // Output is now write-only
	feedback chan<- error         // Feedback is now write-only
	wg       *sync.WaitGroup
}

func (prover *PipelineProver) Start(ctx context.Context, nbParallel int) {
	defer prover.wg.Done()
	defer close(prover.output) // When prover finishes, close the final response channel

	var proverWg sync.WaitGroup
	control := make(chan struct{}, nbParallel)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Prover: context cancelled, waiting for active proofs to finish.")
			proverWg.Wait()
			return
		case request, ok := <-prover.input:
			if !ok {
				fmt.Println("Prover: input channel closed, waiting for active proofs to finish.")
				proverWg.Wait()
				return
			}
			proverWg.Add(1)
			go prover.prove(request, control, &proverWg)
		}
	}
}

func (prover *PipelineProver) prove(request ProveRequest, control chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	control <- struct{}{}
	fmt.Println("Prover: start prove request")
	defer func() {
		<-control
		fmt.Println("Prover: finish prove request")
	}()
	start := time.Now()
	proof, err := groth16.ProofComputing(request.Solution, prover.pk)
	fmt.Println("proof time: ", time.Since(start))
	if err != nil {
		select {
		case prover.feedback <- err:
		default:
		}
		return
	}
	prover.output <- NewProveResponse(request.Request, proof)
}

func NewPipelineProver(wg *sync.WaitGroup, pk groth16.ProvingKey, input <-chan ProveRequest, output chan<- ProveResponse, feedback chan<- error) *PipelineProver {
	return &PipelineProver{
		pk:       pk,
		input:    input,
		output:   output,
		feedback: feedback,
		wg:       wg,
	}
}
