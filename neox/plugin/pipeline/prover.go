package pipeline

import (
	"context"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"sync"
)

type PipelineProver struct {
	proveFunc map[circuit.CircuitEnum]func(solution any) (groth16.Proof, error)
	input     <-chan ProveRequest
	output    chan<- ProveResponse
	feedback  chan<- error
	wg        *sync.WaitGroup
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
	defer func() {
		<-control
	}()
	prove, ok := prover.proveFunc[request.CircuitEnum()]
	if !ok {
		prover.feedback <- fmt.Errorf("unsupported circuit type: %d", request.CircuitEnum())
	}
	proof, err := prove(request.Solution)
	if err != nil {
		select {
		case prover.feedback <- err:
		default:
		}
		return
	}
	prover.output <- NewProveResponse(request.Request, proof, request.CircuitEnum())
}

func NewPipelineProver(wg *sync.WaitGroup, proveFunc map[circuit.CircuitEnum]func(solution any) (groth16.Proof, error), input <-chan ProveRequest, output chan<- ProveResponse, feedback chan<- error) *PipelineProver {
	return &PipelineProver{
		proveFunc: proveFunc,
		input:     input,
		output:    output,
		feedback:  feedback,
		wg:        wg,
	}
}
