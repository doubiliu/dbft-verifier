package workflow

import (
	"context"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/plugin/pipeline"
	"github.com/txhsl/neox-dbft-verifier/service"
	"golang.org/x/sync/errgroup"
	"runtime"
	"time"
)

// Worker impls a workflow of generate inner circuit proofs
// each node only proves one certain circuit
type Worker struct {
	config.NodeConfig
	config.ServiceConfig
	tasks chan Task
	service.DistributeServer
	service.AggregateClient
	feedback chan error
}

func (n *Worker) Start() error {
	runtime.GOMAXPROCS(n.NbMaxCPU)
	go func() {
		for err := range n.feedback {
			fmt.Println("InnerCircuitProverNode Error: ", err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		switch n.Mode {
		case config.Pipeline:
			return n.runInPipeline()
		case config.Serial:
			return n.runInSerial()
		default:
			return errors.New("invalid mode")
		}
	})
	g.Go(func() error {
		fmt.Println("Distribute Server start in", n.ServiceConfig.Local.String())
		return n.StartDistributeServer(gCtx)
	})
	err := g.Wait()
	return err
}
func (n *Worker) instanceConfig() (map[circuit.CircuitEnum]config.InstanceConfig, error) {
	// each innerCircuitProverNode just need to get 2 circuits
	// rlpHash
	config := make(map[circuit.CircuitEnum]config.InstanceConfig)
	config[circuit.RlpHash] = n.RlpHashInstance
	switch n.ExtraVersion {
	case circuit.ExtraV0:
		config[circuit.NoSigRlp] = n.NoSigRlpInstance
	case circuit.ExtraV1, circuit.ExtraV2:
		config[circuit.ToG2Hash] = n.ToG2HashInstance
	default:
		return nil, errors.New("invalid node version")
	}
	return config, nil
}

func (n *Worker) runInSerial() error {
	c, err := n.instanceConfig()
	if err != nil {
		return err
	}
	instances := make(map[circuit.CircuitEnum]pipeline.PackedCircuitInstance)
	for ce, ic := range c {
		// load ccs, pk
		instance, err := pipeline.LoadFromInstanceConfig(ic)
		if err != nil {
			n.feedback <- err
			continue
		}
		instances[ce] = instance
	}
	fmt.Println("instance load finish")
	go func() {
		for request := range n.DistributeChannel() {
			if request.IsReliable {
				fmt.Println("first block need not to be proved in worker, ignore it")
				continue
			}
			header := new(types.Header)
			err := header.UnmarshalJSON(request.Header)
			if err != nil {
				n.feedback <- err
			}
			fmt.Printf("receive block distribute request, block height: %d\n", header.Number.Uint64())
			blockRequest := BlockRequest{
				blockHeader: header,
				isInner:     true,
				startTime:   time.Now(),
			}
			rlpHashTask := Task{&blockRequest, circuit.RlpHash}
			rlpWitness, err := rlpHashTask.GetWitness()
			if err != nil {
				n.feedback <- err
				continue
			}
			instance, ok := instances[circuit.RlpHash]
			if !ok {
				n.feedback <- fmt.Errorf("invalid instance for circuitEnum %d", rlpHashTask.ce)
				continue
			}

			proof, err := groth16.Prove(instance.Ccs, instance.Pk, rlpWitness, stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
			if err != nil {
				fmt.Println("rlpHash prove error in block", header.Number.Uint64())
				n.feedback <- err
				continue
			}
			fmt.Printf("finish rlpHash proof, block height: %d\n", header.Number.Uint64())
			//proveResponse := pipeline.NewProveResponse(&rlpHashTask, proof, circuit.RlpHash)
			//n.tmp <- proveResponse
			err = n.CommitProof(header, proof, circuit.RlpHash)
			if err != nil {
				n.feedback <- err
				continue
			}
			// next is noSig/toG2
			next, isFinish, err := rlpHashTask.Next()
			if err != nil {
				n.feedback <- err
				continue
			}
			if isFinish {
				continue
			}
			nextInstance, ok := instances[next.ce]
			if !ok {
				n.feedback <- fmt.Errorf("invalid instance for circuitEnum %d", next.ce)
				continue
			}
			nextWitness, err := next.GetWitness()
			if err != nil {
				n.feedback <- err
				continue
			}
			nextProof, err := groth16.Prove(nextInstance.Ccs, nextInstance.Pk, nextWitness, blockRequest.Option()...)
			if err != nil {
				fmt.Println("next prove error in block", header.Number.Uint64())
				n.feedback <- err
				continue
			}
			//nextResponse := pipeline.NewProveResponse(&next, nextProof, next.ce)
			err = n.CommitProof(header, nextProof, next.ce)
			fmt.Printf("finish next proof, block height: %d\n", header.Number.Uint64())

		}
	}()
	return nil
}

func (n *Worker) runInPipeline() error {
	// node in Pipeline mode starts a pipelineScheduler to prove proofs in pipeline
	// todo pendingSize
	fmt.Println("node starts in pipeline mode")
	config, err := n.instanceConfig()
	if err != nil {
		return err
	}
	scheduler, err := pipeline.NewPipelineScheduler(n.NbSolve, n.NbProve, 100, config)
	if err != nil {
		return err
	}
	fmt.Println("instance load finish")

	go func() {
		for request := range n.DistributeChannel() {
			header := new(types.Header)
			err := header.UnmarshalJSON(request.Header)
			if err != nil {
				n.feedback <- err
			}
			blockRequest := BlockRequest{
				blockHeader: header,
				isInner:     true,
				startTime:   time.Now(),
			}
			task := Task{&blockRequest, circuit.RlpHash}
			n.tasks <- task
			next, isFinish, err := task.Next() // can pipeline
			if err != nil {
				n.feedback <- err
				continue
			}
			if isFinish {
				continue
			}
			n.tasks <- next
		}
	}()
	scheduler.Start()
	go func() {
		for response := range scheduler.Response {
			fmt.Println("finish prove")
			err = n.CommitProof(response.Request.(*Task).blockHeader, response.Proof, response.CircuitEnum())
			if err != nil {
				n.feedback <- err
			}
			//n.connection.output <- &response
		}
	}()
	go func() {
		for err := range scheduler.Errors() {
			n.feedback <- err
		}
	}()
	go func() {
		for task := range n.tasks {
			fmt.Println("receive request, add to solve queue")
			scheduler.Prove(&task)
		}
	}()
	return nil
}

func NewWorker(nodeConfig config.NodeConfig, serviceConfig config.ServiceConfig) Worker {
	// todo connection
	node := Worker{}
	node.NodeConfig = nodeConfig
	node.ServiceConfig = serviceConfig
	node.feedback = make(chan error, 100) // todo
	node.AggregateClient = *service.NewAggregateClient(serviceConfig)
	node.DistributeServer = *service.NewDistributeServer(serviceConfig, node.feedback)
	node.tasks = make(chan Task, 100) // todo
	return node
}
