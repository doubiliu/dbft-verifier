package neox

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	neox "github.com/txhsl/neox-dbft-verifier/circuit/neox"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/mod"
	"github.com/txhsl/neox-dbft-verifier/plugin/pipeline"
	"github.com/txhsl/neox-dbft-verifier/service"
	"github.com/txhsl/neox-dbft-verifier/workflow"
	"golang.org/x/sync/errgroup"
	"time"
)

// Worker impls a workflow of generate inner circuit proofs
// each node only proves one certain circuit
type Worker struct {
	config.CommonConfig
	tasks chan workflow.Task
	service.DistributeServer
	service.AggregateClient
	feedback chan error
	received map[string]struct{}
}

func (n *Worker) RuntimeJob() config.NodeJob {
	return config.Worker
}
func (n *Worker) RuntimeMode() config.NodeMode {
	return n.Mode
}

func (n *Worker) Start() error {
	//runtime.GOMAXPROCS(n.NbMaxCPU)
	if n.Job != config.Worker {
		return errors.New("not a worker")
	}
	go func() {
		for err := range n.feedback {
			fmt.Println("Worker Error: ", err)
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
		fmt.Println("Distribute Server start in", n.ServiceConfig.Local.DistributeString())
		return n.StartDistributeServer(gCtx)
	})
	err := g.Wait()
	return err
}
func (n *Worker) rlpInstance() (pipeline.PackedCircuitInstance, error) {
	return mod.LoadFromInstanceConfig(n.RlpHashInstance)
}

func (n *Worker) nextInstance() (pipeline.PackedCircuitInstance, error) {
	switch n.ExtraVersion {
	case neox.ExtraV0:

		return mod.LoadFromInstanceConfig(n.NoSigRlpInstance)
	case neox.ExtraV1, neox.ExtraV2:
		return mod.LoadFromInstanceConfig(n.ToG2HashInstance)
	default:
		return pipeline.PackedCircuitInstance{}, errors.New("invalid version")
	}
}

func (n *Worker) rlpInstanceConfig() (map[circuit.CircuitEnum]config.InstanceConfig, error) {
	return map[circuit.CircuitEnum]config.InstanceConfig{
		circuit.RlpHash: n.RlpHashInstance,
	}, nil
}

func (n *Worker) nextInstanceConfig() (map[circuit.CircuitEnum]config.InstanceConfig, error) {
	switch n.ExtraVersion {
	case neox.ExtraV0:
		return map[circuit.CircuitEnum]config.InstanceConfig{
			circuit.NoSigRlp: n.NoSigRlpInstance,
		}, nil
	case neox.ExtraV1, neox.ExtraV2:
		return map[circuit.CircuitEnum]config.InstanceConfig{
			circuit.ToG2Hash: n.ToG2HashInstance,
		}, nil
	default:
		return nil, errors.New("invalid node version")
	}

}
func (n *Worker) instanceConfig() (map[circuit.CircuitEnum]config.InstanceConfig, error) {
	// each innerCircuitProverNode just need to get 2 circuits
	// rlpHash
	config := make(map[circuit.CircuitEnum]config.InstanceConfig)
	config[circuit.RlpHash] = n.RlpHashInstance
	switch n.ExtraVersion {
	case neox.ExtraV0:
		config[circuit.NoSigRlp] = n.NoSigRlpInstance
	case neox.ExtraV1, neox.ExtraV2:
		config[circuit.ToG2Hash] = n.ToG2HashInstance
	default:
		return nil, errors.New("invalid node version")
	}
	return config, nil
}

func (n *Worker) runInSerial() error {
	//c, err := n.instanceConfig()
	rlpInstance, err := n.rlpInstance()
	if err != nil {
		return err
	}
	nextInstance, err := n.nextInstance()
	if err != nil {
		return err
	}
	fmt.Println("instance load finish")
	go func() {
		for request := range n.DistributeChannel() {
			if request.IsReliable {
				fmt.Println("first block need not to be proved in worker, ignore it")
				continue
			}
			header := neox.NewNeoxBlockHeader(new(types.Header))
			err := header.UnmarshalJSON(request.Header)
			if err != nil {
				n.feedback <- err
			}
			blockHash, err := header.Hash()
			if err != nil {
				n.feedback <- err
				continue
			}
			if _, ok := n.received[hex.EncodeToString(blockHash)]; ok {
				continue // Repeatedly sending blocks
			}
			n.received[hex.EncodeToString(blockHash)] = struct{}{}
			fmt.Printf("receive block distribute request, block height: %d\n", header.Height())
			blockRequest := workflow.BlockRequest{
				BlockHeader: header,
				Ce:          circuit.RlpHash,
				StartTime:   time.Now(),
			}
			rlpHashTask := workflow.NewTask(&blockRequest)
			rlpWitness, err := rlpHashTask.Witness()
			if err != nil {
				n.feedback <- err
				continue
			}

			proof, err := groth16.Prove(rlpInstance.Ccs, rlpInstance.Pk, rlpWitness, stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
			if err != nil {
				fmt.Println("rlpHash prove error in block", header.Height())
				n.feedback <- err
				continue
			}
			fmt.Printf("finish rlpHash proof, block height: %d\n", header.Height())
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
			nextWitness, err := next.Witness()
			if err != nil {
				n.feedback <- err
				continue
			}
			nextProof, err := groth16.Prove(nextInstance.Ccs, nextInstance.Pk, nextWitness, blockRequest.Option()...)
			if err != nil {
				fmt.Println("next prove error in block", header.Height())
				n.feedback <- err
				continue
			}
			//nextResponse := pipeline.NewProveResponse(&next, nextProof, next.ce)
			err = n.CommitProof(header, nextProof, next.CircuitEnum())
			fmt.Printf("finish next proof, block height: %d\n", header.Height())

		}
	}()
	return nil
}

func (n *Worker) runInPipeline() error {
	// node in Pipeline mode starts a pipelineScheduler to prove proofs in pipeline
	// todo pendingSize
	fmt.Println("node starts in pipeline mode")
	rlpInstance, err := n.rlpInstance()
	if err != nil {
		return err
	}
	nextInstanceConfig, err := n.nextInstanceConfig()
	if err != nil {
		return err
	}
	// rlp is too fast and has a high-cpu-usage solve and prove, we serially run it
	//rlpScheduler, err := pipeline.NewPipelineScheduler(n.NbSolve, n.NbProve, 100, rlpInstanceConfig)
	nextScheduler, err := pipeline.NewPipelineScheduler(n.NbSolve, n.NbProve, 100, nextInstanceConfig)
	if err != nil {
		return err
	}
	fmt.Println("instance load finish")

	go func() {
		for request := range n.DistributeChannel() {
			if request.IsReliable {
				fmt.Println("first block need not to be proved in worker, ignore it")
				continue
			}
			header := neox.NewNeoxBlockHeader(new(types.Header))
			err := header.UnmarshalJSON(request.Header)
			if err != nil {
				n.feedback <- err
			}
			blockHash, err := header.Hash()
			if err != nil {
				n.feedback <- err
				continue
			}
			if _, ok := n.received[hex.EncodeToString(blockHash)]; ok {
				continue // Repeatedly sending blocks
			}
			n.received[hex.EncodeToString(blockHash)] = struct{}{}
			fmt.Printf("receive block distribute request, block height: %d\n", header.Height())
			blockRequest := workflow.BlockRequest{
				BlockHeader: header,
				Ce:          circuit.RlpHash,
				StartTime:   time.Now(),
			}
			task := workflow.NewTask(&blockRequest)
			n.tasks <- task                    // tasks is used for serial running
			next, isFinish, err := task.Next() // can pipeline
			if err != nil {
				n.feedback <- err
				continue
			}
			if isFinish {
				continue
			}
			nextScheduler.Prove(&next)
		}
	}()
	//rlpScheduler.Start()
	nextScheduler.Start()
	//go func() {
	//	for response := range rlpScheduler.Response {
	//		fmt.Printf("finish prove block %d, circuit: %d\n", response.Request.(*Task).blockHeader.Number, response.CircuitType)
	//		err = n.CommitProof(response.Request.(*Task).blockHeader, response.Proof, response.CircuitEnum())
	//		if err != nil {
	//			n.feedback <- err
	//		}
	//	}
	//}()
	go func() {
		for response := range nextScheduler.Response {
			fmt.Printf("finish next proof, circuit: %d, block height: %d\n", response.CircuitType, response.Request.(*workflow.Task).BlockHeader.Height())
			err = n.CommitProof(response.Request.(*workflow.Task).BlockHeader.(*neox.NeoxBlockHeader), response.Proof, response.CircuitEnum())
			if err != nil {
				n.feedback <- err
			}
		}
	}()
	//go func() {
	//	for err := range rlpScheduler.Errors() {
	//		n.feedback <- err
	//	}
	//}()
	go func() {
		for err := range nextScheduler.Errors() {
			n.feedback <- err
		}
	}()
	// rlp(serial)
	go func() {
		for task := range n.tasks {
			//if task.CircuitEnum() == circuit.RlpHash {
			//	rlpScheduler.Prove(&task)
			//} else {
			//	nextScheduler.Prove(&task)
			//}
			if task.CircuitEnum() != circuit.RlpHash {
				n.feedback <- fmt.Errorf("invalid circuit type in rlp tasks: %v", task.CircuitEnum())
				continue
			}
			rlpWitness, err := task.Witness()
			if err != nil {
				n.feedback <- err
				continue
			}

			proof, err := groth16.Prove(rlpInstance.Ccs, rlpInstance.Pk, rlpWitness, stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
			if err != nil {
				fmt.Println("rlpHash prove error in block", task.BlockHeader.Height())
				n.feedback <- err
				continue
			}
			fmt.Printf("finish rlpHash proof, block height: %d\n", task.BlockHeader.Height())
			//proveResponse := pipeline.NewProveResponse(&rlpHashTask, proof, circuit.RlpHash)
			//n.tmp <- proveResponse
			err = n.CommitProof(task.BlockHeader.(*neox.NeoxBlockHeader), proof, circuit.RlpHash)
			if err != nil {
				n.feedback <- err
				continue
			}
		}
	}()
	return nil
}

func (n *Worker) FromCommonConfig(cc config.CommonConfig, params ...any) error {
	n.CommonConfig = cc
	n.feedback = make(chan error, 100) // todo
	n.AggregateClient = *service.NewAggregateClient(n.ServiceConfig)
	n.DistributeServer = *service.NewDistributeServer(n.ServiceConfig, n.feedback)
	n.tasks = make(chan workflow.Task, 100) // todo
	n.received = make(map[string]struct{})
	return nil
}
func NewWorker(nodeConfig config.NodeConfig, serviceConfig config.ServiceConfig) Worker {
	node := Worker{}
	node.NodeConfig = nodeConfig
	node.ServiceConfig = serviceConfig
	node.feedback = make(chan error, 100) // todo
	node.AggregateClient = *service.NewAggregateClient(serviceConfig)
	node.DistributeServer = *service.NewDistributeServer(serviceConfig, node.feedback)
	node.tasks = make(chan workflow.Task, 100) // todo
	return node
}
