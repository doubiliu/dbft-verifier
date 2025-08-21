package n3

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/circuit/n3"
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
	//service.AggregateClient // n3 has no aggregator
	feedback chan error
	parents  map[string]*n3.N3BlockHeader
	received map[string]struct{}
	network  uint32
}

func (n *Worker) SetNetwork(network uint32) {
	n.network = network
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
	fmt.Println("n3 worker network: ", n.network)
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

func (n *Worker) verifierInstance() (pipeline.PackedCircuitInstance, error) {
	return mod.LoadFromInstanceConfig(n.N3VerifierInstance)
}

func (n *Worker) runInSerial() error {
	instance, err := n.verifierInstance()
	if err != nil {
		return err
	}
	fmt.Println("instance load finish")
	go func() {
		output := n.DistributeChannel()
		for request := range n.DistributeChannel() {
			header := n3.NewN3BlockHeader(new(block.Header))
			err := header.UnmarshalJSON(request.Header)
			if err != nil {
				n.feedback <- err
				continue
			}
			if request.IsReliable {
				// a parent block for proving
				parentHash, err := header.Hash()
				if err != nil {
					n.feedback <- err
					continue
				}
				n.received[hex.EncodeToString(parentHash)] = struct{}{}
				n.parents[hex.EncodeToString(parentHash)] = header
				continue
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
			// get parent
			parent, ok := n.parents[hex.EncodeToString(header.PrevHash.BytesBE())]
			if !ok {
				// parent has not arrived
				output <- request
				continue
			}
			blockRequest := workflow.BlockRequest{
				BlockHeader: header,
				Ce:          circuit.N3Verifier,
				StartTime:   time.Now(),
			}
			task := workflow.NewTask(&blockRequest)
			task.AddParams(parent, n.network)
			w, err := task.Witness()
			if err != nil {
				n.feedback <- err
				continue
			}
			proof, err := groth16.Prove(instance.Ccs, instance.Pk, w, stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
			if err != nil {
				fmt.Println("n3 verifier prove error in block", header.Height())
				n.feedback <- err
				continue
			}
			fmt.Printf("finish n3 verifier proof, block height: %d, block hash: %d, proof: %v\n", header.Height(), blockHash, proof)
			//proveResponse := pipeline.NewProveResponse(&rlpHashTask, proof, circuit.RlpHash)
			//n.tmp <- proveResponse

		}
	}()
	return nil
}

func (n *Worker) runInPipeline() error {
	// node in Pipeline mode starts a pipelineScheduler to prove proofs in pipeline
	// todo pendingSize
	fmt.Println("node starts in pipeline mode")
	// rlp is too fast and has a high-cpu-usage solve and prove, we serially run it
	scheduler, err := pipeline.NewPipelineScheduler(n.NbSolve, n.NbProve, 100, map[circuit.CircuitEnum]mod.InstanceConfig{circuit.N3Verifier: n.N3VerifierInstance})
	if err != nil {
		return err
	}
	fmt.Println("instance load finish")

	go func() {
		output := n.DistributeChannel()
		for request := range n.DistributeChannel() {
			header := n3.NewN3BlockHeader(new(block.Header))
			err := header.UnmarshalJSON(request.Header)
			if err != nil {
				n.feedback <- err
			}
			if request.IsReliable {
				// a parent block for proving
				parentHash, err := header.Hash()
				if err != nil {
					n.feedback <- err
					continue
				}
				n.received[hex.EncodeToString(parentHash)] = struct{}{}
				n.parents[hex.EncodeToString(parentHash)] = header
				continue
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
			parent, ok := n.parents[hex.EncodeToString(header.PrevHash.BytesBE())]
			if !ok {
				// parent has not arrived
				output <- request
				continue
			}
			blockRequest := workflow.BlockRequest{
				BlockHeader: header,
				Ce:          circuit.N3Verifier,
				StartTime:   time.Now(),
			}
			task := workflow.NewTask(&blockRequest)
			task.AddParams(parent, n.network)
			scheduler.Prove(&task)
		}
	}()
	scheduler.Start()
	go func() {
		for response := range scheduler.Response {
			header := response.Request.(*workflow.Task).BlockHeader
			blockHash, err := header.Hash()
			if err != nil {
				n.feedback <- err
				continue
			}
			fmt.Printf("finish n3 verifier proof, block height: %d, block hash: %d, proof: %v\n", header.Height(), blockHash, response.Proof)
			if err != nil {
				n.feedback <- err
			}
		}
	}()
	go func() {
		for err := range scheduler.Errors() {
			n.feedback <- err
		}
	}()
	return nil
}

func (n *Worker) FromCommonConfig(cc config.CommonConfig, params ...any) error {
	n.CommonConfig = cc
	n.feedback = make(chan error, 100) // todo
	n.DistributeServer = *service.NewDistributeServer(n.ServiceConfig, n.feedback)
	n.tasks = make(chan workflow.Task, 100) // todo
	n.parents = make(map[string]*n3.N3BlockHeader)
	n.received = make(map[string]struct{})
	return nil
}
func NewWorker(nodeConfig config.NodeConfig, serviceConfig config.ServiceConfig) Worker {
	node := Worker{}
	node.NodeConfig = nodeConfig
	node.ServiceConfig = serviceConfig
	node.feedback = make(chan error, 100) // todo
	node.DistributeServer = *service.NewDistributeServer(serviceConfig, node.feedback)
	node.tasks = make(chan workflow.Task, 100) // todo
	return node
}
