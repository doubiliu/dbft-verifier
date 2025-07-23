package workflow

import (
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"github.com/txhsl/neox-dbft-verifier/plugin/pipeline"
	"runtime"
)

// InnerCircuitProverNode impls a workflow of generate inner circuit proofs
// each node only proves one certain circuit
type InnerCircuitProverNode struct {
	NodeConfig
	pk         groth16.ProvingKey
	vk         groth16.VerifyingKey // no need todo we can delete it after test
	ccs        constraint.ConstraintSystem
	connection TempLocalConnection // todo we should impl it in rpc
	feedback   chan error
}

func (n *InnerCircuitProverNode) Start() {
	runtime.GOMAXPROCS(n.nbMaxCPU)
	go func() {
		for err := range n.feedback {
			fmt.Println("InnerCircuitProverNode Error: ", err)
		}
	}()
	switch n.mode {
	case Pipeline:
		n.runInPipeline()
	case Serial:
		n.runInSerial()
	default:
		panic("invalid node mode")

	}
}

func (n *InnerCircuitProverNode) runInSerial() {
	for request := range n.connection.input {
		witness, err := request.Witness()
		if err != nil {
			n.feedback <- err
			continue
		}
		proof, err := groth16.Prove(n.ccs, n.pk, witness)
		proveResponse := pipeline.NewProveResponse(request, proof)
		n.connection.output <- &proveResponse
	}
}

func (n *InnerCircuitProverNode) runInPipeline() {
	// node in Pipeline mode starts a pipelineScheduler to prove proofs in pipeline
	// todo pendingSize
	fmt.Println("node starts in pipeline mode")
	scheduler := pipeline.NewPipelineScheduler(n.nbSolve, n.nbProve, 100, n.ccs, n.pk, n.vk)
	scheduler.Start()
	go func() {
		for response := range scheduler.Response {
			fmt.Println("finish prove")
			n.connection.output <- &response
		}
	}()
	go func() {
		for err := range scheduler.Errors() {
			n.feedback <- err
		}
	}()
	for request := range n.connection.input {
		fmt.Println("receive request, add to solve queue")
		scheduler.Prove(request)
	}
}
func (n *InnerCircuitProverNode) SetTempConnection(connection TempLocalConnection) {
	n.connection = connection
}

func NewNode(config NodeConfig) InnerCircuitProverNode {
	// todo connection
	node := InnerCircuitProverNode{}
	node.NodeConfig = config
	node.feedback = make(chan error, 100) // todo
	// load ccs, pk, vk
	ccs, err := helper.ReadCCS(config.ccsPath)
	if err != nil {
		panic(err)
	}
	pk, err := helper.ReadProvingKey(config.pkPath)
	if err != nil {
		panic(err)
	}
	vk, err := helper.ReadVerifyingKey(config.vkPath)
	if err != nil {
		panic(err)
	}
	node.ccs, node.pk, node.vk = ccs, pk, vk
	return node
}
