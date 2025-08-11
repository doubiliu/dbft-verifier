package workflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/plugin/pipeline"
	"github.com/txhsl/neox-dbft-verifier/service"
	"github.com/txhsl/neox-dbft-verifier/utils"
	"golang.org/x/sync/errgroup"
	"time"
)

type PackedBlockHeader struct {
	header              *types.Header
	currentRlpHashProof groth16.Proof
	toG2HashProof       groth16.Proof
	noSigHashProof      groth16.Proof
	isVerified          bool
}

func (pb *PackedBlockHeader) CanBeVerify() bool {
	extraVersion := utils.GetBlockHeaderExtraVersion(pb.header)
	switch extraVersion {
	case circuit.ExtraV0:
		return pb.header != nil && pb.currentRlpHashProof != nil && pb.noSigHashProof != nil
	case circuit.ExtraV1, circuit.ExtraV2:
		return pb.header != nil && pb.currentRlpHashProof != nil && pb.toG2HashProof != nil
	default:
		return false // todo error?
	}
}
func (pb *PackedBlockHeader) Proofs() (groth16.Proof, groth16.Proof, error) {
	if !pb.CanBeVerify() {
		return nil, nil, errors.New("can't be verify")
	}
	extraVersion := utils.GetBlockHeaderExtraVersion(pb.header)
	switch extraVersion {
	case circuit.ExtraV0:
		return pb.currentRlpHashProof, pb.noSigHashProof, nil
	case circuit.ExtraV1, circuit.ExtraV2:
		return pb.currentRlpHashProof, pb.toG2HashProof, nil
	default:
		return nil, nil, errors.New("invalid extra version")
	}

}

func NewPackedBlockHeader(header *types.Header) *PackedBlockHeader {
	return &PackedBlockHeader{
		header:              header,
		currentRlpHashProof: nil,
		toG2HashProof:       nil,
		noSigHashProof:      nil,
		isVerified:          false,
	}
}

type Aggregator struct {
	config.CommonConfig
	tasks chan Task
	service.AggregateServer
	service.DistributeServer
	feedback               chan error
	isNoFork               bool // if is no fork, then parent and current is one-to-one, then when current finishes its proof, parent's PackedBlockHeader can be deleted
	headers                map[string]*PackedBlockHeader
	rlpHashOneTimeInstance *pipeline.PackedCircuitInstance // just use to prove the first block, then should be deleted(memory)
	//verifyInstance         pipeline.PackedCircuitInstance
}

func (agg *Aggregator) RuntimeJob() config.NodeJob {
	return config.Aggregator
}
func (agg *Aggregator) RuntimeMode() config.NodeMode {
	return agg.Mode
}

func (agg *Aggregator) loadOneTimeRlpInstance() error {
	oneTimeInstance, err := pipeline.LoadFromInstanceConfig(agg.RlpHashInstance)
	if err != nil {
		return err
	}
	agg.rlpHashOneTimeInstance = &oneTimeInstance
	return nil
}

func (agg *Aggregator) Start() error {
	//runtime.GOMAXPROCS(agg.NbMaxCPU)
	if agg.Job != config.Aggregator {
		fmt.Println(agg.Job)
		return errors.New("not a aggregator")
	}
	go func() {
		for err := range agg.feedback {
			fmt.Println("Aggregator Error: ", err)
		}
	}()
	if err := agg.loadOneTimeRlpInstance(); err != nil {
		return err
	}
	fmt.Println("load one-time rlpHash instances finished")
	go agg.processDistributeRequest()
	go agg.processAggregateRequest()
	// start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		switch agg.Mode {
		case config.Pipeline:
			return agg.runInPipeline()
		case config.Serial:
			return agg.runInSerial()
		default:
			return fmt.Errorf("invalid node mode: %v", agg.Mode)
		}
	})

	g.Go(func() error {
		fmt.Println("Aggregate Server starting in", agg.ServiceConfig.Local.AggregateString())
		return agg.StartAggregateServer(gCtx)
	})

	g.Go(func() error {
		fmt.Println("Distribute Server starting in", agg.ServiceConfig.Local.DistributeString())
		return agg.StartDistributeServer(gCtx)
	})

	err := g.Wait()
	return err
}

// processDistributeRequest manager should also distribute block to aggregator so that it can compute public witness
// we append the block into headers map, each block waits for sub-circuit proofs
func (agg *Aggregator) processDistributeRequest() {
	for request := range agg.DistributeChannel() {
		header := new(types.Header)
		err := header.UnmarshalJSON(request.Header)
		if err != nil {
			agg.feedback <- err
			continue
		}
		edata, err := circuit.EncodeHeader(header, false)
		if err != nil {
			agg.feedback <- err
		}
		blockHash := common.BytesToHash(crypto.Keccak256(edata)).Bytes()
		if _, exist := agg.headers[hex.EncodeToString(blockHash)]; exist {
			// todo Repeatedly sending blocks
			continue
		}
		agg.headers[hex.EncodeToString(blockHash)] = NewPackedBlockHeader(header)
		fmt.Printf("Receive a new block, block height: %d, block hash: %v\n", header.Number.Uint64(), blockHash)
		if request.IsReliable {
			go func() {
				if err = agg.computeFirstBlockRlpHash(header, hex.EncodeToString(blockHash)); err != nil {
					panic(fmt.Errorf("first block prove failed in aggregator, err: %s", err.Error())) // we panic
				}
			}()
		}
	}

}
func (agg *Aggregator) computeFirstBlockRlpHash(header *types.Header, blockHash string) error {
	fmt.Println("Start computing the first block rlpHash proof")
	blockRequest := BlockRequest{
		blockHeader: header,
		isInner:     true,
		startTime:   time.Now(),
	}

	rlpHashTask := Task{&blockRequest, circuit.RlpHash, make([]any, 0)}
	rlpWitness, err := rlpHashTask.Witness()
	proof, err := groth16.Prove(agg.rlpHashOneTimeInstance.Ccs, agg.rlpHashOneTimeInstance.Pk, rlpWitness, stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		return err
	}

	if _, exist := agg.headers[blockHash]; !exist {
		return errors.New("first block has not append into headers map")
	}
	pb := agg.headers[blockHash]
	pb.currentRlpHashProof = proof
	pb.isVerified = true
	fmt.Printf("first block's rlpHash Proof has computed, block height: %d\n", header.Number)
	// delete
	agg.rlpHashOneTimeInstance = nil
	return nil
}
func (agg *Aggregator) processAggregateRequest() {
	output := agg.AggregateChannel()
	for request := range agg.AggregateChannel() {
		blockHash := request.BlockHash
		hashString := hex.EncodeToString(blockHash)
		if _, exist := agg.headers[hashString]; !exist {
			// todo this can not happen, since the block header should be sent before prove
			output <- request
			continue
		}
		pb := agg.headers[hashString]
		if pb.isVerified {
			continue
		}
		proof := groth16.NewProof(ecc.BN254).(*groth16_bn254.Proof)
		_, err := proof.ReadFrom(bytes.NewReader(request.Proof))
		if err != nil {
			agg.feedback <- err
			continue
		}
		fmt.Printf("Receive a Aggregate request, block hash: %v, block height: %d, circuit: %d\n", blockHash, pb.header.Number.Uint64(), request.Circuit)
		switch circuit.CircuitEnum(request.Circuit) {
		case circuit.RlpHash:
			if pb.currentRlpHashProof == nil {
				pb.currentRlpHashProof = proof
			}
		case circuit.NoSigRlp:
			if pb.noSigHashProof == nil {
				pb.noSigHashProof = proof
			}
		case circuit.ToG2Hash:
			if pb.toG2HashProof == nil {
				pb.toG2HashProof = proof
			}
		default:
			agg.feedback <- errors.Errorf("invalid circuit type: %v", request.Circuit)
		}
		if !pb.CanBeVerify() {
			continue
		}
		// check can be verified
		current := pb.header
		parentHash := hex.EncodeToString(current.ParentHash[:])
		parentPb, exist := agg.headers[parentHash]
		if !exist {
			// todo this can happen, the parent header is sent after current header since the network is unstable
			// we just re-process it
			output <- request
			continue
		}
		if parentPb.currentRlpHashProof == nil {
			output <- request
			continue
		}
		// new task
		task := Task{
			BlockRequest: &BlockRequest{
				blockHeader: current,
				isInner:     false,
				startTime:   time.Now(),
			},
			ce: circuit.OuterAgg,
		}
		go func() { agg.tasks <- task }()
	}
}

func (agg *Aggregator) runInPipeline() error {
	fmt.Println("aggregator starts in pipeline mode")
	instanceConfig := map[circuit.CircuitEnum]pipeline.InstanceConfig{
		circuit.OuterAgg: agg.OuterAggInstance,
	}
	scheduler, err := pipeline.NewPipelineScheduler(agg.NbSolve, agg.NbProve, 100, instanceConfig)
	if err != nil {
		return err
	}
	fmt.Println("instance load finish")
	scheduler.Start()

	go func() {
		for task := range agg.tasks {
			header := task.blockHeader
			// get proofs
			// compute hash,
			edata, err := circuit.EncodeHeader(header, false)
			if err != nil {
				agg.feedback <- err
			}
			blockHash := common.BytesToHash(crypto.Keccak256(edata)).Bytes()
			fmt.Printf("Start prove a aggregate circuit, block hash: %v, block height: %d\n", blockHash, header.Number.Uint64())

			currentPb, _ := agg.headers[hex.EncodeToString(blockHash)] // no need to check, since before the task is created, headers[hashString] has been checked
			rlpHashProof, nextProof, err := currentPb.Proofs()
			if err != nil {
				agg.feedback <- err
			}
			// get parent RlpProof
			parentPb, _ := agg.headers[hex.EncodeToString(header.ParentHash[:])] // no need to check, since before the task is created, headers[hashString] has been checked
			parentRlpHashProof := parentPb.currentRlpHashProof
			task.AddParams(parentPb.header, parentRlpHashProof, rlpHashProof, nextProof)
			scheduler.Prove(&task)
		}
	}()
	go func() {
		for response := range scheduler.Response {
			header := response.Request.(*Task).blockHeader
			edata, err := circuit.EncodeHeader(header, false) // todo can this pre-compute or re-used?
			if err != nil {
				agg.feedback <- err
			}
			blockHash := common.BytesToHash(crypto.Keccak256(edata)).Bytes()

			fmt.Printf("finish outer aggregate proof, block height: %d, block hash: %v, proof: %v\n", header.Number.Uint64(), blockHash, response.Proof)
		}
	}()
	go func() {
		for err := range scheduler.Errors() {
			agg.feedback <- err
		}
	}()
	return nil // todo
}

func (agg *Aggregator) runInSerial() error {
	// load verify instance
	instance, err := pipeline.LoadFromInstanceConfig(agg.OuterAggInstance)
	if err != nil {
		return err
	}
	fmt.Println("instance load finish")

	go func() {
		for task := range agg.tasks {

			header := task.blockHeader
			// get proofs
			// compute hash,
			edata, err := circuit.EncodeHeader(header, false)
			if err != nil {
				agg.feedback <- err
			}
			blockHash := common.BytesToHash(crypto.Keccak256(edata)).Bytes()
			fmt.Printf("Start prove a aggregate circuit, block hash: %v, block height: %d\n", blockHash, header.Number.Uint64())

			currentPb, _ := agg.headers[hex.EncodeToString(blockHash)] // no need to check, since before the task is created, headers[hashString] has been checked
			rlpHashProof, nextProof, err := currentPb.Proofs()
			if err != nil {
				agg.feedback <- err
			}
			// get parent RlpProof
			parentPb, _ := agg.headers[hex.EncodeToString(header.ParentHash[:])] // no need to check, since before the task is created, headers[hashString] has been checked
			parentRlpHashProof := parentPb.currentRlpHashProof
			task.AddParams(parentPb.header, parentRlpHashProof, rlpHashProof, nextProof)
			outerAggWitness, err := task.Witness()
			if err != nil {
				agg.feedback <- err
				continue
			}

			proof, err := groth16.Prove(instance.Ccs, instance.Pk, outerAggWitness, backend.WithProverHashToFieldFunction(sha256.New()))
			if err != nil {
				agg.feedback <- err
			}
			fmt.Printf("finish outer aggregate proof, block height: %d, block hash: %v, proof: %v\n", header.Number.Uint64(), blockHash, proof)

		}
	}()
	return nil
}

func (agg *Aggregator) FromCommonConfig(cc config.CommonConfig, params ...any) error {
	agg.CommonConfig = cc
	isNoFork := true
	if len(params) != 0 {
		_, ok := params[0].(bool)
		if !ok {
			return errors.New("invalid param")
		}
		isNoFork = params[0].(bool)
	}
	//agg.CommonConfig, err = config.LoadConfigFromJson(jsonPath)
	fmt.Println(agg.CommonConfig.Network)
	agg.feedback = make(chan error, 100) // todo
	agg.DistributeServer = *service.NewDistributeServer(agg.ServiceConfig, agg.feedback)
	agg.AggregateServer = *service.NewAggregateServer(agg.ServiceConfig, agg.feedback)
	agg.tasks = make(chan Task, 100) // todo
	agg.headers = make(map[string]*PackedBlockHeader)
	agg.isNoFork = isNoFork
	return nil
}

func NewAggregator(nodeConfig config.NodeConfig, serviceConfig config.ServiceConfig, isNoFork bool) Aggregator {
	// todo connection
	node := Aggregator{}
	node.NodeConfig = nodeConfig
	node.ServiceConfig = serviceConfig
	node.feedback = make(chan error, 100) // todo
	node.DistributeServer = *service.NewDistributeServer(serviceConfig, node.feedback)
	node.AggregateServer = *service.NewAggregateServer(serviceConfig, node.feedback)
	node.tasks = make(chan Task, 100) // todo
	node.headers = make(map[string]*PackedBlockHeader)
	node.isNoFork = isNoFork
	return node
}
