package workflow

import (
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/plugin/pipeline"
	"testing"
	"time"
)

func TestAggregatorWorkflow(t *testing.T) {
	nodeConfig := config.NodeConfig{
		Mode: config.Serial,
		//NbMaxCPU: 64, // max
		NbSolve: 1,
		NbProve: 1,
		RlpHashInstance: pipeline.NewInstanceConfig(
			"../circuit/rlp_encode_hash_extra_v1_test.ccs",
			"../circuit/rlp_encode_hash_extra_v1_test.pk",
			"../circuit/rlp_encode_hash_extra_v1_test.vk",
		), // to prove first block, one-time
		OuterAggInstance: pipeline.NewInstanceConfig(
			"../circuit/verify_header_extra_v1.ccs",
			"../circuit/verify_header_extra_v1.pk",
			"../circuit/verify_header_extra_v1.vk",
		),
		ExtraVersion: circuit.ExtraV1,
	}
	serviceConfig := config.ServiceConfig{
		ID: 0,
		Network: config.NetworkConfig{
			Aggregator: config.AggregateURL{
				Address:        "localhost",
				DistributePort: 8888,
				AggregatorPort: 8889,
			},
			Workers:     nil, // no need
			BlockSource: "",  // no need
		},
		Local: config.BaseURL{
			Address: "localhost",
			Port:    8888, // to receive block
		},
		GrpcConfig: config.GrpcConfig{
			MessageLimitSize: 1024 * 1024 * 1024,
			Timeout:          5 * time.Second,
		},
	}
	aggregator := NewAggregator(nodeConfig, serviceConfig, true)
	//go func() {
	//	for res := range worker.tmp {
	//		fmt.Println(fmt.Sprintf("Outside receive a %d response, time: %v", res.CircuitType, time.Since(res.Request.(*Task).startTime)))
	//	}
	//}()
	err := aggregator.Start()
	if err != nil {
		panic(err)
	}
}
