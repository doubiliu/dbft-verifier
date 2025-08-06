package workflow

import (
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/plugin/pipeline"
	"testing"
	"time"
)

func TestWorkerWorkflow(t *testing.T) {
	nodeConfig := config.NodeConfig{
		Mode: config.Pipeline,
		//NbMaxCPU: 64, // max
		NbSolve: 1,
		NbProve: 1,
		RlpHashInstance: pipeline.NewInstanceConfig(
			"../circuit/rlp_encode_hash_extra_v1_test.ccs",
			"../circuit/rlp_encode_hash_extra_v1_test.pk",
			"../circuit/rlp_encode_hash_extra_v1_test.vk",
		),
		ToG2HashInstance: pipeline.NewInstanceConfig(
			"../circuit/to_g2_hash.ccs",
			"../circuit/to_g2_hash.pk",
			"../circuit/to_g2_hash.vk",
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
			Port:    8890,
		},
		GrpcConfig: config.GrpcConfig{
			MessageLimitSize: 1024 * 1024 * 1024,
			Timeout:          5 * time.Second,
		},
	}
	worker := NewWorker(nodeConfig, serviceConfig)
	err := worker.Start()
	if err != nil {
		panic(err)
	}

}
