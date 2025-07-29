package workflow

import (
	"fmt"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/plugin/pipeline"
	"testing"
	"time"
)

func TestWorkerWorkflow(t *testing.T) {
	nodeConfig := config.NodeConfig{
		Mode:     config.Serial,
		NbMaxCPU: 64, // max
		NbSolve:  -1,
		NbProve:  -1,
		RlpHashInstance: pipeline.NewInstanceConfig(
			"/root/neo/dbft-verifier/neox/circuit/rlp_encode_hash_extra_v1_test.ccs",
			"/root/neo/dbft-verifier/neox/circuit/rlp_encode_hash_extra_v1_test.pk",
			"/root/neo/dbft-verifier/neox/circuit/rlp_encode_hash_extra_v1_test.vk",
		),
		ToG2HashInstance: pipeline.NewInstanceConfig(
			"/root/neo/dbft-verifier/neox/circuit/to_g2_hash.ccs",
			"/root/neo/dbft-verifier/neox/circuit/to_g2_hash.pk",
			"/root/neo/dbft-verifier/neox/circuit/to_g2_hash.vk",
		),
		ExtraVersion: circuit.ExtraV1,
	}
	serviceConfig := config.ServiceConfig{
		ID: 0,
		Network: config.NetworkConfig{
			Aggregator: config.BaseURL{
				Address: "localhost",
				Port:    8889,
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
	go func() {
		for res := range worker.tmp {
			fmt.Println(fmt.Sprintf("Outside receive a %d response, time: %v", res.CircuitType, time.Since(res.Request.(*Task).startTime)))
		}
	}()
	err := worker.Start()
	if err != nil {
		panic(err)
	}

}
