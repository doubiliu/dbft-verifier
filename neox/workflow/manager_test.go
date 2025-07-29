package workflow

import (
	"github.com/txhsl/neox-dbft-verifier/config"
	"testing"
	"time"
)

func TestManagerWorkflow(t *testing.T) {
	serviceConfig := config.ServiceConfig{
		ID: -1, // manager
		Local: config.BaseURL{
			Address: "localhost",
			Port:    8888,
		},
		GrpcConfig: config.GrpcConfig{
			MessageLimitSize: 1024 * 1024 * 1024,
			Timeout:          5 * time.Second,
		},
		Network: config.NetworkConfig{
			Aggregator: config.BaseURL{
				Address: "localhost",
				Port:    8889,
			},
			BlockSource: "https://neoxt4seed1.ngd.network/",
			Workers: map[config.NodeID]config.BaseURL{
				0: {
					Address: "localhost",
					Port:    8890,
				},
				//1: {
				//	Address: "localhost",
				//	Port:    8891,
				//},
			},
		},
	}
	manager := NewBlockManager(serviceConfig)
	err := manager.Start()
	if err != nil {
		panic(err)
	}
	for err := range manager.Feedback() {
		panic(err)
	}

}
