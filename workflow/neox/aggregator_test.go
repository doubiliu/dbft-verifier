package neox

import (
	"github.com/txhsl/neox-dbft-verifier/config"
	"testing"
)

func TestAggregatorWorkflow(t *testing.T) {
	commonConfig, err := config.LoadConfigFromJson("../../cmd/workflow/configs/172.23.166.111/node_0/common_config.json")
	var aggregator Aggregator
	err = aggregator.FromCommonConfig(commonConfig)
	if err != nil {
		panic(err)
	}
	err = aggregator.Start() // blocked
	if err != nil {
		panic(err)
	}
}
