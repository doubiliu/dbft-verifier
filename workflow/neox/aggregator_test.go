package neox

import (
	"testing"
)

func TestAggregatorWorkflow(t *testing.T) {
	aggregator := new(Aggregator)
	err := aggregator.FromJson("../cmd/workflow/configs/172.23.166.111/config_node_0.json")
	if err != nil {
		panic(err)
	}
	//aggregator := NewAggregator(nodeConfig, serviceConfig, true)
	err = aggregator.Start()
	if err != nil {
		panic(err)
	}
}
