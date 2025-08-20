package n3

import (
	"github.com/txhsl/neox-dbft-verifier/config"
	"testing"
)

func TestWorkerWorkflow(t *testing.T) {
	commonConfig, err := config.LoadConfigFromJson("../../cmd/workflow/configs/localhost/node_1/common_config.json")
	if err != nil {
		panic(err)
	}
	worker := new(Worker)
	err = worker.FromCommonConfig(commonConfig)
	if err != nil {
		panic(err)
	}
	err = worker.Start() // blocked
	if err != nil {
		panic(err)
	}
}
