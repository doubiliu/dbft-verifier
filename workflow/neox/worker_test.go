package neox

import (
	"github.com/txhsl/neox-dbft-verifier/config"
	"testing"
)

func TestWorkerWorkflow(t *testing.T) {
	commonConfig, err := config.LoadConfigFromJson("../../cmd/workflow/configs/172.23.166.111/node_2/common_config.json")
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
