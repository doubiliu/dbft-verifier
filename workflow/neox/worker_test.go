package neox

import (
	"testing"
)

func TestWorkerWorkflow(t *testing.T) {
	worker := new(Worker)
	err := worker.FromJson("../../cmd/workflow/configs/172.23.166.111/node_2/common_config.json")
	if err != nil {
		panic(err)
	}
	err = worker.Start()
	if err != nil {
		panic(err)
	}
}
