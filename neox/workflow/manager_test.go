package workflow

import (
	"testing"
)

func TestManagerWorkflow(t *testing.T) {
	manager := new(BlockManager)
	err := manager.FromJson("../cmd/workflow/configs/manager.json")
	if err != nil {
		panic(err)
	}
	err = manager.Start()
	if err != nil {
		panic(err)
	}
	for err := range manager.Feedback() {
		panic(err)
	}

}
