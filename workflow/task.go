package workflow

import (
	"errors"
	"github.com/consensys/gnark/backend/witness"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	neox "github.com/txhsl/neox-dbft-verifier/circuit/neox"
)

// Task is a pending-request's actual processing
type Task struct {
	*BlockRequest
	//ce     circuit.CircuitEnum
	params []any
}

func NewTask(request *BlockRequest, params ...any) Task {
	return Task{
		BlockRequest: request,
		params:       params,
	}
}
func (task *Task) Witness() (witness.Witness, error) {
	return task.GetWitness(task.params...)
}

func (task *Task) AddParams(p ...any) {
	task.params = append(task.params, p...)
}
func (task *Task) CircuitEnum() circuit.CircuitEnum {
	return task.BlockRequest.Ce
}

func (task *Task) Next() (Task, bool, error) {
	extraVersion, err := task.ExtraVersion()
	if err != nil {
		return Task{}, false, err
	}
	switch extraVersion {
	case neox.ExtraV0:
		if task.CircuitEnum() == circuit.RlpHash {
			return Task{task.BlockRequest, make([]any, 0)}, false, nil
		} else if task.CircuitEnum() == circuit.NoSigRlp || task.CircuitEnum() == circuit.NeoxOuter {
			return Task{}, true, nil
		} else {
			return Task{}, false, errors.New("invalid task circuit Enum")
		}
	case neox.ExtraV1, neox.ExtraV2:
		if task.CircuitEnum() == circuit.RlpHash {
			return Task{task.BlockRequest, make([]any, 0)}, false, nil
		} else if task.CircuitEnum() == circuit.ToG2Hash || task.CircuitEnum() == circuit.NeoxOuter {
			return Task{}, true, nil
		} else {
			return Task{}, false, errors.New("invalid task circuit Enum")
		}
	default:
		return Task{}, false, errors.New("invalid extra version")
	}
}
