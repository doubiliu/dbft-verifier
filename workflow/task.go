package workflow

import (
	"errors"
	"github.com/consensys/gnark/backend/witness"
	"github.com/txhsl/neox-dbft-verifier/circuit"
)

// Task is a pending-request's actual processing
type Task struct {
	*BlockRequest
	ce     circuit.CircuitEnum
	params []any
}

func (task *Task) Witness() (witness.Witness, error) {
	p := append([]any{task.ce}, task.params...)
	return task.GetWitness(p...)
}

func (task *Task) AddParams(p ...any) {
	task.params = append(task.params, p...)
}
func (task *Task) CircuitEnum() circuit.CircuitEnum {
	return task.ce
}

func (task *Task) Next() (Task, bool, error) {
	extraVersion, err := task.ExtraVersion()
	if err != nil {
		return Task{}, false, err
	}
	switch extraVersion {
	case circuit.ExtraV0:
		if task.ce == circuit.RlpHash {
			return Task{task.BlockRequest, circuit.NoSigRlp, make([]any, 0)}, false, nil
		} else if task.ce == circuit.NoSigRlp || task.ce == circuit.OuterAgg {
			return Task{}, true, nil
		} else {
			return Task{}, false, errors.New("invalid task circuit Enum")
		}
	case circuit.ExtraV1, circuit.ExtraV2:
		if task.ce == circuit.RlpHash {
			return Task{task.BlockRequest, circuit.ToG2Hash, make([]any, 0)}, false, nil
		} else if task.ce == circuit.ToG2Hash || task.ce == circuit.OuterAgg {
			return Task{}, true, nil
		} else {
			return Task{}, false, errors.New("invalid task circuit Enum")
		}
	default:
		return Task{}, false, errors.New("invalid extra version")
	}
}
