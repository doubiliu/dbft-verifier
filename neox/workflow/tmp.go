package workflow

import "github.com/txhsl/neox-dbft-verifier/plugin/pipeline"

// TempLocalConnection simulates a request channel
// Finally we should impl it in rpc
type TempLocalConnection struct {
	input  chan pipeline.Request
	output chan any
}

func NewTempLocalConnection() TempLocalConnection {
	input := make(chan pipeline.Request, 100) // todo
	output := make(chan any, 100)             // todo
	return TempLocalConnection{input, output}

}
