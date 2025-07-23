package workflow

import "github.com/txhsl/neox-dbft-verifier/circuit"

type NodeMode = int

const (
	Serial NodeMode = iota
	Pipeline
)

// NodeConfig gives a configuration of node
type NodeConfig struct {
	ce       circuit.CircuitEnum
	mode     NodeMode
	nbMaxCPU int // cpu number
	nbSolve  int // solver number
	nbProve  int // prover number
	ccsPath  string
	pkPath   string
	vkPath   string
	rpcUrl   string // todo
}
