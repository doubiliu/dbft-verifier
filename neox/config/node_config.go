package config

import (
	"github.com/txhsl/neox-dbft-verifier/plugin/pipeline"
)

type NodeMode = int
type InstanceConfig = pipeline.InstanceConfig

const (
	Serial NodeMode = iota
	Pipeline
)

// NodeConfig gives a configuration of node
type NodeConfig struct {
	Mode             NodeMode
	NbMaxCPU         int // cpu number
	NbSolve          int // solver number
	NbProve          int // prover number
	RlpHashInstance  InstanceConfig
	ToG2HashInstance InstanceConfig
	NoSigRlpInstance InstanceConfig
	OuterAggInstance InstanceConfig
	ExtraVersion     byte
}
