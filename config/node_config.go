package config

import (
	"encoding/json"
	"fmt"
	"github.com/txhsl/neox-dbft-verifier/mod"
	"os"
)

type InstanceConfig = mod.InstanceConfig
type NodeMode = int

const (
	Serial NodeMode = iota
	Pipeline
)

type NodeJob = int

const (
	Worker NodeJob = iota
	Aggregator
	N3Verifier
	Manager
)

// NodeConfig gives a configuration of node
type NodeConfig struct {
	Mode NodeMode `json:"mode"`
	Job  NodeJob  `json:"job"`
	//NbMaxCPU         int // cpu number
	NbSolve            int            `json:"nb_solve"` // solver number todo we fix it 1
	NbProve            int            `json:"nb_prove"` // prover number todo we fix it 1
	RlpHashInstance    InstanceConfig `json:"rlp_hash_instance"`
	ToG2HashInstance   InstanceConfig `json:"to_g2_hash_instance"`
	NoSigRlpInstance   InstanceConfig `json:"no_sig_rlp_instance"`
	NeoxOuterInstance  InstanceConfig `json:"neox_outer_instance"`
	N3VerifierInstance InstanceConfig `json:"n3_verifier_instance"`
	ExtraVersion       byte           `json:"extra_version"`
}

func (config *NodeConfig) FromJson(jsonPath string) error {
	fileContent, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("error reading configuration file at '%s': %w", jsonPath, err)
	}
	err = json.Unmarshal(fileContent, config)
	if err != nil {
		return fmt.Errorf("error parsing JSON from '%s': %w", jsonPath, err)
	}
	return nil
}
