package pipeline

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/txhsl/neox-dbft-verifier/helper"
)

// PackedCircuitInstance We pack circuit's ccs, pk, vk together
type PackedCircuitInstance struct {
	Ccs constraint.ConstraintSystem
	Pk  groth16.ProvingKey
	Vk  groth16.VerifyingKey
}
type InstanceConfig struct {
	ccsPath string `json:"ccs_path"`
	pkPath  string `json:"pk_path"`
	vkPath  string `json:"vk_path"`
}

func NewInstanceConfig(ccsPath string, pkPath, vkPath string) InstanceConfig {
	return InstanceConfig{
		ccsPath: ccsPath,
		pkPath:  pkPath,
		vkPath:  vkPath,
	}
}

func LoadFromInstanceConfig(config InstanceConfig) (PackedCircuitInstance, error) {
	ccs, err := helper.ReadCCS(config.ccsPath)
	if err != nil {
		return PackedCircuitInstance{}, err
	}
	pk, err := helper.ReadProvingKey(config.pkPath)
	if err != nil {
		return PackedCircuitInstance{}, err
	}
	vk, err := helper.ReadVerifyingKey(config.vkPath)
	if err != nil {
		return PackedCircuitInstance{}, err
	}
	return PackedCircuitInstance{
		Ccs: ccs,
		Pk:  pk,
		Vk:  vk,
	}, nil
}
