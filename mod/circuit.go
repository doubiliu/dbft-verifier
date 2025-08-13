package mod

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
	CcsPath string `json:"ccs_path"`
	PkPath  string `json:"pk_path"`
	VkPath  string `json:"vk_path"`
}

func NewInstanceConfig(ccsPath string, pkPath, vkPath string) InstanceConfig {
	return InstanceConfig{
		CcsPath: ccsPath,
		PkPath:  pkPath,
		VkPath:  vkPath,
	}
}

func LoadFromInstanceConfig(config InstanceConfig) (PackedCircuitInstance, error) {
	ccs, err := helper.ReadCCS(config.CcsPath)
	if err != nil {
		return PackedCircuitInstance{}, err
	}
	pk, err := helper.ReadProvingKey(config.PkPath)
	if err != nil {
		return PackedCircuitInstance{}, err
	}
	vk, err := helper.ReadVerifyingKey(config.VkPath)
	if err != nil {
		return PackedCircuitInstance{}, err
	}
	return PackedCircuitInstance{
		Ccs: ccs,
		Pk:  pk,
		Vk:  vk,
	}, nil
}
