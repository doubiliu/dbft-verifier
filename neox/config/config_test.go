package config

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNodeConfig(t *testing.T) {
	assert := assert.New(t)
	testJsonPath := "../cmd/workflow/node_config.json"
	c := NodeConfig{}
	err := c.FromJson(testJsonPath)
	assert.NoError(err)
	fmt.Println(c.NbSolve, c.NbProve)
	fmt.Println(c.Mode, c.ExtraVersion)
	fmt.Println(c.RlpHashInstance)
	fmt.Println(c.ToG2HashInstance)
	fmt.Println(c.NoSigRlpInstance)
	fmt.Println(c.OuterAggInstance)
}
