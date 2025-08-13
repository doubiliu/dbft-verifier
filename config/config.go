package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type CommonConfig struct {
	NodeConfig
	ServiceConfig
}

func (c *CommonConfig) IsAggregator() bool {
	return c.Job == Aggregator
}
func (c *CommonConfig) IsWorker() bool {
	return c.Job == Worker
}

func LoadConfigFromJson(jsonPath string) (CommonConfig, error) {
	type configWrapper struct {
		Node    NodeConfig    `json:"NodeConfig"`
		Service ServiceConfig `json:"ServiceConfig"`
	}
	var wrapper configWrapper
	fileContent, err := os.ReadFile(jsonPath)
	if err != nil {
		return CommonConfig{}, fmt.Errorf("load config error: %w", err)
	}
	if err := json.Unmarshal(fileContent, &wrapper); err != nil {
		return CommonConfig{}, fmt.Errorf("load config error: %w", err)
	}
	c := new(CommonConfig)
	c.NodeConfig = wrapper.Node
	c.ServiceConfig = wrapper.Service
	return *c, nil
}
