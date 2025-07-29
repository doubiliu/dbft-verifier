package config

import (
	"fmt"
	"time"
)

type ServiceConfig struct {
	ID      NodeID
	Network NetworkConfig
	Local   BaseURL
	GrpcConfig
}

type NodeID = int
type NetworkConfig struct {
	Aggregator  BaseURL            `json:"agg_sever"`
	Workers     map[NodeID]BaseURL `json:"node_severs"`
	BlockSource string             `json:"block_source"`
}

type BaseURL struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

func (url *BaseURL) String() string {
	return fmt.Sprintf("%s:%d", url.Address, url.Port)
}

type GrpcConfig struct {
	MessageLimitSize int
	Timeout          time.Duration
}
