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

type AggregateURL struct {
	Address        string `json:"address"`
	DistributePort int    `json:"distributePort"`
	AggregatorPort int    `json:"aggregatorPort"`
}

func (url *AggregateURL) DistributeString() string {
	return fmt.Sprintf("%s:%d", url.Address, url.DistributePort)
}
func (url *AggregateURL) AggregateString() string {
	return fmt.Sprintf("%s:%d", url.Address, url.AggregatorPort)
}

type NodeID = int
type NetworkConfig struct {
	Aggregator  AggregateURL       `json:"agg_sever"`
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
