package config

import (
	"fmt"
)

type ServiceConfig struct {
	ID      NodeID        `json:"id"`
	Network NetworkConfig `json:"network"`
	Local   BaseURL       `json:"local"`
	//GrpcConfig `json:"grpc_config"`
}

type NodeID = int
type WorkerID = NodeID
type AggregatorID = NodeID

// NetworkConfig all nodes have a same NetworkConfig
type NetworkConfig struct {
	Aggregators map[AggregatorID]BaseURL `json:"agg_servers"`
	Workers     map[WorkerID]BaseURL     `json:"worker_servers"`
	BlockSource string                   `json:"block_source"`
}

type BaseURL struct {
	Address        string `json:"address"`
	DistributePort int    `json:"distribute_port"`
	AggregatorPort int    `json:"aggregate_port"`
}

func (url *BaseURL) DistributeString() string {
	return fmt.Sprintf("%s:%d", url.Address, url.DistributePort)
}
func (url *BaseURL) AggregateString() string {
	return fmt.Sprintf("%s:%d", url.Address, url.AggregatorPort)
}

//// GrpcConfig all nodes have a same GrpcConfig
//type GrpcConfig struct {
//	MessageLimitSize int           `json:"message_limit_size"`
//	Timeout          time.Duration `json:"timeout"`
//}
