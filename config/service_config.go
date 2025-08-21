package config

import (
	"fmt"
	"sort"
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

func (config *ServiceConfig) AllocBlock(height uint64, isWorker bool) NodeID {
	//height := block.Number()
	idLists := make([]NodeID, 0)
	if isWorker {
		for id, _ := range config.Network.Workers {
			idLists = append(idLists, id)
		}
	} else {
		for id, _ := range config.Network.Aggregators {
			idLists = append(idLists, id)
		}
	}
	sort.Slice(idLists, func(i, j int) bool {
		return idLists[i] < idLists[j]
	})
	return idLists[height%uint64(len(idLists))]

}

//// GrpcConfig all nodes have a same GrpcConfig
//type GrpcConfig struct {
//	MessageLimitSize int           `json:"message_limit_size"`
//	Timeout          time.Duration `json:"timeout"`
//}
