package workflow

import (
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/plugin/pipeline"
	"github.com/txhsl/neox-dbft-verifier/service"
)

type Aggregator struct {
	config.NodeConfig
	config.ServiceConfig
	tasks chan Task
	service.AggregateServer
	feedback chan error
	tmp      chan pipeline.ProveResponse
}
