package n3

import (
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/service"
)

type HeaderVerifier struct {
	config.CommonConfig
	tasks chan Task
	service.DistributeServer
	service.AggregateClient
	feedback chan error
}
