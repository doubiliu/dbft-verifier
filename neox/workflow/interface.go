package workflow

import "github.com/txhsl/neox-dbft-verifier/config"

type VerifierNode interface {
	Start() error
	RuntimeJob() config.NodeJob
	RuntimeMode() config.NodeMode
	FromCommonConfig(config.CommonConfig, ...any) error
}
