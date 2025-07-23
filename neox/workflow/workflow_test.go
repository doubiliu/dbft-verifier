package workflow

import (
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"testing"
	"time"
)

func TestSingleNode(t *testing.T) {
	connection := NewTempLocalConnection()
	config := NodeConfig{
		ce:       circuit.ToG2Hash,
		mode:     Pipeline,
		nbMaxCPU: -1, // max
		nbSolve:  1,
		nbProve:  1,
		ccsPath:  "/root/yzm/dbft-verifier/neox/circuit/to_g2_hash.ccs",
		pkPath:   "/root/yzm/dbft-verifier/neox/circuit/to_g2_hash.pk",
		vkPath:   "/root/yzm/dbft-verifier/neox/circuit/to_g2_hash.vk",
		rpcUrl:   "",
	}
	node := NewNode(config)
	node.SetTempConnection(connection)
	go node.Start()
	// we simulate the block request, 5s/blk
	for i := 0; i < 10; i++ {
		parent, current := circuit.HeaderTestData(circuit.ExtraV1)
		request := BlockRequest{
			blockHeaders: []types.Header{*parent, *current},
			ce:           circuit.ToG2Hash,
			extraVersion: circuit.ExtraV1,
		}
		connection.input <- &request
	}
	start := time.Now()
	for response := range connection.output {
		fmt.Println("Outside receive a response", response)
		fmt.Println("timestamp: ", time.Since(start))
	}

}
