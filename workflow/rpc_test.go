package workflow

import (
	"context"
	"testing"
)
import "github.com/nspcc-dev/neo-go/pkg/rpcclient"

func TestRPC(t *testing.T) {
	endpoint := "http://seed5t5.neo.org:20332"
	opts := rpcclient.Options{}
	client, err := rpcclient.New(context.Background(), endpoint, opts)
	if err != nil {
		panic(err)
	}
	err = client.Init()
	if err != nil {
		panic(err)
	}
	height, err := client.GetBlockCount()
	if err != nil {
		panic(err)
	}
	println("Block Count:", height)
	hash, err := client.GetBlockHash(height - 1)
	if err != nil {
		panic(err)
	}
	println("Block hash:", hash.String())
	header, err := client.GetBlockHeader(hash)
	if err != nil {
		panic(err)
	}
	println(header)
}
