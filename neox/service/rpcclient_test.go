package service

import (
	"context"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
	"testing"
)

func Test_rpc(t *testing.T) {
	client, err := ethclient.Dial("https://neoxt4seed1.ngd.network/")
	if err != nil {
		t.Fatal(err)
	}
	number, err := client.BlockNumber(context.Background())
	if err != nil {
		panic(err)
	}
	println(number)
	header, err := client.HeaderByNumber(context.Background(), big.NewInt(int64(number)))
	if err != nil {
		panic(err)
	}
	data, err := header.MarshalJSON()
	if err != nil {
		return
	}
	println(string(data))
}
