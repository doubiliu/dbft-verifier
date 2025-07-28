package service

import (
	"testing"
	"time"
)

func Test_rpc(t *testing.T) {
	xClient, err := NewNeoXClient("https://neoxt4seed1.ngd.network/")
	if err != nil {
		panic(err)
	}
	for i := 0; i < 10; i++ {
		blockHeader, err := xClient.GetCurrentBlockHeader()
		if err != nil {
			panic(err)
		}
		data, err := blockHeader.MarshalJSON()
		if err != nil {
			return
		}
		println(string(data))
		time.Sleep(5 * time.Second)
	}
	defer xClient.Close()
}
