package service

import (
	"context"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
)

type NeoXClient struct {
	client ethclient.Client
}

func NewNeoXClient(url string) (NeoXClient, error) {
	var nxClient NeoXClient
	client, err := ethclient.Dial(url)
	if err != nil {
		return NeoXClient{}, err
	}
	nxClient.client = *client
	return nxClient, nil
}

func (neoX *NeoXClient) GetCurrentBlockHeader() (*types.Header, error) {
	number, err := neoX.client.BlockNumber(context.Background())
	if err != nil {
		return nil, err
	}
	header, err := neoX.client.HeaderByNumber(context.Background(), big.NewInt(int64(number)))
	if err != nil {
		return nil, err
	}
	return header, nil
}

func (neoX *NeoXClient) Close() {
	neoX.client.Close()
}
