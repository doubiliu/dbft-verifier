package manager

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/circuit/n3"
	neox "github.com/txhsl/neox-dbft-verifier/circuit/neox"
	"math"
	"math/big"
)

type BlockFetcher interface {
	Connect(source string) error
	LatestBlockNumber(ctx context.Context) (uint64, error)
	FetchBlockByBlockNumber(ctx context.Context, blockNumber uint64) (circuit.HashableBlockHeader, error)
	Close()
}

type NeoxBlockFetcher struct {
	client *ethclient.Client
}

func (f *NeoxBlockFetcher) Connect(source string) error {
	client, err := ethclient.Dial(source)
	if err != nil {
		return fmt.Errorf("failed to dial block source: %w", err)
	}
	f.client = client
	return nil
}

func (f *NeoxBlockFetcher) LatestBlockNumber(ctx context.Context) (uint64, error) {
	return f.client.BlockNumber(ctx)
}

func (f *NeoxBlockFetcher) FetchBlockByBlockNumber(ctx context.Context, blockNumber uint64) (circuit.HashableBlockHeader, error) {
	header, err := f.client.HeaderByNumber(ctx, big.NewInt(int64(blockNumber)))
	if err != nil {
		return nil, err
	}
	return neox.NewNeoxBlockHeader(header), nil
}
func (f *NeoxBlockFetcher) Close() {
	f.client.Close()
}

type N3BlockFetcher struct {
	client *rpcclient.Client
}

func (f *N3BlockFetcher) Connect(source string) error {
	client, err := rpcclient.New(context.Background(), source, rpcclient.Options{}) // todo options?
	if err != nil {
		return err
	}
	err = client.Init()
	if err != nil {
		return err
	}
	f.client = client
	return nil
}

func (f *N3BlockFetcher) LatestBlockNumber(ctx context.Context) (uint64, error) {
	count, err := f.client.GetBlockCount()
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return math.MaxInt64, fmt.Errorf("no valid block")
	}
	return uint64(count - 1), nil
}

func (f *N3BlockFetcher) FetchBlockByBlockNumber(ctx context.Context, blockNumber uint64) (circuit.HashableBlockHeader, error) {
	hash, err := f.client.GetBlockHash(uint32(blockNumber) - 1)
	if err != nil {
		return nil, err
	}
	//println("Block hash:", hash.String())
	header, err := f.client.GetBlockHeader(hash)
	if err != nil {
		return nil, err
	}
	return n3.NewN3BlockHeader(header), nil

}

func (f *N3BlockFetcher) Close() {
	f.client.Close()
}
