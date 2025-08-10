package workflow

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/service"
	"math/big"
	"time"
)

// BlockManager gets the blocks and send block to inner Worker Node
type BlockManager struct {
	config   *config.ServiceConfig
	client   *ethclient.Client
	stopCh   chan struct{}
	feedback chan error
	service.DistributeClient
}

func NewBlockManager(cfg config.ServiceConfig) *BlockManager {
	return &BlockManager{
		config:           &cfg,
		stopCh:           make(chan struct{}, 1),
		feedback:         make(chan error, 1),
		client:           nil,
		DistributeClient: *service.NewDistributeClient(cfg),
	}
}
func (manager *BlockManager) Start() error {
	client, err := ethclient.Dial(manager.config.Network.BlockSource)
	if err != nil {
		return fmt.Errorf("failed to dial block source: %w", err)
	}
	manager.client = client
	// first, we should select a block as the start, and then send to aggregator to compute rlpHash proof
	ctx, cancel := context.WithTimeout(context.Background(), config.CONNECT_TIMEOUT)
	defer cancel()
	firstBlockNumber, err := manager.client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get block number: %w", err)
	}
	firstBlockHeader, err := manager.client.HeaderByNumber(ctx, big.NewInt(int64(firstBlockNumber)))
	if err != nil {
		return fmt.Errorf("failed to get first block header: %w", err)
	}
	time.Sleep(5 * time.Second) // todo
	go func() {
		for {
			err = manager.DistributeBlock(firstBlockHeader, true) // we simply send it to all nodes(workers and aggregator, workers will ignore it)
			if err != nil {
				manager.feedback <- err
			} else {
				break
			}
		}
	}()
	go func() {
		defer manager.client.Close()
		current := firstBlockNumber + 1
		for {
			select {
			case <-manager.stopCh:
				return
			default:
				for {
					err := manager.fetchBlock(current)
					if err == nil {
						current++
						time.Sleep(5 * time.Second) // todo
						break
					} else {
						fmt.Printf("Block %d fetched error: %v, retry again\n", current, err)
						time.Sleep(1 * time.Second) // todo
					}
				}
			}
		}
	}()

	return nil
}

func (manager *BlockManager) fetchBlock(blockNumber uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), config.CONNECT_TIMEOUT)
	defer cancel()

	header, err := manager.client.HeaderByNumber(ctx, big.NewInt(int64(blockNumber)))
	if err != nil {
		return err
	}
	return manager.DistributeBlock(header, false)

}
func (manager *BlockManager) Stop() {
	close(manager.stopCh)
}

func (manager *BlockManager) Feedback() chan error {
	return manager.feedback
}
