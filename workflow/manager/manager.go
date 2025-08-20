package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/service"
	"os"
	"time"
)

// BlockManager gets the blocks and send block to inner Worker Node
// BlockManager can be run in both n3/neox
type BlockManager struct {
	blockFetcher BlockFetcher
	config       *config.ServiceConfig
	stopCh       chan struct{}
	feedback     chan error
	service.DistributeClient
	isNeox bool // if is neox, block is NeoxBlockHeader, else is N3BlockHeader
}

func (manager *BlockManager) Start() error {
	fmt.Println(manager.config)
	if manager.isNeox {
		manager.blockFetcher = new(NeoxBlockFetcher)
	} else {
		manager.blockFetcher = new(N3BlockFetcher)
	}
	err := manager.blockFetcher.Connect(manager.config.Network.BlockSource)
	if err != nil {
		return err
	}
	// first, we should select a block as the start, and then send to aggregator to compute rlpHash proof
	ctx, cancel := context.WithTimeout(context.Background(), config.CONNECT_TIMEOUT)
	defer cancel()
	firstBlockNumber, err := manager.blockFetcher.LatestBlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get block number: %w", err)
	}
	firstBlockHeader, err := manager.blockFetcher.FetchBlockByBlockNumber(ctx, firstBlockNumber)
	if err != nil {
		return fmt.Errorf("failed to get first block header: %w", err)
	}
	time.Sleep(5 * time.Second) // todo
	current := firstBlockNumber
	if manager.isNeox {
		err = manager.DistributeBlock(firstBlockHeader, true, true) // we simply send it to all nodes(workers and aggregator, workers will ignore it in neox)
		if err != nil {
			manager.feedback <- err
		}
		current++
		time.Sleep(5 * time.Second)
	}

	go func() {
		defer manager.Stop()
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

	header, err := manager.blockFetcher.FetchBlockByBlockNumber(ctx, blockNumber)
	if err != nil {
		return err
	}
	return manager.DistributeBlock(header, manager.isNeox, false)
}
func (manager *BlockManager) Stop() {
	close(manager.stopCh)
	manager.blockFetcher.Close()
}

func (manager *BlockManager) Feedback() chan error {
	return manager.feedback
}

func (manager *BlockManager) FromJson(jsonPath string) error {
	var serviceConfig config.ServiceConfig
	fileContent, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("load config error: %w", err)
	}
	if err := json.Unmarshal(fileContent, &serviceConfig); err != nil {
		return fmt.Errorf("load config error: %w", err)
	}
	manager.config = &serviceConfig
	manager.stopCh = make(chan struct{}, 1)
	manager.feedback = make(chan error, 1)
	manager.DistributeClient = *service.NewDistributeClient(*manager.config)
	return nil
}

func NewBlockManager(isNeox bool) *BlockManager {
	return &BlockManager{isNeox: isNeox}
}
