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
	stopCh   chan struct{} // 用于发送停止信号的channel
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
	ticker := time.NewTicker(5 * time.Second)

	// 3. 启动一个后台 goroutine 来处理定时任务
	go func() {
		defer ticker.Stop()
		defer manager.client.Close()
		for {
			select {
			case <-manager.stopCh:
				return
			case <-ticker.C: // 定时器触发
				err := manager.fetchLatestBlock()
				if err != nil {
					manager.feedback <- err
				}
			}
		}
	}()

	return nil
}
func (manager *BlockManager) Feedback() chan error {
	return manager.feedback
}

func (manager *BlockManager) fetchLatestBlock() error {
	ctx, cancel := context.WithTimeout(context.Background(), manager.config.Timeout)
	defer cancel()

	number, err := manager.client.BlockNumber(ctx)
	if err != nil {
		return err
	}
	header, err := manager.client.HeaderByNumber(ctx, big.NewInt(int64(number)))
	if err != nil {
		return err
	}
	return manager.DistributeBlock(header)

}
func (manager *BlockManager) Stop() {
	close(manager.stopCh)
}
