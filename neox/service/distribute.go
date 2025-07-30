package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/service/pb/distribute"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
)

type DistributeServer struct {
	config config.ServiceConfig
	distribute.UnimplementedDistributeServiceServer
	output   chan *distribute.BlockDistributeRequest
	feedback chan error
}

func NewDistributeServer(config config.ServiceConfig, feedback chan error) *DistributeServer {
	return &DistributeServer{
		config:   config,
		output:   make(chan *distribute.BlockDistributeRequest, 100), // todo
		feedback: feedback,
	}
}

func (ds *DistributeServer) StartDistributeServer(ctx context.Context) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", ds.config.Local.Port))
	if err != nil {
		return err
	}
	server := grpc.NewServer(grpc.MaxSendMsgSize(ds.config.MessageLimitSize), grpc.MaxRecvMsgSize(ds.config.MessageLimitSize))
	distribute.RegisterDistributeServiceServer(server, ds)
	go func() {
		<-ctx.Done()
		fmt.Println("Shutting down Aggregate Server...")
		server.Stop()
	}()
	return server.Serve(lis)
}

func (ds *DistributeServer) SendBlock(ctx context.Context, req *distribute.BlockDistributeRequest) (*distribute.BlockDistributeResponse, error) {
	ds.output <- req
	return &distribute.BlockDistributeResponse{
		Success: true,
	}, nil
}

func (ds *DistributeServer) DistributeChannel() chan *distribute.BlockDistributeRequest {
	return ds.output
}

type DistributeClient struct {
	config config.ServiceConfig
}

func NewDistributeClient(config config.ServiceConfig) *DistributeClient {
	return &DistributeClient{
		config: config,
	}
}

func (dc *DistributeClient) DistributeBlock(block *types.Header, isFirstBlock bool) error {
	header, err := block.MarshalJSON()
	if err != nil {
		return err
	}
	distributeToWorker := func() error {
		nodeID := dc.alloc(block)
		ctx, cancel := context.WithTimeout(context.Background(), dc.config.Timeout)
		defer cancel()
		server, ok := dc.config.Network.Workers[nodeID]
		if !ok {
			return fmt.Errorf("worker %d not found", nodeID)
		}
		conn, err := grpc.NewClient(server.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return err
		}
		client := distribute.NewDistributeServiceClient(conn)
		request := &distribute.BlockDistributeRequest{Header: header, IsReliable: isFirstBlock}
		response, err := client.SendBlock(ctx, request)
		if err != nil {
			return err
		}
		if !response.Success {
			return errors.New("send Block Failed, response not have a success")
		}
		fmt.Printf("Send Block %d to worker %d successfully\n", block.Number.Uint64(), nodeID)
		return conn.Close()
	}
	// aggregator should have the block header to compute public witness
	distributeToAggregator := func() error {
		server := dc.config.Network.Aggregator
		serverUrl := fmt.Sprintf("%s:%d", server.Address, server.DistributePort)
		conn, err := grpc.NewClient(serverUrl, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return err
		}
		client := distribute.NewDistributeServiceClient(conn)
		request := &distribute.BlockDistributeRequest{Header: header, IsReliable: isFirstBlock}
		response, err := client.SendBlock(context.Background(), request)
		if err != nil {
			return err
		}
		if !response.Success {
			return errors.New("send Block Failed, response not have a success")
		}
		fmt.Printf("Send Block %d to aggregator successfully\n", block.Number.Uint64())
		return conn.Close()
	}
	if err := distributeToWorker(); err != nil {
		return err
	}
	return distributeToAggregator()

}

func (dc *DistributeClient) alloc(block *types.Header) config.NodeID {
	// todo
	if len(dc.config.Network.Workers) == 1 {
		return 0
	}
	return config.NodeID(block.Number.Uint64() % uint64(len(dc.config.Network.Workers)-1)) // not alloc to aggregator, we set nodeID(aggregator) = len(workers) - 1
}
