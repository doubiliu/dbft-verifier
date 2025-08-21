package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/txhsl/neox-dbft-verifier/circuit"
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
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", ds.config.Local.DistributePort))
	if err != nil {
		return err
	}
	server := grpc.NewServer(grpc.MaxSendMsgSize(config.MESSAGE_LIMIT_SIZE), grpc.MaxRecvMsgSize(config.MESSAGE_LIMIT_SIZE))
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

func (dc *DistributeClient) DistributeBlock(block circuit.HashableBlockHeader, isNeox bool, isFirstBlock bool) error {
	header, err := block.MarshalJSON()
	if err != nil {
		return err
	}
	// 1. In Neox, each block is proved in a worker, each worker proves a rlp proof and a g2/noSig proof
	//    1.1 then the aggregator receives the rlp and g2/noSig proof, and it should have a parent rlp proof(for verify)
	// to get the witness assignment, it should have current block and parent block
	//    1.2 so a block should be sent to a certain worker and 2 aggregators
	//    1.3 Specially, the first block only need to be sent to the aggregator who aggregates the next block

	// 2. In N3, each block is proved in a single worker, and no aggregator
	//    2.1 to get the witness assignment, it should have current block and parent block
	//		  so a block should be sent to 2 workers
	send := func(ctx context.Context, server config.BaseURL, block circuit.HashableBlockHeader, isReliable bool) error {
		conn, err := grpc.NewClient(server.DistributeString(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return err
		}
		client := distribute.NewDistributeServiceClient(conn)
		request := &distribute.BlockDistributeRequest{Header: header, IsReliable: isReliable}
		response, err := client.SendBlock(ctx, request)
		if err != nil {
			return err
		}
		if !response.Success {
			return errors.New("send Block Failed, response not have a success")
		}
		fmt.Printf("Send Block %d to %s successfully\n", block.Height(), server.DistributeString())
		return conn.Close()
	}
	if isFirstBlock {
		// in neox, it should be sent to the aggregator who aggregates the next block
		// in n3, it's reliable and it should be sent to next block's prover
		if isNeox {
			aggID := dc.config.AllocBlock(block.Height()+1, false)
			server, ok := dc.config.Network.Aggregators[aggID]
			if !ok {
				return fmt.Errorf("aggregator %d not found", aggID)
			}
			ctx, cancel := context.WithTimeout(context.Background(), config.CONNECT_TIMEOUT)
			defer cancel()
			err = send(ctx, server, block, true)
			if err != nil {
				return err
			}
		} else {
			workerID := dc.config.AllocBlock(block.Height()+1, true)
			server, ok := dc.config.Network.Workers[workerID]
			if !ok {
				return fmt.Errorf("worker %d not found", workerID)
			}
			ctx, cancel := context.WithTimeout(context.Background(), config.CONNECT_TIMEOUT)
			defer cancel()
			err = send(ctx, server, block, true)
			if err != nil {
				return err
			}
		}
	} else {
		if isNeox {
			// in neox, the block should be sent to a certain worker and 2 aggregators
			workerID := dc.config.AllocBlock(block.Height(), true)
			workerServer, ok := dc.config.Network.Workers[workerID]
			if !ok {
				return fmt.Errorf("worker %d not found", workerID)
			}
			ctx, cancel := context.WithTimeout(context.Background(), config.CONNECT_TIMEOUT)
			defer cancel()
			err = send(ctx, workerServer, block, false)
			if err != nil {
				return err
			}
			aggregatorIDs := []config.NodeID{dc.config.AllocBlock(block.Height(), false), dc.config.AllocBlock(block.Height()+1, false)}
			// todo same aggID, in aggregator we ignore it, but it's no need to send
			for _, aggID := range aggregatorIDs {
				server, ok := dc.config.Network.Aggregators[aggID]
				if !ok {
					return fmt.Errorf("aggregator %d not found", aggID)
				}
				err = send(ctx, server, block, false)
				if err != nil {
					return err
				}
			}
		} else {
			// in n3, a block should be sent to 2 workers
			ctx, cancel := context.WithTimeout(context.Background(), config.CONNECT_TIMEOUT)
			defer cancel()
			workerIDs := []config.NodeID{dc.config.AllocBlock(block.Height(), true), dc.config.AllocBlock(block.Height()+1, true)}
			for i, workerID := range workerIDs {
				server, ok := dc.config.Network.Workers[workerID]
				if !ok {
					return fmt.Errorf("worker %d not found", workerID)
				}
				err = send(ctx, server, block, i == 1) // todo
				if err != nil {
					return err
				}
			}
		}
	}

	//distributeToWorker := func() error {
	//	nodeID := dc.config.AllocBlock(block.Number()+1, false)
	//	ctx, cancel := context.WithTimeout(context.Background(), config.CONNECT_TIMEOUT)
	//	defer cancel()
	//	server, ok := dc.config.Network.Workers[nodeID]
	//	if !ok {
	//		return fmt.Errorf("worker %d not found", nodeID)
	//	}
	//	conn, err := grpc.NewClient(server.DistributeString(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	//	if err != nil {
	//		return err
	//	}
	//	client := distribute.NewDistributeServiceClient(conn)
	//	request := &distribute.BlockDistributeRequest{Header: header, IsReliable: isFirstBlock}
	//	response, err := client.SendBlock(ctx, request)
	//	if err != nil {
	//		return err
	//	}
	//	if !response.Success {
	//		return errors.New("send Block Failed, response not have a success")
	//	}
	//	fmt.Printf("Send Block %d to worker %d successfully\n", block.Number(), nodeID)
	//	return conn.Close()
	//}
	//// aggregator should have the block header to compute public witness
	//// in n3 there is no aggregator, but all workers should get each block
	//distributeToAggregator := func() error {
	//	if len(dc.config.Network.Aggregators) == 0 {
	//		return nil
	//	}
	//	nodeID := dc.alloc(block, true)
	//	server := dc.config.Network.Aggregators[nodeID]
	//	conn, err := grpc.NewClient(server.DistributeString(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	//	if err != nil {
	//		return err
	//	}
	//	client := distribute.NewDistributeServiceClient(conn)
	//	request := &distribute.BlockDistributeRequest{Header: header, IsReliable: isFirstBlock}
	//	response, err := client.SendBlock(context.Background(), request)
	//	if err != nil {
	//		return err
	//	}
	//	if !response.Success {
	//		return errors.New("send Block Failed, response not have a success")
	//	}
	//	fmt.Printf("Send Block %d to aggregator successfully\n", block.Number())
	//	return conn.Close()
	//}
	//if err := distributeToWorker(); err != nil {
	//	return err
	//}
	//return distributeToAggregator()

	return nil

}

//func (dc *DistributeClient) alloc(block circuit.HashableBlockHeader) config.NodeID {
//	// todo
//	nbWorker := len(dc.config.Network.Workers)
//	nbAggregator := len(dc.config.Network.Aggregators)
//	return nbAggregator + config.NodeID(block.Number()%(uint64(nbWorker)))
//}
