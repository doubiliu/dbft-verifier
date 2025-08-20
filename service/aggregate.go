package service

import (
	"bytes"
	"context"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/pkg/errors"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	neox "github.com/txhsl/neox-dbft-verifier/circuit/neox"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/service/pb/aggregate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
)

// Aggregate Service impls the service that a InnerCircuitProverNode commits a proof of inner circuit to AggregateProverNode

type AggregateServer struct {
	config config.ServiceConfig
	aggregate.UnimplementedAggregateServiceServer
	output   chan *aggregate.AggregateRequest
	feedback chan error
}

func NewAggregateServer(config config.ServiceConfig, feedback chan error) *AggregateServer {
	return &AggregateServer{
		config:   config,
		output:   make(chan *aggregate.AggregateRequest, 100), // todo
		feedback: feedback,
	}
}
func (as *AggregateServer) StartAggregateServer(ctx context.Context) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", as.config.Local.AggregatorPort))
	if err != nil {
		return err
	}
	server := grpc.NewServer(grpc.MaxSendMsgSize(config.MESSAGE_LIMIT_SIZE), grpc.MaxRecvMsgSize(config.MESSAGE_LIMIT_SIZE))
	aggregate.RegisterAggregateServiceServer(server, as)
	go func() {
		<-ctx.Done()
		fmt.Println("Shutting down Aggregate Server...")
		server.Stop()
	}()
	return server.Serve(lis)
}

func (as *AggregateServer) AggregateChannel() chan *aggregate.AggregateRequest {
	return as.output
}
func (as *AggregateServer) Commit(ctx context.Context, request *aggregate.AggregateRequest) (*aggregate.AggregateResponse, error) {
	as.output <- request
	return &aggregate.AggregateResponse{
		Success: true,
	}, nil
}

type AggregateClient struct {
	config    config.ServiceConfig
	ServerURL string
}

func NewAggregateClient(config config.ServiceConfig) *AggregateClient {
	return &AggregateClient{
		config:    config,
		ServerURL: config.Local.AggregateString(),
	}
}

func (ac *AggregateClient) CommitProof(block *neox.NeoxBlockHeader, proof groth16.Proof, ce circuit.CircuitEnum) error {
	// we should choose an aggregator to commit our proof, notice that the first rlp proof is done by alloc()

	// Note: Important!!!
	// the rlpHash proof should be committed to 2 aggregators, as parent or current
	aggIDs := []config.NodeID{ac.config.AllocBlock(block.Height(), false)} // current
	if ce == circuit.RlpHash {
		// as parent!!!
		aggIDs = append(aggIDs, ac.config.AllocBlock(block.Height()+1, false))
	}
	ctx, cancel := context.WithTimeout(context.Background(), config.CONNECT_TIMEOUT)
	defer cancel()
	for _, aggregateID := range aggIDs {
		agg, ok := ac.config.Network.Aggregators[aggregateID]
		if !ok {
			return fmt.Errorf("unknown aggregator %s", aggregateID)
		}

		conn, err := grpc.NewClient(agg.AggregateString(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return err
		}
		client := aggregate.NewAggregateServiceClient(conn)
		// we compute rlpHash here in avoid to modify the params
		blockHash, err := block.Hash()
		if err != nil {
			return err
		}

		buf := bytes.NewBuffer([]byte{})
		_, err = proof.(*groth16_bn254.Proof).WriteTo(buf)
		if err != nil {
			return err
		}

		request := &aggregate.AggregateRequest{
			BlockHash: blockHash,
			Proof:     buf.Bytes(), // todo read
			Circuit:   int32(ce),
		}
		response, err := client.Commit(ctx, request)
		if err != nil {
			return err
		}
		if !response.Success {
			return errors.New("commit proof failed, verify not success")
		}
		if err = conn.Close(); err != nil {
			return nil
		}
	}
	return nil

}
