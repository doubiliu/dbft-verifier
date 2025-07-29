package service

import (
	"context"
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/txhsl/neox-dbft-verifier/circuit"
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

func (as *AggregateServer) StartAggregateServer() error {
	// 监听指定端口
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", as.config.Local.Port))
	if err != nil {
		return err
	}
	server := grpc.NewServer(grpc.MaxSendMsgSize(as.config.MessageLimitSize), grpc.MaxRecvMsgSize(as.config.MessageLimitSize))
	aggregate.RegisterAggregateServiceServer(server, as)

	return server.Serve(lis)
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

func (ac *AggregateClient) CommitProof(block *types.Header, proof groth16.Proof, ce circuit.CircuitEnum) error {
	conn, err := grpc.NewClient(ac.ServerURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), ac.config.Timeout)
	defer cancel()
	client := aggregate.NewAggregateServiceClient(conn)
	// we compute rlpHash here in avoid to modify the params
	edata, err := circuit.EncodeHeader(block, false)
	if err != nil {
		panic(err)
	}
	request := &aggregate.AggregateRequest{
		BlockHash: common.BytesToHash(crypto.Keccak256(edata)).Bytes(),
		Proof:     proof.(*groth16_bn254.Proof).MarshalSolidity(), // todo read
		Circuit:   int32(ce),
	}
	response, err := client.Commit(ctx, request)
	if err != nil {
		return err
	}
	if !response.Success {
		return errors.New("commit proof failed, verify not success")
	}
	return conn.Close()

}
