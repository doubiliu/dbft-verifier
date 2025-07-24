package service

import (
	"context"
	"encoding/hex"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/service/agg_task"
	"google.golang.org/grpc"
	"strconv"
)

type AggClient struct {
	conn   *grpc.ClientConn
	client agg_task.AggCalculateServiceClient
}

func NewAggClient(cfg config.BaseServerInfo) (AggClient, error) {
	var agg AggClient
	conn, err := grpc.Dial(cfg.Address+":"+cfg.Port, grpc.WithInsecure())
	if err != nil {
		return AggClient{}, err
	}
	client := agg_task.NewAggCalculateServiceClient(conn)
	agg.conn = conn
	agg.client = client
	return agg, nil
}

func (agg *AggClient) Close() error {
	return agg.conn.Close()
}

func (agg *AggClient) AddAggCalculateTask(height int, proof []byte) (string, error) {
	req := &agg_task.AggRequest{Height: strconv.Itoa(height), Proof: hex.EncodeToString(proof)}
	rep, err := agg.client.AddAggCalculateTask(context.Background(), req)
	if err != nil {
		return "", err
	}
	return rep.Value, nil
}
