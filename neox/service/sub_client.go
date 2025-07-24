package service

import (
	"context"
	"encoding/hex"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/service/sub_task"
	"google.golang.org/grpc"
)

type SubClient struct {
	conn   *grpc.ClientConn
	client sub_task.SubCalculateServiceClient
}

func NewSubClient(cfg config.BaseServerInfo) (SubClient, error) {
	var sub SubClient
	conn, err := grpc.Dial(cfg.Address+":"+cfg.Port, grpc.WithInsecure())
	if err != nil {
		return SubClient{}, err
	}
	client := sub_task.NewSubCalculateServiceClient(conn)
	sub.conn = conn
	sub.client = client
	return sub, nil
}

func (sub *SubClient) Close() error {
	return sub.conn.Close()
}

func (sub *SubClient) AddSubCalculateTask(headerData []byte) (string, error) {
	req := &sub_task.SubRequest{Headdata: hex.EncodeToString(headerData)}
	rep, err := sub.client.AddSubCalculateTask(context.Background(), req)
	if err != nil {
		return "", err
	}
	return rep.Value, nil
}
