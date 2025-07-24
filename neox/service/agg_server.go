package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/service/agg_task"
	"google.golang.org/grpc"
	"io/ioutil"
	"log"
	"net"
	"os"
)

type AggCalTaskService struct {
	agg_task.UnimplementedAggCalculateServiceServer
}

var _ agg_task.AggCalculateServiceServer = (*AggCalTaskService)(nil)

func (p *AggCalTaskService) AddAggCalculateTask(ctx context.Context, req *agg_task.AggRequest) (*agg_task.AggResponse, error) {
	height := req.Height
	proof := req.Proof
	resp := &agg_task.AggResponse{}
	resp.Value = "hello:" + height + "," + proof
	return resp, nil
}

func StartAggTaskService() {
	configPath := os.Args[1]
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Println("Config read error:", err)
		return
	}
	cfg := config.ServiceConfig{}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		panic(err)
	}
	grpcServer := grpc.NewServer()
	agg_task.RegisterAggCalculateServiceServer(grpcServer, new(AggCalTaskService))
	listen, err := net.Listen("tcp", ":"+cfg.Local.Port)
	if err != nil {
		log.Fatal("Listen TCP err:", err)
	}
	err = grpcServer.Serve(listen)
	if err != nil {
		log.Fatal(err)
	}
}
