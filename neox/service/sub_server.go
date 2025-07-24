package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/txhsl/neox-dbft-verifier/config"
	"github.com/txhsl/neox-dbft-verifier/service/sub_task"
	"google.golang.org/grpc"
	"io/ioutil"
	"log"
	"net"
	"os"
)

type SubCalTaskService struct {
	sub_task.UnimplementedSubCalculateServiceServer
}

var _ sub_task.SubCalculateServiceServer = (*SubCalTaskService)(nil)

func (p *SubCalTaskService) AddSubCalculateTask(ctx context.Context, req *sub_task.SubRequest) (*sub_task.SubResponse, error) {
	resp := &sub_task.SubResponse{}
	resp.Value = "hello:" + req.Headdata
	return resp, nil
}

func StartSubCalTaskService() {
	configPath := os.Args[1]
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Println("Config read error:", err)
		return
	}
	config := config.ServiceConfig{}
	err = json.Unmarshal(data, &config)
	if err != nil {
		panic(err)
	}
	grpcServer := grpc.NewServer()
	sub_task.RegisterSubCalculateServiceServer(grpcServer, new(SubCalTaskService))
	listen, err := net.Listen("tcp", ":"+config.Local.Port)
	if err != nil {
		log.Fatal("Listen TCP err:", err)
	}
	err = grpcServer.Serve(listen)
	if err != nil {
		log.Fatal(err)
	}
}
