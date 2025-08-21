cd pb
protoc --go_out=. --go-grpc_out=. --proto_path=. distribute.proto
protoc --go_out=. --go-grpc_out=. --proto_path=. aggregate.proto