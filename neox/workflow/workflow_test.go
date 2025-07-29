package workflow

//func TestInnerProverNodeSerialRunning(t *testing.T) {
//	nodeConfig := config.NodeConfig{
//		Mode:     config.Serial,
//		NbMaxCPU: 64, // max
//		NbSolve:  -1,
//		NbProve:  -1,
//		RlpHashInstance: pipeline.NewInstanceConfig(
//			"/root/neo/dbft-verifier/neox/circuit/rlp_encode_hash_extra_v1_test.ccs",
//			"/root/neo/dbft-verifier/neox/circuit/rlp_encode_hash_extra_v1_test.pk",
//			"/root/neo/dbft-verifier/neox/circuit/rlp_encode_hash_extra_v1_test.vk",
//		),
//		ToG2HashInstance: pipeline.NewInstanceConfig(
//			"/root/neo/dbft-verifier/neox/circuit/to_g2_hash.ccs",
//			"/root/neo/dbft-verifier/neox/circuit/to_g2_hash.pk",
//			"/root/neo/dbft-verifier/neox/circuit/to_g2_hash.vk",
//		),
//		ExtraVersion: circuit.ExtraV1,
//	}
//	serviceConfig := config.ServiceConfig{
//		ID:      0,
//		Network: config.NetworkConfig{},
//		Local: config.BaseURL{
//			Address: "localhost",
//			Port:    1234,
//		},
//		GrpcConfig: config.GrpcConfig{
//			MessageLimitSize: 1024 * 1024 * 1024,
//			Timeout:          5 * time.Second,
//		},
//	}
//	node := NewNode(c)
//	err := node.Start()
//	if err != nil {
//		panic(err)
//	}
//	// we simulate the block request, 5s/blk
//	go func() {
//		_, current := circuit.HeaderTestData(circuit.ExtraV1)
//		mockDistributeClient := service.DistributeClient{}
//		header, err := current.MarshalJSON()
//		if err != nil {
//			panic(err)
//		}
//		request := BlockRequest{
//			blockHeader: header,
//			isInner:     true,
//		}
//		for i := 0; i < 2; i++ {
//			connection.input <- request
//			time.Sleep(time.Second * 5)
//		}
//	}()
//	count := 0
//	overallStart := time.Now()
//	start := time.Now()
//	for response := range connection.output {
//		res := response.(*pipeline.ProveResponse)
//		fmt.Println(fmt.Sprintf("Outside receive a %d response, time: %v", res.CircuitType, time.Since(start)))
//		start = time.Now()
//		count++
//		if count == 4 {
//			break
//		}
//	}
//	fmt.Println("Total time: ", time.Since(overallStart)) // 3min54 = 234s（112 core）, 4min52s(292s, 32core)， 4min(240s, 64core)
//
//}
//
//func TestInnerProverNodePipelineRunning(t *testing.T) {
//	connection := NewTempLocalConnection()
//	config := config2.NodeConfig{
//		mode:     config2.Pipeline,
//		nbMaxCPU: 64, // max
//		nbSolve:  2,
//		nbProve:  1,
//		rlpHashInstance: pipeline.NewInstanceConfig(
//			"/root/neo/dbft-verifier/neox/circuit/rlp_encode_hash_extra_v1_test.ccs",
//			"/root/neo/dbft-verifier/neox/circuit/rlp_encode_hash_extra_v1_test.pk",
//			"/root/neo/dbft-verifier/neox/circuit/rlp_encode_hash_extra_v1_test.vk",
//		),
//		toG2HashInstance: pipeline.NewInstanceConfig(
//			"/root/neo/dbft-verifier/neox/circuit/to_g2_hash.ccs",
//			"/root/neo/dbft-verifier/neox/circuit/to_g2_hash.pk",
//			"/root/neo/dbft-verifier/neox/circuit/to_g2_hash.vk",
//		),
//		extraVersion: circuit.ExtraV1,
//	}
//	node := NewNode(config)
//	node.SetTempConnection(connection)
//	err := node.Start()
//	if err != nil {
//		panic(err)
//	}
//	// we simulate the block request, 5s/blk
//	go func() {
//		_, current := circuit.HeaderTestData(circuit.ExtraV1)
//		header, err := current.MarshalJSON()
//		if err != nil {
//			panic(err)
//		}
//		request := BlockRequest{
//			blockHeader: header,
//			isInner:     true,
//		}
//		for i := 0; i < 2; i++ {
//			connection.input <- request
//			time.Sleep(time.Second * 5)
//		}
//	}()
//	count := 0
//	overallStart := time.Now()
//	start := time.Now()
//	for response := range connection.output {
//		res := response.(*pipeline.ProveResponse)
//		fmt.Println(fmt.Sprintf("Outside receive a %d response, time: %v", res.CircuitType, time.Since(start)))
//		start = time.Now()
//		count++
//		if count == 4 {
//			break
//		}
//	}
//	fmt.Println("Total time: ", time.Since(overallStart))
//	// 3min18s=198s // 2min42s = 162s (nbSolve=1, nbSolve=2, 112core)
//	// 3min59s=219s  // 3min50s = 210s (nbSolve=1, nbSolve=2, 32core)
//	// 3min25s=205s  // 2min56s = 176s (nbSolve=1, nbSolve=2, 64core)
//
//}
