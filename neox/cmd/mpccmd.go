package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/txhsl/neox-dbft-verifier/circuit"
	"github.com/txhsl/neox-dbft-verifier/helper"
	"github.com/txhsl/neox-dbft-verifier/mpc"
	"github.com/urfave/cli/v2"
	"math"
	"os"
)

var (
	// Flags for MPC
	domainFlag = &cli.IntFlag{
		Name:  "domain",
		Usage: "The power of FFT domain size of a phase1 srs file, N = 2^{domain}",
		Value: 27,
	}
	srsFileFlag = &cli.PathFlag{
		Name:  "srs",
		Usage: "The input file path of a phase1 SRS file",
	}
	inputFileFlag = &cli.PathFlag{
		Name:  "input",
		Usage: "The input file path of a MPC contribution",
	}
	outputFileFlag = &cli.PathFlag{
		Name:  "output",
		Usage: "The out file path of a MPC contribution",
	}
	// Flags for contract generation
	contractFileFlag = &cli.PathFlag{
		Name:  "contract",
		Usage: "The out file path of contract exportation",
		Value: "Verifier.sol",
	}
	provingKeyFileFlag = &cli.PathFlag{
		Name:  "pk",
		Usage: "The out file path of proving key",
		Value: "ProvingKey",
	}
	verifyingKeyFileFlag = &cli.PathFlag{
		Name:  "vk",
		Usage: "The out file path of verifying key",
		Value: "VerifyingKey",
	}
	ccsFileFlag = &cli.PathFlag{
		Name:  "ccs",
		Usage: "The out file path of r1cs",
		Value: "",
	}
	circuitFlag = &cli.StringFlag{
		Name:  "circuit",
		Usage: "The type of circuit, [rlp, noSig, g2]",
		Value: "rlp",
		Action: func(context *cli.Context, s string) error {
			validCircuitFlags := []string{"rlp", "noSig", "g2"}
			for _, v := range validCircuitFlags {
				if v == s {
					return nil
				}
			}
			return fmt.Errorf(fmt.Sprintf("Invalid validCircuitFlags %s, expected: {rlp, noSig, g2}", s))
		},
	}
	// todo
	inputVk1Flag = &cli.PathFlag{
		Name:  "vk1",
		Usage: "The path of vk1 for outer-circuit",
		Value: "",
	}
	inputVk2Flag = &cli.PathFlag{
		Name:  "vk2",
		Usage: "The path of vk2 for outer-circuit",
		Value: "",
	}
	inputCcs1Flag = &cli.PathFlag{
		Name:  "ccs1",
		Usage: "The path of ccs1 for outer-circuit",
		Value: "",
	}
	inputCcs2Flag = &cli.PathFlag{
		Name:  "ccs2",
		Usage: "The path of ccs2 for outer-circuit",
		Value: "",
	}
	extraVersionFlag = &cli.StringFlag{
		Name:  "extra",
		Usage: "The extra version",
		Value: "v1",
		Action: func(context *cli.Context, s string) error {
			validExtraVersionFlags := []string{"v0", "v1", "v2"}
			for _, v := range validExtraVersionFlags {
				if v == s {
					return nil
				}
			}
			return fmt.Errorf(fmt.Sprintf("Invalid ExtraVersionFlag %s, expected: {v0, v1, v2}", s))
		},
	}
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "compile", // we compile ccs first
				Usage: "Compile constraint systems into .ccs file",
				Description: `
			Compile commands deal the generation of r1cs constraint system files,
			should be performed before any ZK application deployed based on
			this algorithm, and later can be used by any phase1 which needs
			this MPC.`,
				Subcommands: []*cli.Command{
					{
						Name: "sub",
						Flags: []cli.Flag{
							extraVersionFlag,
						},
						Action:      compileSubCircuit,
						Description: "Compile Sub Circuits in current version into .ccs file, must be done before compile the verify circuit",
					},
				},
			},
			{
				Name:  "phase1",
				Usage: "Deal with MPC phase1",
				Description: `
Phase1 commands deal the generation of Groth16 setup parameters,
should be performed before any ZK application deployed based on
this algorithm, and later can be used by any phase2 which needs
this MPC.`,
				Subcommands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Generate the first phase1 file",
						Action: initPhase1,
						Flags: []cli.Flag{
							domainFlag,
							outputFileFlag,
						},
						Description: `
	phase1 init --output <filepath>

will generate a phase1 file without any input, should be used by
the first participant to generate the first file.`,
					},
					{
						Name:   "verify",
						Usage:  "Verify the phase1 file step forward",
						Action: verifyPhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 verify --phase1file <filepath> --output <filepath>

will verify the contribute operation that takes place on the input
file to the output file, should be used before any further contribution
to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the phase1 MPC",
						Action: contributePhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 contribute --phase1file <filepath> --output <filepath>

will generate a new phase1 file based on the input one, every
participant should do this only once and one by one, so that a
chain of this contribute operations realize a MPC.`,
					},
					{
						Name:   "seal",
						Usage:  "Convert Phase1 data to common SRS",
						Action: sealPhase1,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
	phase1 seal --phase1file <filepath> --output <filepath>

will convert Phase1 data to common srs,each participant can execute this operation locally to verify that the correct public SRS string is used`,
					},
				},
			},
			{
				Name:  "phase2",
				Usage: "Deal with MPC phase2",
				Description: `
			Phase2 commands deal the generation of circuit setup parameters,
			should be performed before every ZK application deployed based on
			phase1, and later can be used by this application repeatedly.`,
				Subcommands: []*cli.Command{
					{
						Name:  "init",
						Usage: "Generate the first phase2 file",
						Subcommands: []*cli.Command{
							{
								Name:   "inner",
								Action: initInnerCircuitPhase2,
								Flags: []cli.Flag{
									srsFileFlag,
									circuitFlag,
									outputFileFlag,
									ccsFileFlag,
									extraVersionFlag,
								},
								Description: `
				phase2 init --batch <size> --srsfile <filepath> --output <filepath>
			
			will generate a phase2 file with a phase1 input, should be used by
			the first participant to generate the first file. A parameter "batch"
			is required by circuit definition, which depends on the amount of
			input message, please refer
			https://github.com/bane-labs/zk-dkg/blob/v0.1.0/circuit/batch_encryption.go#L33`,
							},
							{
								Name:   "outer",
								Action: initOuterCircuitPhase2,
								Flags: []cli.Flag{
									srsFileFlag,
									outputFileFlag,
									ccsFileFlag,
									inputVk1Flag,
									inputVk2Flag,
									inputCcs1Flag,
									inputCcs2Flag,
									extraVersionFlag,
								},
							},
						},
					},
					{
						Name:   "verify",
						Usage:  "Verify the phase2 file step forward",
						Action: verifyPhase2,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
				phase2 verify --phase2file <filepath> --output <filepath>
			
			will verify the contribute operation that takes place on the input
			file to the output file, should be used before any further contribution
			to the unverified output file.`,
					},
					{
						Name:   "contribute",
						Usage:  "Contribute to the phase2 MPC",
						Action: contributePhase2,
						Flags: []cli.Flag{
							inputFileFlag,
							outputFileFlag,
						},
						Description: `
				phase2 contribute --phase2file <filepath> --output <filepath>
			
			will generate a new phase2 file based on the input one, every
			participant should do this only once and one by one, so that a
			chain of this contribute operations realize a MPC.`,
					},
				},
			},
			{
				Name:  "seal",
				Usage: "Export the proving key, verifying key and the verifier contract",
				Flags: []cli.Flag{
					srsFileFlag,
					inputFileFlag,
					provingKeyFileFlag,
					verifyingKeyFileFlag,
					ccsFileFlag, // is input, we have compiled in init
					circuitFlag,
					contractFileFlag,
				},
				Action: sealCircuit,
				Description: `
				seal --batch <size> --srsfile <filepath> --phase2file <filepath> --contract <filepath> --provingkey <filepath> --verifyingkey <filepath> --r1cs <filepath>
			
			will generate a proving key file, a verifying key file, and a
			Solidity verifier contract based on the input MPC phase1 and
			phase2 files, the same parameter "batch" used in "phase2 init"
			should also be provided, please refer
			https://github.com/bane-labs/zk-dkg/blob/v0.1.0/circuit/batch_encryption.go#L33.`,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(fmt.Errorf("error: %v", err.Error()))
		os.Exit(1)
	}
}

func getCircuitEnum(c string) (circuit.CircuitEnum, error) {
	switch c {
	case "rlp":
		return circuit.RlpHash, nil
	case "noSig":
		return circuit.NoSigRlp, nil
	case "g2":
		return circuit.ToG2Hash, nil
	default:
		return circuit.Invalid, fmt.Errorf("invalid c, expect: [rlp, noSig, g2]")
	}
}
func getExtraVersion(e string) (byte, error) {
	switch e {
	case "v0":
		return circuit.ExtraV0, nil
	case "v1":
		return circuit.ExtraV1, nil
	case "v2":
		return circuit.ExtraV2, nil
	default:
		return 0, errors.New("invalid extraVersion")
	}
}

func compileSubCircuit(ctx *cli.Context) error {
	extraVersion := ctx.String(extraVersionFlag.Name)
	v, err := getExtraVersion(extraVersion)
	if err != nil {
		return err
	}
	maxCircuitSize := 0
	// rlpHash
	rlpHashCircuit, err := circuit.GetSubCircuitWrapper(circuit.RlpHash, v)
	if err != nil {
		return err
	}
	rlpHashCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, rlpHashCircuit)
	if err != nil {
		return err
	}
	fmt.Printf("Compile RlpHash Circuit in extra version %s, NbContraints = %d\n", extraVersion, rlpHashCcs.GetNbConstraints())
	maxCircuitSize = max(maxCircuitSize, rlpHashCcs.GetNbConstraints())
	// g2 or noSig + verify
	if v == circuit.ExtraV0 {
		// noSig
		noSigRlpHashCircuit, err := circuit.GetSubCircuitWrapper(circuit.RlpHash, v)
		if err != nil {
			return err
		}
		noSigRlpHashCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, noSigRlpHashCircuit)
		if err != nil {
			return err
		}
		fmt.Printf("Compile NoSigRlpHash Circuit in extra version %s, NbConstraints = %d\n", extraVersion, noSigRlpHashCcs.GetNbConstraints())
		maxCircuitSize = max(maxCircuitSize, noSigRlpHashCcs.GetNbConstraints())
	} else {
		// g2hash
		g2HashCircuit, err := circuit.GetSubCircuitWrapper(circuit.ToG2Hash, v)
		if err != nil {
			return err
		}
		g2HashCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, g2HashCircuit)
		if err != nil {
			return err
		}
		fmt.Printf("Compile ToG2Hash Circuit in extra version %s, NbConstraints = %d\n", extraVersion, g2HashCcs.GetNbConstraints())
		maxCircuitSize = max(maxCircuitSize, g2HashCcs.GetNbConstraints())
	}
	fmt.Printf("Compile finished, max ccs size: %d\n", maxCircuitSize)
	fmt.Printf("Recommend Domain Size: %d\n", int(math.Ceil(math.Log2(float64(ecc.NextPowerOfTwo(uint64(maxCircuitSize)))))))
	return nil

}

func sealCircuit(ctx *cli.Context) error {
	srsFilePath := ctx.Path(srsFileFlag.Name)
	if srsFilePath == "" {
		return errors.New("invalid phase1 SRS file path")
	}
	phase2FilePath := ctx.Path(inputFileFlag.Name)
	if phase2FilePath == "" {
		return errors.New("invalid phase2 file path")
	}
	provingKeyFilePath := ctx.Path(provingKeyFileFlag.Name)
	if provingKeyFilePath == "" {
		return errors.New("invalid provingkey file path")
	}
	verifyingKeyFilePath := ctx.Path(verifyingKeyFileFlag.Name)
	if verifyingKeyFilePath == "" {
		return errors.New("invalid verifyingkey file path")
	}
	contractFilePath := ctx.Path(contractFileFlag.Name)
	//if contractFilePath == "" {
	//	return errors.New("invalid contract file path")
	//}
	r1csFilePath := ctx.Path(ccsFileFlag.Name)
	if r1csFilePath == "" {
		return errors.New("invalid r1cs file path")
	}
	ccs, err := helper.ReadCCS(r1csFilePath)
	if err != nil {
		return err
	}
	fmt.Println("read ccs")
	// Generate node private key
	pk, vk, err := helper.GetInitParamsFromExistedMPCSetUp(ccs, srsFilePath, phase2FilePath)
	if err != nil {
		return err
	}
	fmt.Println("finish pk, vk")
	err = helper.ExportProvingKey(pk, provingKeyFilePath)
	if err != nil {
		return err
	}
	err = helper.ExportVerifyingKey(vk, verifyingKeyFilePath)
	if err != nil {
		return err
	}
	if contractFilePath != "" {
		err = helper.ExportContract(vk, contractFilePath)
	}
	if err != nil {
		return err
	}
	return nil
}
func initInnerCircuitPhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(srsFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 SRS file path")
	}
	cf := ctx.String(circuitFlag.Name)
	ce, err := getCircuitEnum(cf)
	if err != nil {
		return err
	}
	extraVersion := ctx.String(extraVersionFlag.Name)
	v, err := getExtraVersion(extraVersion)
	if err != nil {
		return err
	}
	outputFileName := ctx.Path(outputFileFlag.Name)
	if outputFileName == "" {
		outputFileName = "init.phase2"
	}
	ccsPath := ctx.Path(ccsFileFlag.Name)
	if ccsPath == "" {
		return errors.New("invalid ccsFile path")
	}
	c, err := circuit.GetSubCircuitWrapper(ce, v)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return err
	}
	_, _, p, err := mpc.InitPhase2(ccs, inputPath, outputFileName, ccsPath)
	if err != nil {
		return err
	}
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func initOuterCircuitPhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(srsFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 SRS file path")
	}
	extraVersion := ctx.String(extraVersionFlag.Name)
	v, err := getExtraVersion(extraVersion)
	if err != nil {
		return err
	}
	outputFileName := ctx.Path(outputFileFlag.Name)
	if outputFileName == "" {
		outputFileName = "init.phase2"
	}
	ccsPath := ctx.Path(ccsFileFlag.Name)
	if ccsPath == "" {
		return errors.New("invalid ccsFile path")
	}
	readVkFromPath := func(p string) (groth16.VerifyingKey, error) {
		if p == "" {
			return nil, errors.New("invalid vk1 file path")
		}
		return helper.ReadVerifyingKey(p)
	}
	readCcsFromPath := func(p string) (constraint.ConstraintSystem, error) {
		if p == "" {
			return nil, errors.New("invalid ccs file path")
		}
		return helper.ReadCCS(p)
	}
	vk1, err := readVkFromPath(ctx.Path(inputVk1Flag.Name))
	if err != nil {
		return err
	}
	vk2, err := readVkFromPath(ctx.Path(inputVk2Flag.Name))
	if err != nil {
		return err
	}
	ccs1, err := readCcsFromPath(ctx.Path(inputCcs1Flag.Name))
	if err != nil {
		return err
	}
	ccs2, err := readCcsFromPath(ctx.Path(inputCcs2Flag.Name))
	if err != nil {
		return err
	}
	var c frontend.Circuit
	switch v {
	case circuit.ExtraV0:
		c, err = circuit.GetExtraV0VerifierCircuit(func() (*types.Header, *types.Header, error) {
			parent, current := circuit.HeaderTestData(circuit.ExtraV0)
			return parent, current, nil
		}, ccs1, ccs2, vk1, vk2)
	case circuit.ExtraV1, circuit.ExtraV2:
		c, err = circuit.GetExtraV1OrV2VerifierCircuit(v, func(extraVersion byte) (*types.Header, *types.Header, error) {
			parent, current := circuit.HeaderTestData(extraVersion)
			return parent, current, nil
		}, ccs1, ccs2, vk1, vk2)
	default:
		return errors.New("invalid extraVersion")
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return err
	}
	_, _, p, err := mpc.InitPhase2(ccs, inputPath, outputFileName, ccsPath)
	if err != nil {
		return err
	}
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func verifyPhase2(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("invalid phase2 file path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid output file path")
	}

	challenge, err := mpc.VerifyPhase2(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("Phase2 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

func contributePhase2(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase2 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid output file path")
	}
	p, err := mpc.ContributePhase2(inputPath, outputPath)
	if err != nil {
		return err
	}
	fmt.Println("Contributed to:", hex.EncodeToString(p.Challenge))
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func initPhase1(ctx *cli.Context) error {
	initPhase1FileName := ctx.Path(outputFileFlag.Name)
	if initPhase1FileName == "" {
		initPhase1FileName = "init.phase1"
	}
	domain := ctx.Int("domain")
	p, err := mpc.InitPhase1(initPhase1FileName, uint64(math.Pow(2, float64(domain))))
	if err != nil {
		return err
	}
	fmt.Printf("Phase1 SRS File initials successfully, fft domain size: 2^%d\n", domain)
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

// verifyPhase1 verify contribution of phase1
func verifyPhase1(ctx *cli.Context) error {
	path1 := ctx.Path(inputFileFlag.Name)
	if path1 == "" {
		return errors.New("invalid phase1 file path")
	}
	path2 := ctx.Path(outputFileFlag.Name)
	if path2 == "" {
		return errors.New("invalid output file path")
	}
	challenge, err := mpc.VerifyPhase1(path1, path2)
	if err != nil {
		return err
	}
	fmt.Println("Phase1 verified, and the previous challenge is", hex.EncodeToString(challenge))
	return nil
}

// contributePhase1 contribute to crs in phase1
func contributePhase1(ctx *cli.Context) error {
	inputName := ctx.Path(inputFileFlag.Name)
	if inputName == "" {
		return errors.New("invalid input file path")
	}
	outputName := ctx.Path(outputFileFlag.Name)
	if outputName == "" {
		return errors.New("invalid output file path")
	}
	p, err := mpc.ContributePhase1(inputName, outputName)
	if err != nil {
		return err
	}
	fmt.Println("Contributed to:", hex.EncodeToString(p.Challenge))
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	fmt.Println("File challenge:", hex.EncodeToString(sha.Sum(nil)))
	return nil
}

func sealPhase1(ctx *cli.Context) error {
	inputPath := ctx.Path(inputFileFlag.Name)
	if inputPath == "" {
		return errors.New("invalid phase1 file path")
	}
	outputPath := ctx.Path(outputFileFlag.Name)
	if outputPath == "" {
		return errors.New("invalid output file path")
	}
	_, err := mpc.Seal(inputPath, outputPath)
	if err != nil {
		return err
	}
	fmt.Println("Phase1 finished, seal file to ", outputPath)
	return nil
}
