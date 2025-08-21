package helper

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/txhsl/neox-dbft-verifier/mpc"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
)

/**
 * Function: ComputeProof
 * @Description: a general zk proof calculation method
 * @param css: circuit constraints
 * @param pk: proving key
 * @param assignment: input data collection
 * @return proof: zk proof
 * @return witness: witness
 * @return err: error
 */
func ComputeGroth16Proof(css constraint.ConstraintSystem, pk groth16.ProvingKey, assignment frontend.Circuit) (groth16.Proof, witness.Witness, error) {
	// Compute witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	// Compute proof
	proof, err := groth16.Prove(css.(*cs.R1CS), pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return nil, nil, err
	}
	return proof, witness, nil
}

/**
 * Function: GetInitParamsFromExistedMPCSetUp
 * @Description: get proving key and verification key required for zk proof calculation from the existing MPC file
 * @param ccs: circuit constraints
 * @param srsPath: phase1 SRS file path required for proof calculation
 * @param phase2Path: phase2 file path required for proof calculation
 * @return pk: proving key
 * @return vk: verification key
 * @return err: error
 */
func GetInitParamsFromExistedMPCSetUp(ccs constraint.ConstraintSystem, srsPath string, phase2Path string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	// Get phase1 data
	srs, err := mpc.ReadSrsCommonsFromFile(srsPath)
	if err != nil {
		return nil, nil, err
	}
	// Get phase1.5 data
	r1cs := ccs.(*cs.R1CS)
	p2 := new(mpcsetup.Phase2)
	evals := p2.Initialize(r1cs, &srs)
	// Get phase2 data
	phase2, err := mpc.ReadPhase2FromFile(phase2Path)
	if err != nil {
		return nil, nil, err
	}
	// Generate proving and verifying keys
	fmt.Println("start get pk, vk")
	pk, vk := phase2.Seal(&srs, &evals, []byte("beacon Phase 2"))
	return pk, vk, nil
}

/**
 * Function: ReadProvingKey
 * @Description: import proving key file
 * @param path: proving key file path
 */
func ReadProvingKey(path string) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(ecc.BN254)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	_, err = pk.ReadFrom(file)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

/**
 * Function: ExportProvingKey
 * @Description: export proving key file
 * @param pk: proving key
 */
func ExportProvingKey(pk groth16.ProvingKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = pk.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Function: ReadVerifyingKey
 * @Description: import verifying key file
 * @param path: verifying key file path
 */
func ReadVerifyingKey(path string) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	_, err = vk.ReadFrom(file)
	if err != nil {
		return nil, err
	}
	return vk, nil
}

/**
 * Function: ExportVerifyingKey
 * @Description: export verifying key file
 * @param vk: verifying key
 */
func ExportVerifyingKey(vk groth16.VerifyingKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = vk.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
}

/**
 * Function: ReadCCS
 * @Description: import r1cs file
 * @param path: r1cs file path
 */
func ReadCCS(path string) (constraint.ConstraintSystem, error) {
	ccs := new(cs.R1CS)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	_, err = ccs.ReadFrom(file)
	if err != nil {
		return nil, err
	}
	return ccs, nil
}

/**
 * Function: ExportCCS
 * @Description: export r1cs file
 * @param css: r1cs
 */
func ExportCCS(ccs constraint.ConstraintSystem, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer file.Close()
	_, err = ccs.WriteTo(file)
	if err != nil {
		return fmt.Errorf("failed to write CCS to file %s: %w", path, err)
	}
	return nil
}

/**
 * Function: ExportContract
 * @Description: export solidity file
 * @param vk: verifying key
 */
func ExportGroth16Contract(vk groth16.VerifyingKey, path string) {
	contract, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	err = vk.ExportSolidity(contract, solidity.WithHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}
}

/**
 * Function: GetHash
 * @Description: get data hash
 * @param data: data
 * @return []byte: hash
 */
func GetHash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

/**
 * Function: GetContractInput
 * @Description: get the data submitted to the chain
 * @param proof: zk proof
 * @return []*big.Int: data submitted to the chain
 */
func GetGroth16ContractInput(proof groth16.Proof) ([8]*big.Int, []*big.Int, [2]*big.Int, error) {
	// Solidity contract inputs
	proofInBn254, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		return [8]*big.Int{}, []*big.Int{}, [2]*big.Int{}, fmt.Errorf("invalid proof type")
	}
	proofBytes := proofInBn254.MarshalSolidity()
	fpSize := 4 * 8
	var prf [8]*big.Int
	// proof.Ar, proof.Bs, proof.Krs
	for i := 0; i < 8; i++ {
		prf[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}
	c := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	cmtCount := int(c.Int64())
	var cmts = make([]*big.Int, 2*cmtCount)
	// commitments
	for i := 0; i < 2*cmtCount; i++ {
		cmts[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}
	var cmtPok [2]*big.Int
	// commitmentPok
	cmtPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*cmtCount*fpSize : fpSize*8+4+2*cmtCount*fpSize+fpSize])
	cmtPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*cmtCount*fpSize+fpSize : fpSize*8+4+2*cmtCount*fpSize+2*fpSize])
	return prf, cmts, cmtPok, nil
}

func TrustedLocalSetup(ct frontend.Circuit, assignment frontend.Circuit) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, ct)
	if err != nil {
		return nil, nil, nil, err
	}
	fmt.Println(ccs.GetNbConstraints())
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, err
	}
	err = ProveCircuit(ccs, pk, vk, assignment)
	if err != nil {
		return nil, nil, nil, err
	}
	return ccs, pk, vk, nil
}

func ProveCircuit(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, assignment frontend.Circuit) error {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	start := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return err
	}
	fmt.Println("Prove Time: ", time.Since(start))
	publicWitness, err := witness.Public()
	if err != nil {
		return err
	}
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	if err != nil {
		return err
	}
	proofData, cmts, cmtPok, err := GetGroth16ContractInput(proof)
	if err != nil {
		return err
	}
	// proof.Ar, proof.Bs, proof.Krs
	fmt.Printf("Proof:")
	for i := 0; i < 8; i++ {
		fmt.Printf(proofData[i].String())
	}
	fmt.Println()
	// commitments
	fmt.Printf("Commitments:")
	for i := 0; i < len(cmts); i++ {
		fmt.Printf(cmts[i].String())
	}
	fmt.Println()
	// commitmentPok
	fmt.Printf("CommitmentPok:")
	for i := 0; i < len(cmtPok); i++ {
		fmt.Printf(cmtPok[i].String())
	}
	return nil
}
