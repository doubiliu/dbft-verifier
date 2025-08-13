package main

//
//import (
//	"encoding/hex"
//	"fmt"
//	"github.com/consensys/gnark-crypto/ecc"
//	"github.com/consensys/gnark-crypto/kzg"
//	"github.com/consensys/gnark/backend/plonk"
//	"github.com/consensys/gnark/constraint"
//	cs "github.com/consensys/gnark/constraint/bn254"
//	"github.com/consensys/gnark/frontend"
//	"github.com/consensys/gnark/frontend/cs/scs"
//	"github.com/consensys/gnark/test"
//	"github.com/ethereum/go-ethereum/core/types"
//	"github.com/stretchr/testify/require"
//	"github.com/txhsl/neox-dbft-verifier/helper"
//	"os"
//	"strconv"
//	"testing"
//
//	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
//	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
//)
//
//func TestZkVerifyWithMPC(t *testing.T) {
//	assert := test.NewAssert(t)
//	rootDir := ""
//	parent := new(types.Header)
//	err := parent.UnmarshalJSON([]byte(
//		`{
//    "baseFeePerGas": "0x4a817c800",
//    "difficulty": "0x2",
//    "extraData": "0x0101072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76a5b5119bdcba3022c77f07b13bea98239781492b075fb8a1dff6895377dcd5251c3134660c973244d84101814ad14fa9a6605298b06a5c70c969ee5c1357236cbe9b7b65ee59f567e95d6a8fe0966175676170c0ecf174ef6ad701574d7b7d1a099068d29ac7662e20a2ae74898d19b93966d89314946745860d47c59c38208f83b50013414845cb5706840426f45b2c",
//    "gasLimit": "0x1c9c380",
//    "gasUsed": "0x0",
//    "hash": "0xecd8bd1c514fd33d9e01184783af6f2dd58f3a213b294fe8019aab5271140633",
//    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//    "miner": "0x1212000000000000000000000000000000000003",
//    "mixHash": "0xc1a8ea569ae7daff411094c088d4dd58cd439d241d9c31af61a537c6505761a5",
//    "nonce": "0x0000000000000005",
//    "number": "0x2970d9",
//    "parentHash": "0x59db04b079ab47dde8736b231469db4e4a1ca2c9fc8e251bf41cf3c336facefe",
//    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
//    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
//    "size": "0x2db",
//    "stateRoot": "0xf675a08553de3363c8abc70879a9cc6ca6c6be517ae21a7f6601835fb6181ff9",
//    "timestamp": "0x680b3b51",
//    "totalDifficulty": "0x5023a5",
//    "transactions": [],
//    "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
//    "uncles": [],
//    "withdrawals": [],
//    "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
//}`,
//	))
//	current := new(types.Header)
//	err = current.UnmarshalJSON([]byte(
//		`{
//    "baseFeePerGas": "0x4a817c800",
//    "difficulty": "0x2",
//    "extraData": "0x0101072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76a5b5119bdcba3022c77f07b13bea98239781492b075fb8a1dff6895377dcd5251c3134660c973244d84101814ad14fa9a2267aebbca32f4f307ffe32c1d387b78585335d413747522953d7eccdfdb54fec71d9c8d28ce456ce51fadbf3dd059a15c42c964250c71107c987966a23d49f086cadf981f812d8deab403047cd8b8438fc8ca79cb6ee9290b3780f80007838",
//    "gasLimit": "0x1c9c380",
//    "gasUsed": "0x0",
//    "hash": "0x72273a91d87952260ff37c86839d69d1e1b6d3bbfc6e00a55198950bbcf182dc",
//    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//    "miner": "0x1212000000000000000000000000000000000003",
//    "mixHash": "0xc1a8ea569ae7daff411094c088d4dd58cd439d241d9c31af61a537c6505761a5",
//    "nonce": "0x0000000000000006",
//    "number": "0x2970da",
//    "parentHash": "0xecd8bd1c514fd33d9e01184783af6f2dd58f3a213b294fe8019aab5271140633",
//    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
//    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
//    "size": "0x2db",
//    "stateRoot": "0xf675a08553de3363c8abc70879a9cc6ca6c6be517ae21a7f6601835fb6181ff9",
//    "timestamp": "0x680b3b56",
//    "totalDifficulty": "0x5023a7",
//    "transactions": [],
//    "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
//    "uncles": [],
//    "withdrawals": [],
//    "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
//}`,
//	))
//	SRSCFlag := false
//	var srsc kzg_bn254.SRS
//	// if pk/vk pairs has been generated, we don't need to load or generate srs/srsc
//	checkSRSC := func() {
//		srscPath := rootDir + "srs_2_canonical" // not kzg.mpcsetup, is kzg.srs(canonical), points on curve
//		if !SRSCFlag {
//			// if srsc has not been generated
//			if _, err := os.Stat(srscPath); err != nil {
//				circuit := GetVerifyUpdateHeaderCiricuit(parent)
//				ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
//				require.NoError(t, err)
//				srsMpcSsetupPath := rootDir + "srs_2"
//				if _, err = os.Stat(srsMpcSsetupPath); err != nil {
//					// if mpcsetup is not generated
//					err = mockSRCMPC("srs_", ccs, 2)
//					if err != nil {
//						require.NoError(t, err)
//					}
//				} else {
//					// load mpcsetup
//					file, err := os.Open(srsMpcSsetupPath)
//					require.NoError(t, err)
//					var srs kzg_bn254.MpcSetup
//					_, err = srs.ReadFrom(file)
//					require.NoError(t, err)
//					err = file.Close()
//					require.NoError(t, err)
//					err = SealSRSMpcSetup(srs, srscPath)
//					require.NoError(t, err)
//				}
//			}
//			SRSCFlag = true
//			file, err := os.Open(srscPath)
//			require.NoError(t, err)
//			_, err = srsc.ReadFrom(file)
//			require.NoError(t, err)
//			err = file.Close()
//			require.NoError(t, err)
//		}
//	}
//	ccsPath := "zk_verify_ccs"
//	pkPath := "zk_verify_pk"
//	vkPath := "zk_verify_vk"
//	if _, err := os.Stat(ccsPath); err != nil {
//		ciricuit := GetVerifyUpdateHeaderCiricuit(parent)
//		mockCcs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &ciricuit)
//		require.NoError(t, err)
//		checkSRSC()
//		_, _, err = mockSeal("zk_verify_", mockCcs, &srsc) // similarly, just input srsc
//		require.NoError(t, err)
//	}
//	ccs, err := helper.ReadCCS(ccsPath)
//	assert.NoError(err)
//	pk, err := helper.ReadPlonkProvingKey(pkPath, ecc.BN254)
//	assert.NoError(err)
//	vk, err := helper.ReadPlonkVerifyingKey(vkPath, ecc.BN254)
//	assert.NoError(err)
//	proof, witness, err := ProveVerifyUpdateHeader(parent, current, ccs, pk)
//	if err != nil {
//		return
//	}
//	assert.NoError(err)
//	err = plonk.Verify(proof, vk, witness)
//	assert.NoError(err)
//	output := helper.GetContractInput(proof)
//	fmt.Println("Plonk proof is", "0x"+hex.EncodeToString(output))
//}
//
//func mockSRCMPC(prefix string, ccs constraint.ConstraintSystem, nContributions int) error {
//	scs := ccs.(*cs.SparseR1CS)
//	srsSize, _ := plonk.SRSSize(scs)
//
//	p := kzg_bn254.InitializeSetup(srsSize)
//	for i := 0; i < nContributions; i++ {
//		if i > 0 {
//			in, err := os.Open(prefix + strconv.Itoa(i))
//			if err != nil {
//				return err
//			}
//			_, err = p.ReadFrom(in)
//			if err != nil {
//				return err
//			}
//			err = in.Close()
//			if err != nil {
//				return err
//			}
//		}
//		p.Contribute()
//		out, err := os.Create(prefix + strconv.Itoa(i+1))
//		if err != nil {
//			return err
//		}
//		_, err = p.WriteTo(out)
//		if err != nil {
//			return err
//		}
//		err = out.Close()
//		if err != nil {
//			return err
//		}
//	}
//	path := prefix + strconv.Itoa(nContributions) + "_canonical"
//	// here we get p (mpcsetup)
//	// since srsc = p.Seal() is too slow and can be reused
//	// so we export srsc
//	return SealSRSMpcSetup(p, path)
//
//}
//
//func SealSRSMpcSetup(p kzg_bn254.MpcSetup, path string) error {
//	srsc := p.Seal([]byte("beacon SRS")) // in gnark, this challenge is fixed (in verifier, e.g. plonk.Verify)
//	f, err := os.Create(path)
//	defer f.Close()
//	if err != nil {
//		return err
//	}
//	_, err = srsc.WriteTo(f)
//	if err != nil {
//		return err
//	}
//	// we export srsc (canonical), since the srsl(lagrange) cannot be reused, srsl = toLagrange(srsc[:lagrange]) should be performed in each circuit
//	return nil
//}
//
//func mockSeal(prefix string, ccs constraint.ConstraintSystem, srs kzg.SRS, innerVKID ...int) (pk plonk.ProvingKey, vk plonk.VerifyingKey, err error) {
//	suffix := ""
//	if len(innerVKID) != 0 {
//		suffix = fmt.Sprintf("_%d", innerVKID[0])
//	}
//	scs := ccs.(*cs.SparseR1CS)
//	_, lagrange := plonk.SRSSize(scs)
//	srsLagrange := &kzg_bn254.SRS{Vk: srs.(*kzg_bn254.SRS).Vk}
//	srsLagrange.Pk.G1, err = kzg_bn254.ToLagrangeG1(srs.(*kzg_bn254.SRS).Pk.G1[:lagrange])
//	if err != nil {
//		return nil, nil, err
//	}
//	p1, v1, err := plonk.Setup(ccs, srs, srsLagrange)
//	if err != nil {
//		return nil, nil, err
//	}
//	pk = p1.(*plonk_bn254.ProvingKey)
//	vk = v1.(*plonk_bn254.VerifyingKey)
//	err = helper.ExportPlonkProvingKey(pk, prefix+"pk"+suffix)
//	if err != nil {
//		return nil, nil, err
//	}
//	err = helper.ExportPlonkVerifyingKey(vk, prefix+"vk"+suffix)
//	if err != nil {
//		return nil, nil, err
//	}
//	err = helper.ExportCCS(ccs, prefix+"ccs"+suffix)
//	if err != nil {
//		return nil, nil, err
//	}
//	return pk, vk, nil
//}
