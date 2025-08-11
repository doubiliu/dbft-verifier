package main

//
//import (
//	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
//	"github.com/consensys/gnark/backend/plonk"
//	"github.com/consensys/gnark/backend/witness"
//	"github.com/consensys/gnark/constraint"
//	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
//	"github.com/ethereum/go-ethereum/core/types"
//	"github.com/txhsl/neox-dbft-verifier/circuit"
//	"github.com/txhsl/neox-dbft-verifier/helper"
//)
//
//func ProveVerifyUpdateHeader(parent *types.Header, current *types.Header, ccs constraint.ConstraintSystem, pk plonk.ProvingKey) (plonk.Proof, witness.Witness, error) {
//	pparent := circuit.GetHeaderParamter(parent)
//	pcurrent := circuit.GetHeaderParamter(current)
//	data, err := encodeSigHeader(current)
//	if err != nil {
//		panic(err)
//	}
//	hash, _ := bls12381.HashToG2(data, BLSDomain)
//	pubBytes := current.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
//	sigBytes := current.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]
//	var pubkey bls12381.G1Affine
//	_, err = pubkey.SetBytes(pubBytes)
//	if err != nil {
//		panic(err)
//	}
//	var sig bls12381.G2Affine
//	_, err = sig.SetBytes(sigBytes)
//
//	assignment := circuit.VerifyWrapper{
//		Parent:  pparent,
//		Current: pcurrent,
//		Pub:     sw_bls12381.NewG1Affine(pubkey),
//		Sig:     sw_bls12381.NewG2Affine(sig),
//		Hash:    sw_bls12381.NewG2Affine(hash),
//	}
//
//	proof, witness, err := helper.ComputeProof(ccs, pk, &assignment)
//	if err != nil {
//		return nil, nil, err
//	}
//	/*	var temp = ""
//		for k := 0; k < len(sumHash); k++ {
//			temp = temp + "\"" + strconv.Itoa(int(sumHash[k])) + "\"" + ","
//		}
//		fmt.Println("public input is", temp)*/
//	return proof, witness, nil
//}
//
//func GetVerifyUpdateHeaderCiricuit(typeHeader *types.Header) circuit.VerifyWrapper {
//	header := circuit.GetHeaderParamter(typeHeader)
//	data, err := encodeSigHeader(typeHeader)
//	if err != nil {
//		panic(err)
//	}
//	hash, _ := bls12381.HashToG2(data, BLSDomain)
//	pubBytes := typeHeader.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
//	sigBytes := typeHeader.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]
//	var pk bls12381.G1Affine
//	_, err = pk.SetBytes(pubBytes)
//	if err != nil {
//		panic(err)
//	}
//	var sig bls12381.G2Affine
//	_, err = sig.SetBytes(sigBytes)
//
//	c := circuit.VerifyWrapper{
//		Parent:  header,
//		Current: header,
//		Pub:     sw_bls12381.NewG1Affine(pk),
//		Sig:     sw_bls12381.NewG2Affine(sig),
//		Hash:    sw_bls12381.NewG2Affine(hash),
//	}
//	return c
//}
