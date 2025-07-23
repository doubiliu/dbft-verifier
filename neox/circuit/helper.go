package circuit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
)

func encodeHeader(header *types.Header, noSig bool) ([]byte, error) {
	hashableExtraLen := len(header.Extra)
	if noSig {
		switch v := header.Extra[0]; v {
		case ExtraV0:
			hashableExtraLen = HashableExtraV0Len
		case ExtraV1, ExtraV2:
			hashableExtraLen = HashableExtraV1Len
		default:
			return nil, errors.New("unexpected extra version")
		}
	}

	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:hashableExtraLen], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if header.WithdrawalsHash != nil {
		enc = append(enc, header.WithdrawalsHash)
	}
	return rlp.EncodeToBytes(enc)
}
func rangeCheck(api frontend.API, x frontend.Variable, limits []frontend.Variable) {
	flag := frontend.Variable(0)
	for i := 0; i < len(limits); i++ {
		subValue := api.Sub(x, limits[i])
		f := api.IsZero(subValue)
		flag = api.Select(f, f, flag)
	}
	//check if x is in limits
	api.AssertIsEqual(flag, frontend.Variable(1))
}
func removeUnusedZeroBytes(in []byte) []byte {
	//remove 0x00 byte
	tin := make([]byte, 0)
	for i := 0; i < len(in); i++ {
		if in[i] != 0x00 {
			tin = in[i:]
			break
		}
	}
	in = tin
	return in
}

func intToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func BytesToIntVarible(api frontend.API, x []frontend.Variable) (frontend.Variable, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	xbytes := make([]uints.U8, len(x))
	for i := 0; i < len(x); i++ {
		xbytes[i] = uapi.ByteValueOf(x[i])
	}
	msb := uapi.PackMSB(xbytes...)
	value := uapi.ToValue(msb)
	return value, nil
}

func publicKeyToVariable(publicKey btcec.PublicKey) ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr] {
	var px fp.Element
	px.SetBigInt(publicKey.X())
	var py fp.Element
	py.SetBigInt(publicKey.Y())
	pub := secp256k1.G1Affine{
		X: px,
		Y: py,
	}

	return ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](pub.X),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](pub.Y),
	}
}

func ComputeRLPProof(field, outer *big.Int, ccs constraint.ConstraintSystem, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, header *types.Header, IsNoSig bool) (groth16.Proof, witness.Witness, error) {

	pheader, err := GetCompressedHeaderParameters(header)
	if err != nil {
		return nil, nil, err
	}
	data, err := encodeHeader(header, IsNoSig) // no sig
	if err != nil {
		return nil, nil, err
	}
	data = common.BytesToHash(crypto.Keccak256(data)).Bytes()
	r1 := new(big.Int).SetBytes(data[:16])
	r2 := new(big.Int).SetBytes(data[16:])
	fmt.Println("rlpInput-out-circuit:")
	fmt.Println(data)
	assignment := HeaderRLPEncodeVerifyWrapper{
		Header:  pheader,
		RlpHash: [2]frontend.Variable{r1, r2},
	}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	pubWitness, err := w.Public()
	if err != nil {
		return nil, nil, err
	}
	innerProof, err := groth16.Prove(ccs, *pk, w, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	err = groth16.Verify(innerProof, *vk, pubWitness, stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}

	return innerProof, pubWitness, nil
}

func ComputeToG2HashProof(field, outer *big.Int, ccs constraint.ConstraintSystem, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, header *types.Header) (groth16.Proof, witness.Witness, error) {
	cheader, err := GetCompressedHeaderParameters(header)
	if err != nil {
		return nil, nil, err
	}
	data, err := encodeHeader(header, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v\n", data)
	hash, err := bls12381.HashToG2(data, BLSDomain)
	if err != nil {
		panic(err)
	}
	g2HashBytes := hash.Bytes()
	toG2HashCompressed := [4]frontend.Variable{}
	for i := 0; i < 4; i++ {
		toG2HashCompressed[i] = new(big.Int).SetBytes(g2HashBytes[i*24 : (i+1)*24])
	}
	assignment := HeaderHashToG2VerifyWrapper{
		Header:   cheader,
		ToG2Hash: toG2HashCompressed,
	}
	w, err := frontend.NewWitness(&assignment, field)
	if err != nil {
		return nil, nil, err
	}
	innerPubWitness, err := w.Public()
	if err != nil {
		return nil, nil, err
	}
	innerProof, err := groth16.Prove(ccs, *pk, w, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	err = groth16.Verify(innerProof, *vk, innerPubWitness, stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		return nil, nil, err
	}
	return innerProof, innerPubWitness, nil
}
