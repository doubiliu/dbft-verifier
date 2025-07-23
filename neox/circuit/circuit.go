package circuit

import (
	"fmt"
	btc_ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
	"math/big"
	"slices"
)

type CircuitEnum = int

const (
	RlpHash CircuitEnum = iota
	NoSigRlp
	ToG2Hash
	Invalid
)

func GetSubCircuitWrapper(e CircuitEnum, extraVersion byte) (frontend.Circuit, error) {
	switch e {
	case RlpHash:
		circuit, _, err := new(HeaderRLPEncodeVerifyWrapper).Instance(extraVersion, false,
			func() (*types.Header, error) {
				header, _ := HeaderTestData(extraVersion)
				return header, nil
			})
		return circuit, err
	case NoSigRlp:
		circuit, _, err := new(HeaderRLPEncodeVerifyWrapper).Instance(extraVersion, true,
			func() (*types.Header, error) {
				header, _ := HeaderTestData(extraVersion)
				return header, nil
			})
		return circuit, err
	case ToG2Hash:
		circuit, _, err := new(HeaderHashToG2VerifyWrapper).Instance(
			func() (*types.Header, error) {
				header, _ := HeaderTestData(extraVersion) // v1 and v2 is same
				return header, nil
			})
		return circuit, err
		// todo Verify
	default:
		return nil, fmt.Errorf("unsupported circuit type: %v", e)
	}
}

// HeaderRLPEncodeVerifyWrapper is used in V0/V1/V2, generate a proof of rlpHash(header)
// we use header.NoSigHeader() to get a NoSigHeaderRLPEncodeVerifyWrapper which is used in V0, generates a proof of rlpHash(NoSigHeader)
// To reduce the number of public input, we use CompressHeadParameters instead of HeadParameters
type HeaderRLPEncodeVerifyWrapper struct {
	RlpHash      [2]frontend.Variable     `gnark:",public"` // we use 2 frontend.Variable to present a 256-variables rlp-hash
	Header       CompressHeaderParameters `gnark:",public"` // we do not reveal the whole header
	extraVersion byte
	isNoSig      bool
}

func (c *HeaderRLPEncodeVerifyWrapper) Define(api frontend.API) error {
	encode := NewHeaderEncoder(api)
	header := c.Header.Decompressed(api)
	var toEncodeHeader HeaderParameters
	var err error
	if c.isNoSig {
		toEncodeHeader, err = header.NoSigHeader()
		if err != nil {
			return err
		}
	} else {
		toEncodeHeader = header

	}
	rlpHash, err := encode.Encode(toEncodeHeader, c.extraVersion)
	api.Println(rlpHash)
	if err != nil {
		return err
	}
	// rlpHash = [r1 00] [r2 00]
	api.AssertIsEqual(len(rlpHash), 32)
	slices.Reverse(rlpHash)
	rlpBits := make([]frontend.Variable, 0)
	for _, r := range rlpHash {
		rlpBits = append(rlpBits, api.ToBinary(r, 8)...)
	}
	// r1 = [rlpBits[:128], 0000...00]
	r1 := make([]frontend.Variable, 254)
	r2 := make([]frontend.Variable, 254)
	for i := 0; i < 254; i++ {
		if i < 128 {
			r1[i] = rlpBits[i]
			r2[i] = rlpBits[128+i]
		} else {
			r1[i] = 0
			r2[i] = 0
		}
	}

	api.AssertIsEqual(c.RlpHash[1], api.FromBinary(r1...))
	api.AssertIsEqual(c.RlpHash[0], api.FromBinary(r2...))
	return nil
}
func (c *HeaderRLPEncodeVerifyWrapper) Instance(extraVersion byte, isNoSig bool, headerGenerator func() (*types.Header, error)) (frontend.Circuit, frontend.Circuit, error) {
	header, err := headerGenerator()
	if err != nil {
		return nil, nil, err
	}
	pheader, err := GetCompressedHeaderParameters(header)
	if err != nil {
		return nil, nil, err
	}
	data, err := encodeHeader(header, isNoSig)
	if err != nil {
		panic(err)
	}
	r1 := new(big.Int).SetBytes(data[:16])
	r2 := new(big.Int).SetBytes(data[16:])
	data = common.BytesToHash(crypto.Keccak256(data)).Bytes()
	return &HeaderRLPEncodeVerifyWrapper{
			Header:       pheader,
			RlpHash:      [2]frontend.Variable{0, 0},
			extraVersion: extraVersion,
			isNoSig:      isNoSig,
		}, &HeaderRLPEncodeVerifyWrapper{
			Header:       pheader,
			RlpHash:      [2]frontend.Variable{r1, r2},
			extraVersion: extraVersion,
			isNoSig:      isNoSig,
		}, nil
}

// HeaderHashToG2VerifyWrapper is used in V1/V2, generate a proof of HashToG2(NoSigHeader)
// This is only used for computing V1/V2 No-sig header's G2Hash
// To reduce the number of public input, we use CompressHeadParameters instead of HeadParameters
// We use 4 frontend.Variable to present a 96-byte(768-bit) G2Hash, each variable have 192-bit
type HeaderHashToG2VerifyWrapper struct {
	ToG2Hash [4]frontend.Variable     `gnark:",public"`
	Header   CompressHeaderParameters `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *HeaderHashToG2VerifyWrapper) Define(api frontend.API) error {
	header := c.Header.Decompressed(api)
	encode := NewHeaderEncoder(api)
	noSigHeader, err := header.NoSigHeader()
	if err != nil {
		return err
	}
	toG2Hash := encode.HashToG2(api, noSigHeader)
	/*	api.Println(toG2Hash)
		api.Println(ToG2Hash)*/
	// toG2Hash is 96-byte
	slices.Reverse(toG2Hash)
	toG2HashBits := make([]frontend.Variable, 0)
	for _, g := range toG2Hash {
		toG2HashBits = append(toG2HashBits, api.ToBinary(g, 8)...)
	}
	r := make([]frontend.Variable, 4)
	for i := 0; i < 4; i++ {
		r[3-i] = api.FromBinary(toG2HashBits[192*i : (i+1)*192]...)
	}
	for i := 0; i < len(c.ToG2Hash); i++ {
		api.AssertIsEqual(c.ToG2Hash[i], r[i])
	}
	return nil
}

func (c *HeaderHashToG2VerifyWrapper) Instance(headerGenerator func() (*types.Header, error)) (frontend.Circuit, frontend.Circuit, error) {
	header, err := headerGenerator()
	if err != nil {
		return nil, nil, err
	}
	cheader, err := GetCompressedHeaderParameters(header)
	if err != nil {
		return nil, nil, err
	}
	data, err := encodeHeader(header, true)
	if err != nil {
		return nil, nil, err
	}
	hash, err := bls12381.HashToG2(data, BLSDomain)
	if err != nil {
		return nil, nil, err
	}
	g2HashBytes := hash.Bytes()
	toG2HashCompressed := [4]frontend.Variable{}
	for i := 0; i < 4; i++ {
		toG2HashCompressed[i] = new(big.Int).SetBytes(g2HashBytes[i*24 : (i+1)*24])
	}
	return &HeaderHashToG2VerifyWrapper{
			Header:   cheader,
			ToG2Hash: [4]frontend.Variable{0, 0, 0, 0},
		}, &HeaderHashToG2VerifyWrapper{
			Header:   cheader,
			ToG2Hash: toG2HashCompressed,
		}, nil
}

// ExtraV0HeaderVerifyWrapper is used in v0
// verify rlpHash(parent), rlpHash(current), noSigHash(current)
// and prove the ecdsa signature
type ExtraV0HeaderVerifyWrapper[ECDSAFp, ECDSAFr emulated.FieldParams, FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Parent         HeaderParameters
	Current        HeaderParameters
	RLPHashProof1  stdgroth16.Proof[G1El, G2El]              `gnark:",secret"`
	RLPHashProof2  stdgroth16.Proof[G1El, G2El]              `gnark:",secret"`
	RLPHashVk      stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	NoSigHashProof stdgroth16.Proof[G1El, G2El]              `gnark:",secret"`
	NoSigHashVk    stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	NoSigHash      [32]frontend.Variable                     `gnark:",secret"`
	ParentHash     [32]frontend.Variable                     `gnark:",public"`
	CurrentHash    [32]frontend.Variable                     `gnark:",public"`
	MixDigest      [32]frontend.Variable                     `gnark:",public"`
	PublicKeys     []ecdsa.PublicKey[ECDSAFp, ECDSAFr]
	AddressIndices []frontend.Variable
}

func (c *ExtraV0HeaderVerifyWrapper[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier := NewHeaderVerifier[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl](api)
	return verifier.VerifyV0(c.Parent, c.Current, c.ParentHash[:], c.CurrentHash[:], c.MixDigest[:], c.RLPHashProof1, c.RLPHashProof2, c.RLPHashVk, c.NoSigHashProof, c.NoSigHashVk, c.NoSigHash[:], c.PublicKeys, c.AddressIndices)
}

func GetExtraV0VerifierCircuit(headerGenerator func() (*types.Header, *types.Header, error), rlpHashCcs, noSigRlpHashCcs constraint.ConstraintSystem) (frontend.Circuit, error) {
	parent, current, err := headerGenerator()
	if err != nil {
		return nil, err
	}
	parentParameters, err := GetHeaderParamter(parent)
	if err != nil {
		return nil, err
	}
	currentParameters, err := GetHeaderParamter(current)
	if err != nil {
		return nil, err
	}
	// we need to recover address and public keys
	addrBytes := current.Extra[HashableExtraV0Len : HashableExtraV0Len+7*common.AddressLength]
	sigBytes := current.Extra[HashableExtraV0Len+7*common.AddressLength:]
	addrs := make([]common.Address, 7)
	for i := range addrs {
		copy(addrs[i][:], addrBytes[i*common.AddressLength:(i+1)*common.AddressLength])
	}
	sigs := make([][]byte, 5)
	for i := range sigs {
		sigs[i] = sigBytes[i*crypto.SignatureLength : (i+1)*crypto.SignatureLength]
	}

	data, err := encodeHeader(current, true)
	if err != nil {
		return nil, err
	}
	fmt.Println("sigHeader RLP: ", data)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	fmt.Println("signature message hash: ", hash)
	noSigHashVar := make([]frontend.Variable, 0)
	for i := 0; i < len(hash); i++ {
		noSigHashVar = append(noSigHashVar, hash[i])
	}
	// recover pk from sig
	signers := make([]common.Address, len(sigs))
	addressIndices := make([]int, len(sigs))
	publicKeys := make([]ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(sigs))
	for i := range signers {
		btcsig := make([]byte, crypto.SignatureLength)
		btcsig[0] = sigs[i][64] + 27
		copy(btcsig[1:], sigs[i])
		pub, _, err := btc_ecdsa.RecoverCompact(btcsig, hash)
		if err != nil {
			return nil, err
		}
		publicKeys[i] = publicKeyToVariable(*pub)
		pubBytes := pub.SerializeUncompressed()
		signers[i] = common.BytesToAddress(crypto.Keccak256(pubBytes[1:])[12:])
		flag := false
		for j := range addrs {
			if signers[i].Cmp(addrs[j]) == 0 {
				addressIndices[i] = j
				flag = true
			}
		}
		if !flag {
			return nil, fmt.Errorf("invalid signature")
		}
	}
	indexVariables := make([]frontend.Variable, len(addressIndices))
	for i := 0; i < len(indexVariables); i++ {
		indexVariables[i] = addressIndices[i]
	}
	pdata, err := encodeHeader(parent, false)
	if err != nil {
		panic(err)
	}
	pdata = common.BytesToHash(crypto.Keccak256(pdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var ParentHash [32]frontend.Variable
	for i := 0; i < len(ParentHash); i++ {
		ParentHash[i] = pdata[i]
	}
	cdata, err := encodeHeader(current, false)
	if err != nil {
		panic(err)
	}
	cdata = common.BytesToHash(crypto.Keccak256(cdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var CurrentHash [32]frontend.Variable
	for i := 0; i < len(CurrentHash); i++ {
		CurrentHash[i] = cdata[i]
	}
	var MixDigest [32]frontend.Variable
	for i := 0; i < len(MixDigest); i++ {
		MixDigest[i] = current.MixDigest[i]
	}
	circuit := ExtraV0HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:         parentParameters,
		Current:        currentParameters,
		RLPHashProof1:  stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashCcs),
		RLPHashProof2:  stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashCcs),
		RLPHashVk:      stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashCcs),
		NoSigHashProof: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](noSigRlpHashCcs),
		NoSigHashVk:    stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](noSigRlpHashCcs),
		PublicKeys:     publicKeys,
		AddressIndices: indexVariables,
	}
	return &circuit, nil
}

func GetExtraV0VerifierAssignment(headerGenerator func() (*types.Header, *types.Header, error),
	rlpHashCcs, noSigRlpHashCcs constraint.ConstraintSystem,
	rlpHashPk, noSigRlpHashPk groth16.ProvingKey,
	rlpHashVk, noSigRlpHashVk groth16.VerifyingKey) (frontend.Circuit, error) {
	parent, current, err := headerGenerator()
	if err != nil {
		return nil, err
	}
	parentParameters, err := GetHeaderParamter(parent)
	if err != nil {
		return nil, err
	}
	currentParameters, err := GetHeaderParamter(current)
	if err != nil {
		return nil, err
	}
	// we need to recover address and public keys
	addrBytes := current.Extra[HashableExtraV0Len : HashableExtraV0Len+7*common.AddressLength]
	sigBytes := current.Extra[HashableExtraV0Len+7*common.AddressLength:]
	addrs := make([]common.Address, 7)
	for i := range addrs {
		copy(addrs[i][:], addrBytes[i*common.AddressLength:(i+1)*common.AddressLength])
	}
	sigs := make([][]byte, 5)
	for i := range sigs {
		sigs[i] = sigBytes[i*crypto.SignatureLength : (i+1)*crypto.SignatureLength]
	}

	data, err := encodeHeader(current, true)
	if err != nil {
		return nil, err
	}
	fmt.Println("sigHeader RLP: ", data)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	fmt.Println("signature message hash: ", hash)
	noSigHashVar := make([]frontend.Variable, 0)
	for i := 0; i < len(hash); i++ {
		noSigHashVar = append(noSigHashVar, hash[i])
	}
	// recover pk from sig
	signers := make([]common.Address, len(sigs))
	addressIndices := make([]int, len(sigs))
	publicKeys := make([]ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(sigs))
	for i := range signers {
		btcsig := make([]byte, crypto.SignatureLength)
		btcsig[0] = sigs[i][64] + 27
		copy(btcsig[1:], sigs[i])
		pub, _, err := btc_ecdsa.RecoverCompact(btcsig, hash)
		if err != nil {
			return nil, err
		}
		publicKeys[i] = publicKeyToVariable(*pub)
		pubBytes := pub.SerializeUncompressed()
		signers[i] = common.BytesToAddress(crypto.Keccak256(pubBytes[1:])[12:])
		flag := false
		for j := range addrs {
			if signers[i].Cmp(addrs[j]) == 0 {
				addressIndices[i] = j
				flag = true
			}
		}
		if !flag {
			return nil, fmt.Errorf("invalid signature")
		}
	}
	indexVariables := make([]frontend.Variable, len(addressIndices))
	for i := 0; i < len(indexVariables); i++ {
		indexVariables[i] = addressIndices[i]
	}
	pdata, err := encodeHeader(parent, false)
	if err != nil {
		panic(err)
	}
	pdata = common.BytesToHash(crypto.Keccak256(pdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var ParentHash [32]frontend.Variable
	for i := 0; i < len(ParentHash); i++ {
		ParentHash[i] = pdata[i]
	}
	cdata, err := encodeHeader(current, false)
	if err != nil {
		panic(err)
	}
	cdata = common.BytesToHash(crypto.Keccak256(cdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var CurrentHash [32]frontend.Variable
	for i := 0; i < len(CurrentHash); i++ {
		CurrentHash[i] = cdata[i]
	}
	var MixDigest [32]frontend.Variable
	for i := 0; i < len(MixDigest); i++ {
		MixDigest[i] = current.MixDigest[i]
	}
	rlpHashVerifyProof1, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashCcs, &rlpHashPk, &rlpHashVk, parent, false)
	if err != nil {
		return nil, err
	}
	rlpProof1, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyProof1)
	if err != nil {
		return nil, err
	}
	rlpHashVerifyProof2, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashCcs, &rlpHashPk, &rlpHashVk, current, false)
	if err != nil {
		return nil, err
	}
	rlpProof2, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyProof2)
	if err != nil {
		return nil, err
	}
	noSigHashProof, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), noSigRlpHashCcs, &noSigRlpHashPk, &noSigRlpHashVk, current, true)
	if err != nil {
		return nil, err
	}
	noSigProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](noSigHashProof)
	if err != nil {
		return nil, err
	}
	rlpKey, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashVk)
	if err != nil {
		return nil, err
	}
	noSigKey, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashVk)
	if err != nil {
		return nil, err
	}
	return &ExtraV0HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:         parentParameters,
		Current:        currentParameters,
		RLPHashProof1:  rlpProof1,
		RLPHashProof2:  rlpProof2,
		RLPHashVk:      rlpKey,
		NoSigHashProof: noSigProof,
		NoSigHashVk:    noSigKey,
		NoSigHash:      [32]frontend.Variable(noSigHashVar),
		PublicKeys:     publicKeys,
		AddressIndices: indexVariables,
		ParentHash:     ParentHash,
		CurrentHash:    CurrentHash,
		MixDigest:      MixDigest,
	}, nil
}

type ExtraV1OrV2HeaderVerifyWrapper[ECDSAFp, ECDSAFr emulated.FieldParams, FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Parent        HeaderParameters
	Current       HeaderParameters
	RLPHashProof1 stdgroth16.Proof[G1El, G2El]              `gnark:",secret"`
	RLPHashProof2 stdgroth16.Proof[G1El, G2El]              `gnark:",secret"`
	RLPHashVk     stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	ToG2HashProof stdgroth16.Proof[G1El, G2El]              `gnark:",secret"`
	ToG2HashVk    stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	ToG2Hash      [96]frontend.Variable                     `gnark:",secret"`
	ParentHash    [32]frontend.Variable                     `gnark:",public"`
	CurrentHash   [32]frontend.Variable                     `gnark:",public"`
	MixDigest     [32]frontend.Variable                     `gnark:",public"`
}

func (c *ExtraV1OrV2HeaderVerifyWrapper[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifer := NewHeaderVerifier[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl](api)
	return verifer.VerifyV1OrV2(c.Current, c.Parent, c.ParentHash[:], c.CurrentHash[:], c.MixDigest[:], c.RLPHashProof1, c.RLPHashProof2, c.RLPHashVk, c.ToG2HashProof, c.ToG2HashVk, c.ToG2Hash[:])
}

func GetExtraV1OrV2VerifierCircuit(extraVersion byte,
	headerGenerator func(extraVersion byte) (*types.Header, *types.Header, error),
	rlpHashCcs, toG2HashCcs constraint.ConstraintSystem,
	rlpHashVk, toG2HashVk groth16.VerifyingKey,
) (frontend.Circuit, error) {
	parent, current, err := headerGenerator(extraVersion)
	if err != nil {
		return nil, err
	}
	pparent, err := GetHeaderParamter(parent)
	if err != nil {
		return nil, err
	}
	pcurrent, err := GetHeaderParamter(current)
	if err != nil {
		return nil, err
	}
	pubBytes := current.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
	sigBytes := current.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]
	var pub bls12381.G1Affine
	_, err = pub.SetBytes(pubBytes)
	if err != nil {
		panic(err)
	}
	_, _, g1, _ := bls12381.Generators()
	g1.Neg(&g1)
	var sig bls12381.G2Affine
	_, err = sig.SetBytes(sigBytes)
	data, err := encodeHeader(current, true)
	if err != nil {
		panic(err)
	}
	hash, _ := bls12381.HashToG2(data, BLSDomain)
	hashBytes := hash.Bytes()
	var ToG2Hash [96]frontend.Variable
	for i := 0; i < len(ToG2Hash); i++ {
		ToG2Hash[i] = hashBytes[i]
	}
	pdata, err := encodeHeader(parent, false)
	if err != nil {
		panic(err)
	}
	pdata = common.BytesToHash(crypto.Keccak256(pdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var ParentHash [32]frontend.Variable
	for i := 0; i < len(ParentHash); i++ {
		ParentHash[i] = pdata[i]
	}
	cdata, err := encodeHeader(current, false)
	if err != nil {
		panic(err)
	}
	cdata = common.BytesToHash(crypto.Keccak256(cdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var CurrentHash [32]frontend.Variable
	for i := 0; i < len(CurrentHash); i++ {
		CurrentHash[i] = cdata[i]
	}
	var MixDigest [32]frontend.Variable
	for i := 0; i < len(MixDigest); i++ {
		MixDigest[i] = current.MixDigest[i]
	}
	rlpKey, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashVk)
	if err != nil {
		return nil, err
	}
	g2Key, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](toG2HashVk)
	if err != nil {
		return nil, err
	}
	return &ExtraV1OrV2HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:        pparent,
		Current:       pcurrent,
		RLPHashVk:     rlpKey,
		RLPHashProof1: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashCcs),
		RLPHashProof2: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashCcs),
		ToG2HashVk:    g2Key,
		ToG2HashProof: stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](toG2HashCcs),
		ParentHash:    ParentHash,
		CurrentHash:   CurrentHash,
		MixDigest:     MixDigest,
		ToG2Hash:      ToG2Hash,
	}, nil
}
func GetExtraV1OrV2VerifierAssignment(extraVersion byte,
	headerGenerator func(extraVersion byte) (*types.Header, *types.Header, error),
	rlpHashCcs, toG2HashCcs constraint.ConstraintSystem,
	rlpHashPk, toG2HashPk groth16.ProvingKey,
	rlpHashVk, toG2HashVk groth16.VerifyingKey) (frontend.Circuit, error) {
	parent, current, err := headerGenerator(extraVersion)
	if err != nil {
		return nil, err
	}
	pparent, err := GetHeaderParamter(parent)
	if err != nil {
		return nil, err
	}
	pcurrent, err := GetHeaderParamter(current)
	if err != nil {
		return nil, err
	}
	pubBytes := current.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
	sigBytes := current.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]
	var pub bls12381.G1Affine
	_, err = pub.SetBytes(pubBytes)
	if err != nil {
		panic(err)
	}
	_, _, g1, _ := bls12381.Generators()
	g1.Neg(&g1)
	var sig bls12381.G2Affine
	_, err = sig.SetBytes(sigBytes)
	data, err := encodeHeader(current, true)
	if err != nil {
		panic(err)
	}
	hash, _ := bls12381.HashToG2(data, BLSDomain)
	hashBytes := hash.Bytes()
	var ToG2Hash [96]frontend.Variable
	for i := 0; i < len(ToG2Hash); i++ {
		ToG2Hash[i] = hashBytes[i]
	}
	pdata, err := encodeHeader(parent, false)
	if err != nil {
		panic(err)
	}
	pdata = common.BytesToHash(crypto.Keccak256(pdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var ParentHash [32]frontend.Variable
	for i := 0; i < len(ParentHash); i++ {
		ParentHash[i] = pdata[i]
	}
	cdata, err := encodeHeader(current, false)
	if err != nil {
		panic(err)
	}
	cdata = common.BytesToHash(crypto.Keccak256(cdata)).Bytes()
	//fmt.Printf("%v\n", data)
	var CurrentHash [32]frontend.Variable
	for i := 0; i < len(CurrentHash); i++ {
		CurrentHash[i] = cdata[i]
	}
	var MixDigest [32]frontend.Variable
	for i := 0; i < len(MixDigest); i++ {
		MixDigest[i] = current.MixDigest[i]
	}

	rlpHashVerifyProof1, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashCcs, &rlpHashPk, &rlpHashVk, parent, false)
	if err != nil {
		return nil, err
	}
	rlpProof1, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyProof1)
	if err != nil {
		return nil, err
	}
	rlpHashVerifyProof2, _, err := ComputeRLPProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), rlpHashCcs, &rlpHashPk, &rlpHashVk, current, false)
	if err != nil {
		return nil, err
	}
	rlpProof2, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rlpHashVerifyProof2)
	if err != nil {
		return nil, err
	}
	toG2HashProof, _, err := ComputeToG2HashProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField(), toG2HashCcs, &toG2HashPk, &toG2HashVk, current)
	if err != nil {
		return nil, err
	}
	g2Proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](toG2HashProof)
	if err != nil {
		return nil, err
	}
	rlpKey, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](rlpHashVk)
	if err != nil {
		return nil, err
	}
	g2Key, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](toG2HashVk)
	if err != nil {
		return nil, err
	}

	return &ExtraV1OrV2HeaderVerifyWrapper[emulated.Secp256k1Fp, emulated.Secp256k1Fr, sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Parent:        pparent,
		Current:       pcurrent,
		RLPHashProof1: rlpProof1,
		RLPHashProof2: rlpProof2,
		ToG2HashProof: g2Proof,
		ToG2Hash:      ToG2Hash,
		ParentHash:    ParentHash,
		CurrentHash:   CurrentHash,
		MixDigest:     MixDigest,
		RLPHashVk:     rlpKey,
		ToG2HashVk:    g2Key,
	}, nil
}

func HeaderTestData(extraVersion byte) (parent, current *types.Header) {
	switch extraVersion {
	case ExtraV0:
		parent = new(types.Header)
		err := parent.UnmarshalJSON([]byte(
			`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x1",
			"extraData": "0x000fa7e10abc3b4c9dc768f0fa0a043feb987e21772952f909b98424f1e99f641212951c350ea78a0c4ea2a4697d40247c8be1f2b9ffa03a0e92dcbacca2617fcd447e2932857696c707055f517bbdb2eaa51fe05b0183d01607bf48c1718d1168a1c11171cbbeca26e89011e32ba25610520b20741b809007d10f47396dc6c76ad53546158751582d3e2683ef120f17ca9a284e245123266794e84a9b7837c063efbabb9fa0493bdfef639b4c1bd435671bdc994e3fcb1a49215724846df81dfb053aef81546c09ab9716b5a3004a14579ed10f83daa2bde98917c2ece6a96e44751d09c5d6ae3b142d97896b60386fa6e124fee91bad6db620706e0e7c2c8c164b18b5aca96e6e92e74dfed9c90112634ee0f5e3ac574e6b9d448e63049c21be1918888e0281d125a65be23a64d478af4e920eb98b127ce558210d82617e220cadf53718fc96a4f8c978d9a9f3f500005eb0a3d3d6891e93eea2c265586da39bbaa37340f1314adccb7b412e8bc590518ad65d82ed5e25683e0482f4658918244625dfedff1dce99ec68ea548cdf3a0078034253bd9182d011eeab022da45dd9d92e031655a6f0c16215674496762bd540ccc5e684f92651df31e8233a9b4206b002157a45999d1bc85f13c3dfc11a0800",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0x5651954a9691194b40ec6fa173a7f7d2ca86c4b30c6dd1af331eaeee079c1e78",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0x229c4ebaddc5f4824218d2ec9839f61e984ada15408b8c304a8fbde45a9d12fa",
			"nonce": "0x0000000000000002",
			"number": "0x11",
			"parentHash": "0x8f19bb26cf4e2f3f19a0cb2ad318a3539419c8a1fec46b14ba46a68e6514f085",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x3f9",
			"stateRoot": "0xdb2f7ede2ec991c786df6ac4672817f1608b4893484238d06da8a2278924e8e9",
			"timestamp": "0x668fb56c",
			"totalDifficulty": "0x1d",	
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
		))
		if err != nil {
			panic(err)
		}
		current = new(types.Header)
		err = current.UnmarshalJSON([]byte(
			`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x2",
			"extraData": "0x000fa7e10abc3b4c9dc768f0fa0a043feb987e21772952f909b98424f1e99f641212951c350ea78a0c4ea2a4697d40247c8be1f2b9ffa03a0e92dcbacca2617fcd447e2932857696c707055f517bbdb2eaa51fe05b0183d01607bf48c1718d1168a1c11171cbbeca26e89011e32ba25610520b20741b809007d10f47396dc6c76ad53546158751582d3e2683ef328f82d2587fb1e58e3cb5fdc1b789f15b4acd6101458614b2f13ab5c822eede4e21a3d265868692073432ad9df7a902a2bf2088721999aad8dddc39e853de6c0110bca64701039749bcb404bc1c1f42efa38975507a7c94316acb681b6776064067918c3c98d340ffa623d509209a42bfc199b7d8a117f6ee007dc458199ecc4b0016d999c0420fcf9df7da68a60e6b82a0c8af62386b538265eb2e589e8bc9a553004700c2d4bd1cf4291390c369ad1dd94d0cbbf271b3c206de1fe9086df359e300c33ce941969e864b1d36434248bc96ce24cb5ab75e48daa3a1a64cb927a3326f0b5546d4d5b813b56b4aee42f32b06703db5b6734da5eb575ef0e33a9fcbd0a800687fb01563327200cc68921d349e6ec8a9c04a5b33729bb51a32077dabd85b5274ae9bf95799318e5fc3e566709a5c65b96a5566c3bec4626f9087320886a97501",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0x69d097c89f2f94f33640e8689ecb3b4715fcfca44a16f8c6710c0d29a47e01b1",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0x229c4ebaddc5f4824218d2ec9839f61e984ada15408b8c304a8fbde45a9d12fa",
			"nonce": "0x0000000000000004",
			"number": "0x12",
			"parentHash": "0x5651954a9691194b40ec6fa173a7f7d2ca86c4b30c6dd1af331eaeee079c1e78",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x3f9",
			"stateRoot": "0xdb2f7ede2ec991c786df6ac4672817f1608b4893484238d06da8a2278924e8e9",
			"timestamp": "0x668fb5a9",
			"totalDifficulty": "0x1f",
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
		))
		if err != nil {
			panic(err)
		}

	case ExtraV1:
		parent = new(types.Header)
		err := parent.UnmarshalJSON([]byte(
			`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x2",
			"extraData": "0x0101072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76a5b5119bdcba3022c77f07b13bea98239781492b075fb8a1dff6895377dcd5251c3134660c973244d84101814ad14fa9a6605298b06a5c70c969ee5c1357236cbe9b7b65ee59f567e95d6a8fe0966175676170c0ecf174ef6ad701574d7b7d1a099068d29ac7662e20a2ae74898d19b93966d89314946745860d47c59c38208f83b50013414845cb5706840426f45b2c",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0xecd8bd1c514fd33d9e01184783af6f2dd58f3a213b294fe8019aab5271140633",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0xc1a8ea569ae7daff411094c088d4dd58cd439d241d9c31af61a537c6505761a5",
			"nonce": "0x0000000000000005",
			"number": "0x2970d9",
			"parentHash": "0x59db04b079ab47dde8736b231469db4e4a1ca2c9fc8e251bf41cf3c336facefe",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x2db",
			"stateRoot": "0xf675a08553de3363c8abc70879a9cc6ca6c6be517ae21a7f6601835fb6181ff9",
			"timestamp": "0x680b3b51",
			"totalDifficulty": "0x5023a5",
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
		))
		if err != nil {
			panic(err)
		}
		current = new(types.Header)
		err = current.UnmarshalJSON([]byte(
			`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x2",
			"extraData": "0x0101072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76a5b5119bdcba3022c77f07b13bea98239781492b075fb8a1dff6895377dcd5251c3134660c973244d84101814ad14fa9a2267aebbca32f4f307ffe32c1d387b78585335d413747522953d7eccdfdb54fec71d9c8d28ce456ce51fadbf3dd059a15c42c964250c71107c987966a23d49f086cadf981f812d8deab403047cd8b8438fc8ca79cb6ee9290b3780f80007838",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0x72273a91d87952260ff37c86839d69d1e1b6d3bbfc6e00a55198950bbcf182dc",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0xc1a8ea569ae7daff411094c088d4dd58cd439d241d9c31af61a537c6505761a5",
			"nonce": "0x0000000000000006",
			"number": "0x2970da",
			"parentHash": "0xecd8bd1c514fd33d9e01184783af6f2dd58f3a213b294fe8019aab5271140633",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x2db",
			"stateRoot": "0xf675a08553de3363c8abc70879a9cc6ca6c6be517ae21a7f6601835fb6181ff9",
			"timestamp": "0x680b3b56",
			"totalDifficulty": "0x5023a7",
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
		))
		if err != nil {
			panic(err)
		}
	case ExtraV2:
		parent = new(types.Header)
		err := parent.UnmarshalJSON([]byte(
			`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x2",
			"extraData": "0x0201072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76976d77c5cdebcce0c6e39cdd29d21ac54ad911720cf7fd28d7806515816587b95c6fc14588d93c564bd46ade8affac53aa75d3d4d2abcbc7363ead5d7ada2e9e2de20a40c8d78d440f23f36bd82638cad0039ce46bcfc86c380b643ed9ae38a801d9097e699a9b30306289388bedbc50fabb3633ec8e9d8596c5800d0dc6f3859c766170fb406915574fa81827a0c3d6",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0x70b8d2a8371cf83d94012459876d326fe236141ea2d8c04ccaa7ba5d4dad19a4",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0x8ff779018b306c26cf13c12aa70002ecb98e553f725049d81bfca73ca5141ec9",
			"nonce": "0x0000000000000002",
			"number": "0x3aac81",
			"parentHash": "0xa71dba8853d9a78570c223273b1baa54f1940da2ab6c65cec4a8e055b18a9e91",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x2db",
			"stateRoot": "0x73fa78a8689580ed7319392cb2f9d062acece70f938f9b9af6578e15c6ee4aeb",
			"timestamp": "0x6862306b",
			"totalDifficulty": "0x729861",
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
		))
		if err != nil {
			panic(err)
		}
		current = new(types.Header)
		err = current.UnmarshalJSON([]byte(
			`{
			"baseFeePerGas": "0x4a817c800",
			"difficulty": "0x2",
			"extraData": "0x0201072bc064323344cba6d63cad4ca88afbea585fc612919e3e351f457ea3704f76976d77c5cdebcce0c6e39cdd29d21ac54ad911720cf7fd28d7806515816587b95c6fc14588d93c564bd46ade8affac53b509b7477d85c870d635371a054713ecff352b98261bac920963a7891d86537c8f3ea9f37ebf9bc7a325129f4b9bc47e064bd1ae1f588f62df3613b81c50680d81d7a754262d4027919c827834ce3676997a15b4adea6b387171afb7c65a13a8",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"hash": "0x5ee3e44dbf6a87b798534efb870f63957c2d5b2ccda1b7360ea0159a403e738b",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"miner": "0x1212000000000000000000000000000000000003",
			"mixHash": "0x8ff779018b306c26cf13c12aa70002ecb98e553f725049d81bfca73ca5141ec9",
			"nonce": "0x0000000000000003",
			"number": "0x3aac82",
			"parentHash": "0x70b8d2a8371cf83d94012459876d326fe236141ea2d8c04ccaa7ba5d4dad19a4",
			"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size": "0x2db",
			"stateRoot": "0x73fa78a8689580ed7319392cb2f9d062acece70f938f9b9af6578e15c6ee4aeb",
			"timestamp": "0x68623070",
			"totalDifficulty": "0x729863",
			"transactions": [],
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"uncles": [],
			"withdrawals": [],
			"withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
		}`,
		))
		if err != nil {
			panic(err)
		}
	default:
		panic("invalid extra version")
	}
	return
}
