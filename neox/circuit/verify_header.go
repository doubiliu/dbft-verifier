package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/selector"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"slices"
)

type HeaderVerifier[ECDSAFp, ECDSAFr emulated.FieldParams, FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	api frontend.API
}

func NewHeaderVerifier[ECDSAFp, ECDSAFr emulated.FieldParams, FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](api frontend.API) HeaderVerifier[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl] {
	return HeaderVerifier[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl]{api: api}
}

// VerifyV0 to verify a header in ExtraV0
// // 1. Verify RlpHash(parent) = current.Hash
// // 2. Verify RlpHash(current) = currentHash
// // 3. Verify RlpHash(noSigCurrent) = noSigHash
// // 4. Verify ecdsa signatures
func (hv *HeaderVerifier[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl]) VerifyV0(
	parent, current HeaderParameters,
	parentHash []frontend.Variable, currentHash []frontend.Variable, MixDigest []frontend.Variable,
	RLPHashProof1 groth16.Proof[G1El, G2El], RLPHashProof2 groth16.Proof[G1El, G2El], RLPHashVk groth16.VerifyingKey[G1El, G2El, GtEl],
	NoSigHashProof groth16.Proof[G1El, G2El], NoSigHashVk groth16.VerifyingKey[G1El, G2El, GtEl], NoSigHash []frontend.Variable,
	publicKeys []ecdsa.PublicKey[ECDSAFp, ECDSAFr], addressIndices []frontend.Variable) error {
	api := hv.api
	// ExtraV0
	api.AssertIsEqual(current.Extra[0], 0)
	field, err := emulated.NewField[FR](api)
	if err != nil {
		panic(err)
	}
	// check basic
	if err = hv.BasicCheck(field, current, parent, parentHash, currentHash, MixDigest, RLPHashProof1, RLPHashProof2, RLPHashVk); err != nil {
		return err
	}
	expectConsensus := parent.MixDigest

	api.AssertIsEqual(len(current.Extra), HashableExtraV0Len+7*common.AddressLength+5*crypto.SignatureLength) // len(current.Extra) == HashableExtraV0Len+7*common.AddressLength+5*crypto.SignatureLength
	addrBytes := current.Extra[HashableExtraV0Len : HashableExtraV0Len+7*common.AddressLength]
	sigBytes := current.Extra[HashableExtraV0Len+7*common.AddressLength:]
	addrs := make([][]frontend.Variable, 7) // len(address) = 20
	for i := range addrs {
		for j := i * common.AddressLength; j < (i+1)*common.AddressLength; j++ {
			addrs[i] = append(addrs[i], addrBytes[j])
		}
		//copy(addrs[i][:], addrBytes[i*common.AddressLength:(i+1)*common.AddressLength])
	}
	addressInts := make([]frontend.Variable, 7)
	for i := 0; i < len(addressInts); i++ {
		slices.Reverse(addrs[i]) // little-endian
		addressBits := make([]frontend.Variable, 0)
		for _, b := range addrs[i] {
			addressBits = append(addressBits, api.ToBinary(b, 8)...)
		}
		addressInts[i] = api.FromBinary(addressBits...)
	}
	sigs := make([][]frontend.Variable, 5) // len(sig) = 65
	for i := range sigs {
		for j := i * crypto.SignatureLength; j < (i+1)*crypto.SignatureLength; j++ {
			sigs[i] = append(sigs[i], sigBytes[j])
		}
		//copy(sigs[i][:], sigBytes[i*crypto.SignatureLength:(i+1)*crypto.SignatureLength])
	}
	{
		// Verify CNs
		// compute keccak256(addrBytes)
		keccak256 := NewKeccak256(api)
		addrHash, err := keccak256.Compute(addrBytes)
		if err != nil {
			return err
		}
		api.AssertIsEqual(len(expectConsensus), len(addrHash))
		for i := 0; i < len(addrHash); i++ {
			api.AssertIsEqual(addrHash[i], expectConsensus[i])
		}
	}
	// todo add a GetxxxHeader(heaer, isSig)
	// encode no sig current
	//noSigCurrent, err := current.NoSigHeader()
	//if err != nil {
	//	return err
	//}
	//noSigCompress := noSigCurrent.Compress(api)
	compressedCheader := current.Compress(api)
	if err = hv.verifyRlpHash(field, compressedCheader, NoSigHash, NoSigHashProof, NoSigHashVk); err != nil {
		return err
	}
	//fmt.Println("currentRlpHash in circuit: ", currentRlpHash)
	//fmt.Println("signature hash in circuit: ", message)
	// verify sigs
	sigVerifier := NewECDSASigVerifier[ECDSAFp, ECDSAFr](api)
	// len(public keys) = len(addressIndices) = 5
	api.AssertIsEqual(len(publicKeys), len(addressIndices))
	for i := 0; i < len(addressIndices); i++ {
		// we verify addrBytes[index]
		api.AssertIsEqual(len(sigs[i]), 65)
		signature := [65]frontend.Variable(sigs[i])
		addressInt := selector.Mux(api, addressIndices[i], addressInts...) // addressInt[index]
		address := api.ToBinary(addressInt, 160)                           // len(20) * 8
		addressBytes := make([]frontend.Variable, 20)
		for j := 0; j < 20; j++ {
			addressBytes[j] = api.FromBinary(address[j*8 : (j+1)*8]...)
		}
		if err := sigVerifier.Verify([32]frontend.Variable(NoSigHash), signature, publicKeys[i], [20]frontend.Variable(addressBytes)); err != nil {
			return err
		}
	}
	return nil
}

// VerifyV1OrV2 to verify a header in ExtraV1 or ExtraV2
// 1. Verify RlpHash(parent) = current.Hash
// 2. Verify RlpHash(current) = currentHash
// 3. Verify ToG2Hash(noSigCurrent) = g2Hash
// 4. Verify bls signatures
func (hv *HeaderVerifier[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl]) VerifyV1OrV2(
	current, parent HeaderParameters,
	parentHash []frontend.Variable, currentHash []frontend.Variable, MixDigest []frontend.Variable,
	RLPHashProof1 groth16.Proof[G1El, G2El], RLPHashProof2 groth16.Proof[G1El, G2El], RLPHashVk groth16.VerifyingKey[G1El, G2El, GtEl],
	ToG2HashProof groth16.Proof[G1El, G2El], ToG2HashVk groth16.VerifyingKey[G1El, G2El, GtEl], ToG2Hash []frontend.Variable) error {
	api := hv.api
	field, err := emulated.NewField[FR](api)
	if err != nil {
		panic(err)
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	// Check basic
	if err = hv.BasicCheck(field, current, parent, parentHash, currentHash, MixDigest, RLPHashProof1, RLPHashProof2, RLPHashVk); err != nil {
		return err
	}

	//check consensus
	expectConsensus := parent.MixDigest
	extraLength := len(current.Extra)
	api.AssertIsLessOrEqual(2, frontend.Variable(extraLength))
	v0 := current.Extra[0]
	//check Extra[0], should be ExtraV1 | ExtraV2
	rangeCheck(api, v0, []frontend.Variable{frontend.Variable(ExtraV1), frontend.Variable(ExtraV2)})
	v1 := current.Extra[1]
	//Extra[1] should be ExtraV1ThresholdScheme
	api.AssertIsEqual(v1, frontend.Variable(ExtraV1ThresholdScheme))
	// Check format
	api.AssertIsEqual(frontend.Variable(extraLength), frontend.Variable(HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen))
	// Get global public key and sig
	pubBytes := current.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
	sigBytes := current.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		panic(err)
	}
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		panic(err)
	}
	pubU8s := make([]uints.U8, len(pubBytes))
	for i := 0; i < len(pubBytes); i++ {
		pubU8s[i] = uapi.ByteValueOf(pubBytes[i])
	}
	pk, err := g1.FromCompressedBytes(pubU8s)
	if err != nil {
		panic(err)
	}
	sigU8s := make([]uints.U8, len(sigBytes))
	for i := 0; i < len(sigBytes); i++ {
		sigU8s[i] = uapi.ByteValueOf(sigBytes[i])
	}
	sig, err := g2.FromCompressedBytes(sigU8s)
	if err != nil {
		panic(err)
	}
	// Verify global public key
	keccak256 := NewKeccak256(api)
	exactConsensus, err := keccak256.Compute(pubBytes)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(expectConsensus); i++ {
		api.AssertIsEqual(exactConsensus[i], expectConsensus[i])
	}
	g2Hash := slices.Clone(ToG2Hash)
	slices.Reverse(g2Hash)
	// to verify hash=g2.toHash(current header) in sub-circuit
	toG2HashBits := make([]frontend.Variable, 0) // 768-bit
	for _, v := range g2Hash {
		toG2HashBits = append(toG2HashBits, api.ToBinary(v, 8)...)
	}
	compressG2Hash := make([]frontend.Variable, 4)
	for i := 0; i < 4; i++ {
		compressG2Hash[3-i] = api.FromBinary(toG2HashBits[192*i : (i+1)*192]...)
	}
	compressedCurrentHeader := current.Compress(api)
	toG2HashVerifyInput := make([]frontend.Variable, 0)
	toG2HashVerifyInput = append(toG2HashVerifyInput, compressG2Hash[:]...)
	toG2HashVerifyInput = append(toG2HashVerifyInput, compressedCurrentHeader.Serialize()...)
	toG2HashVerifyInputElements := make([]emulated.Element[FR], len(toG2HashVerifyInput))
	for i := 0; i < len(toG2HashVerifyInputElements); i++ {
		bits := bits.ToBinary(api, toG2HashVerifyInput[i])
		toG2HashVerifyInputElements[i] = *field.FromBits(bits...)
	}
	verifier3, err := groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}
	err = verifier3.AssertProof(ToG2HashVk, ToG2HashProof, groth16.Witness[FR]{Public: toG2HashVerifyInputElements}, groth16.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	ToG2HashU8s := make([]uints.U8, len(ToG2Hash))
	for i := 0; i < len(ToG2Hash); i++ {
		ToG2HashU8s[i] = uapi.ByteValueOf(ToG2Hash[i])
	}
	//get seal hash
	toG2HashPoint, err := g2.FromCompressedBytes(ToG2HashU8s)
	if err != nil {
		return err
	}
	// Negate the sig in V1,current.Extra[0] == ExtraV1
	negSig := g2.Neg(*toG2HashPoint)
	negSigBytes, err := g2.ToCompressedBytes(negSig)
	if err != nil {
		return err
	}
	flag := api.Select(api.IsZero(api.Sub(v0, frontend.Variable(ExtraV1))), frontend.Variable(1), frontend.Variable(0))
	negflag := api.Sub(frontend.Variable(1), flag)
	ToG2HashBits := make([]frontend.Variable, 0)
	for i := 0; i < len(ToG2Hash); i++ {
		tempbits := bits.ToBinary(api, ToG2Hash[i], bits.WithNbDigits(8))
		ToG2HashBits = append(ToG2HashBits, tempbits...)
	}

	negHashBits := make([]frontend.Variable, 0)
	for i := 0; i < len(negSigBytes); i++ {
		tempbits := bits.ToBinary(api, negSigBytes[i].Val, bits.WithNbDigits(8))
		negHashBits = append(negHashBits, tempbits...)
	}
	resultHashBits := make([]frontend.Variable, len(negHashBits))
	for i := 0; i < len(resultHashBits); i++ {
		resultHashBits[i] = api.Add(api.Mul(flag, ToG2HashBits[i]), api.Mul(negflag, negHashBits[i]))
	}
	resultHashBytes := make([]uints.U8, len(resultHashBits)/8)
	for i := 0; i < len(resultHashBytes); i++ {
		tempbyte := bits.FromBinary(api, resultHashBits[i*8:i*8+8])
		resultHashBytes[i] = uapi.ByteValueOf(tempbyte)
	}
	resultHash, err := g2.FromCompressedBytes(resultHashBytes)
	if err != nil {
		panic(err)
	}
	//verify bls sig
	blsVerify := NewBlsSigVerify(api)
	blsVerify.Verify(api, resultHash, sig, pk)
	return nil
}

func (hv *HeaderVerifier[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl]) BasicCheck(
	field *emulated.Field[FR],
	current, parent HeaderParameters,
	parentHash []frontend.Variable, currentHash []frontend.Variable, MixDigest []frontend.Variable,
	RLPHashProof1 groth16.Proof[G1El, G2El], RLPHashProof2 groth16.Proof[G1El, G2El], RLPHashVk groth16.VerifyingKey[G1El, G2El, GtEl],
) error {
	api := hv.api
	compressedCheader := current.Compress(api)
	compressedPheader := parent.Compress(api)
	//to verify parentHash=rlpencode(parent header) in sub-circuit

	if err := hv.verifyRlpHash(field, compressedPheader, slices.Clone(parentHash), RLPHashProof1, RLPHashVk); err != nil {
		return err
	}
	//to verify currentHash=rlpencode(current header) in sub-circuit
	if err := hv.verifyRlpHash(field, compressedCheader, slices.Clone(currentHash), RLPHashProof2, RLPHashVk); err != nil {
		return err
	}
	//check parentHash=current.parentHash
	for i := 0; i < len(parentHash); i++ {
		api.AssertIsEqual(parentHash[i], current.ParentHash[i])
	}
	//check MixDigest
	for i := 0; i < len(current.MixDigest); i++ {
		api.AssertIsEqual(MixDigest[i], current.MixDigest[i])
	}
	//check current number=parent+1
	cn, err := BytesToIntVarible(api, current.Number[:])
	if err != nil {
		return err
	}
	pn, err := BytesToIntVarible(api, parent.Number[:])
	if err != nil {
		return err
	}
	api.AssertIsEqual(cn, api.Add(pn, frontend.Variable(1)))
	//check time ,current.Time should bigger than parent
	ct, err := BytesToIntVarible(api, current.Time[:])
	if err != nil {
		return err
	}
	pt, err := BytesToIntVarible(api, parent.Time[:])
	if err != nil {
		return err
	}
	cmp := api.Cmp(ct, pt)
	api.AssertIsEqual(cmp, frontend.Variable(1))
	return nil
}

func (hv *HeaderVerifier[ECDSAFp, ECDSAFr, FR, G1El, G2El, GtEl]) verifyRlpHash(
	field *emulated.Field[FR],
	header CompressHeaderParameters, hash []frontend.Variable,
	proof groth16.Proof[G1El, G2El], RLPHashVk groth16.VerifyingKey[G1El, G2El, GtEl]) error {
	api := hv.api
	// parentHash is 32-byte
	// we transform to 2 variables
	res := slices.Clone(hash)
	slices.Reverse(res)
	hashBits := make([]frontend.Variable, 0)
	for _, h := range res {
		hashBits = append(hashBits, api.ToBinary(h, 8)...)
	}
	r1 := make([]frontend.Variable, 254)
	r2 := make([]frontend.Variable, 254)
	for i := 0; i < 254; i++ {
		if i < 128 {
			r1[i] = hashBits[i]
			r2[i] = hashBits[128+i]
		} else {
			r1[i] = 0
			r2[i] = 0
		}
	}
	rlpverifyInput := make([]frontend.Variable, 0)
	rlpverifyInput = append(rlpverifyInput, []frontend.Variable{api.FromBinary(r2...), api.FromBinary(r1...)}...)
	rlpverifyInput = append(rlpverifyInput, header.Serialize()...)
	rlpverifyInputElements := make([]emulated.Element[FR], len(rlpverifyInput))
	for i := 0; i < len(rlpverifyInputElements); i++ {
		bits := bits.ToBinary(api, rlpverifyInput[i])
		rlpverifyInputElements[i] = *field.FromBits(bits...)
	}
	verifier, err := groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	err = verifier.AssertProof(RLPHashVk, proof, groth16.Witness[FR]{Public: rlpverifyInputElements}, groth16.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	return nil
}
