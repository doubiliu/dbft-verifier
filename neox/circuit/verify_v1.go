package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
)

type VerifyWrapper[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Current HeaderParameters
	Parent  HeaderParameters
	/*	Hash         sw_bls12381.G2Affine
		Sig          sw_bls12381.G2Affine
		Pub          sw_bls12381.G1Affine*/
	RLPHashProof groth16.Proof[G1El, G2El]              `gnark:",secret"`
	RLPHashVk    groth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"` // CircuitVerifyKeys is related to the srsl and ccs
	//ParentHash   [32]frontend.Variable
	ToG2HashProof groth16.Proof[G1El, G2El]              `gnark:",secret"`
	ToG2HashVk    groth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"` // CircuitVerifyKeys is related to the srsl and ccs
	ToG2Hash      []frontend.Variable
}

// Define declares the circuit's constraints
func (c *VerifyWrapper[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verify := NewVerify[FR, G1El, G2El, GtEl](api)
	//verify.Verify(api, c.Current, c.Parent, c.Hash, c.ParentHash)
	verify.Verify2(api, c.Current, c.Parent, c.RLPHashProof, c.RLPHashVk, c.ToG2HashProof, c.ToG2HashVk, c.ToG2Hash)
	return nil
}

func NewVerify[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](api frontend.API) Verify[FR, G1El, G2El, GtEl] {
	return Verify[FR, G1El, G2El, GtEl]{api: api}
}

type Verify[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	api frontend.API
}

func (verify *Verify[FR, G1El, G2El, GtEl]) Verify(api frontend.API, current HeaderParameters, parent HeaderParameters, hash sw_bls12381.G2Affine) {
	// Check basic
	headerencode := NewHeaderEncode(api)
	parentHash := headerencode.RlpHash(api, parent)
	for i := 0; i < len(current.ParentHash); i++ {
		api.AssertIsEqual(current.ParentHash[i], parentHash[i])
	}
	//check current number=parent+1
	cn, err := BytesToIntVarible(api, current.Number[:])
	pn, err := BytesToIntVarible(api, parent.Number[:])
	api.AssertIsEqual(cn, api.Add(pn, frontend.Variable(1)))

	//compre time ,current.Time should bigger than parent
	ct, err := BytesToIntVarible(api, current.Time[:])
	pt, err := BytesToIntVarible(api, parent.Time[:])
	cmp := api.Cmp(ct, pt)
	api.AssertIsEqual(cmp, frontend.Variable(1))

	expectConsensus := parent.MixDigest
	extraLength := len(current.Extra)
	api.AssertIsLessOrEqual(2, frontend.Variable(extraLength))
	v0 := current.Extra[0]
	//Extra[0] should be ExtraV1 | ExtraV2
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
		return
	}
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return
	}
	pubU8s := make([]uints.U8, len(pubBytes))
	for i := 0; i < len(pubBytes); i++ {
		pubU8s[i] = uapi.ByteValueOf(pubBytes[i])
	}
	pk, err := g1.FromCompressedBytes(pubU8s)
	if err != nil {
		return
	}
	sigU8s := make([]uints.U8, len(sigBytes))
	for i := 0; i < len(sigBytes); i++ {
		sigU8s[i] = uapi.ByteValueOf(sigBytes[i])
	}
	sig, err := g2.FromCompressedBytes(sigU8s)
	if err != nil {
		return
	}

	// Verify global public key
	keccak256 := NewKeccak256(api)
	exactConsensus, err := keccak256.Compute(pubBytes)
	for i := 0; i < len(expectConsensus); i++ {
		api.AssertIsEqual(exactConsensus[i], expectConsensus[i])
	}
	// Get seal hash
	headencode := NewHeaderEncode(api)
	hashBytes := headencode.HashToG2(api, current)
	g2.AssertIsOnG2(&hash)
	marshalHashbits := g2.Marshal(hash)
	marshalHash := make([]frontend.Variable, len(marshalHashbits)/8)
	for i := 0; i < len(hashBytes); i++ {
		tbits := marshalHashbits[i*8 : (i+1)*8]
		treversebits := make([]frontend.Variable, len(tbits))
		for j := 0; j < len(tbits); j++ {
			treversebits[j] = tbits[len(tbits)-j-1]
		}
		marshalHash[i] = api.FromBinary(treversebits...)
	}
	for i := 0; i < len(hashBytes); i++ {
		api.AssertIsEqual(marshalHash[i], hashBytes[i])
	}
	/*	data := headencode.EncodeSigHeader(api, current)
		u8data := make([]uints.U8, len(data))
		uapi, err := uints.New[uints.U32](api)
		if err != nil {
			panic(err)
		}
		for i := 0; i < len(data); i++ {
			u8data[i] = uapi.ByteValueOf(data[i])
		}
		_, err = g2.HashToG2(api, u8data, BLSDomain)
		if err != nil {
			panic(err)
		}
		g2.AssertIsOnG2(&hash)
		hashBits = g2.MarshalG2(hash)
		hashBytes := make([]frontend.Variable, len(hashBits)/8)
		for i := 0; i < len(pkBytes); i++ {
			hashBytes[i] = api.FromBinary(hashBits[i*8 : (i+1)*8]...)
		}*/
	//check
	//ihash=hashBytes

	/*	hash, _ := bls12381.HashToG2(data, BLSDomain)*/
	// Negate the sig in V1,current.Extra[0] == ExtraV1
	//negSig := g2.Neg(&sig)
	/*	flag := api.Cmp(v0, frontend.Variable(ExtraV1))

		r := api.Select(flag, sig, negSig)*/
	// Verify sig
	blsVerify := NewBlsSigVerify(api)
	blsVerify.Verify(api, &hash, sig, pk)

	//最后检查外部hash1==current hash
	//最后检查外部hash2==parent hash
	/*	currentHash := headerencode.RlpHash(api, current)
		for i := 0; i < len(currentHash); i++ {
			api.AssertIsEqual(c.currentHash[i], currentHash[i])
		}*/
}

func (verify *Verify[FR, G1El, G2El, GtEl]) Verify2(api frontend.API, current HeaderParameters, parent HeaderParameters, RLPHashProof groth16.Proof[G1El, G2El], RLPHashVk groth16.VerifyingKey[G1El, G2El, GtEl], ToG2HashProof groth16.Proof[G1El, G2El], ToG2HashVk groth16.VerifyingKey[G1El, G2El, GtEl], ToG2Hash []frontend.Variable) {
	field, err := emulated.NewField[FR](api)
	if err != nil {
		panic(err)
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	// Check basic
	serializeCHeader := Serialize(current)
	serializePHeader := Serialize(parent)
	//to verify parentHash=rlpencode(parent header) in sub-circuit
	parentHash := current.ParentHash
	rlpverifyInput := make([]frontend.Variable, 0)
	rlpverifyInput = append(rlpverifyInput, parentHash[:]...)
	rlpverifyInput = append(rlpverifyInput, serializePHeader...)
	api.Println("rlpInput-in-circuit:")
	api.Println(rlpverifyInput)
	rlpverifyInputElements := make([]emulated.Element[FR], len(rlpverifyInput))
	for i := 0; i < len(rlpverifyInputElements); i++ {
		bits := bits.ToBinary(api, rlpverifyInput[i])
		rlpverifyInputElements[i] = *field.FromBits(bits...)
	}
	verifier1, err := groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		panic(err)
	}
	err = verifier1.AssertProof(RLPHashVk, RLPHashProof, groth16.Witness[FR]{Public: rlpverifyInputElements}, groth16.WithCompleteArithmetic())
	if err != nil {
		panic(err)
	}
	/*	for i := 0; i < len(current.ParentHash); i++ {
		api.AssertIsEqual(current.ParentHash[i], parentHashU8s[i])
	}*/
	//check current number=parent+1
	cn, err := BytesToIntVarible(api, current.Number[:])
	pn, err := BytesToIntVarible(api, parent.Number[:])
	api.AssertIsEqual(cn, api.Add(pn, frontend.Variable(1)))
	//check time ,current.Time should bigger than parent
	ct, err := BytesToIntVarible(api, current.Time[:])
	pt, err := BytesToIntVarible(api, parent.Time[:])
	cmp := api.Cmp(ct, pt)
	api.AssertIsEqual(cmp, frontend.Variable(1))
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
		return
	}
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return
	}
	pubU8s := make([]uints.U8, len(pubBytes))
	for i := 0; i < len(pubBytes); i++ {
		pubU8s[i] = uapi.ByteValueOf(pubBytes[i])
	}
	pk, err := g1.FromCompressedBytes(pubU8s)
	if err != nil {
		return
	}
	sigU8s := make([]uints.U8, len(sigBytes))
	for i := 0; i < len(sigBytes); i++ {
		sigU8s[i] = uapi.ByteValueOf(sigBytes[i])
	}
	sig, err := g2.FromCompressedBytes(sigU8s)
	if err != nil {
		return
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
	// to verify hash=g2.toHash(current header) in sub-circuit
	toG2HashVerifyInput := make([]frontend.Variable, 0)
	toG2HashVerifyInput = append(toG2HashVerifyInput, ToG2Hash[:]...)
	toG2HashVerifyInput = append(toG2HashVerifyInput, serializeCHeader...)
	toG2HashVerifyInputElements := make([]emulated.Element[FR], len(toG2HashVerifyInput))
	for i := 0; i < len(toG2HashVerifyInputElements); i++ {
		bits := bits.ToBinary(api, toG2HashVerifyInput[i])
		toG2HashVerifyInputElements[i] = *field.FromBits(bits...)
	}
	verifier2, err := groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		panic(err)
	}
	err = verifier2.AssertProof(ToG2HashVk, ToG2HashProof, groth16.Witness[FR]{Public: toG2HashVerifyInputElements}, groth16.WithCompleteArithmetic())
	if err != nil {
		panic(err)
	}
	ToG2HashU8s := make([]uints.U8, len(ToG2Hash))
	for i := 0; i < len(ToG2Hash); i++ {
		ToG2HashU8s[i] = uapi.ByteValueOf(ToG2Hash[i])
	}
	// get seal hash
	toG2HashPoint, err := g2.FromCompressedBytes(ToG2HashU8s)
	if err != nil {
		panic(err)
	}
	// Negate the sig in V1,current.Extra[0] == ExtraV1
	negSig := g2.Neg(toG2HashPoint)
	negSigBytes, err := g2.ToCompressedBytes(*negSig)
	if err != nil {
		return
	}
	flag := api.Select(api.IsZero(api.Sub(v0, frontend.Variable(ExtraV1))), frontend.Variable(1), frontend.Variable(0))
	negflag := api.Sub(frontend.Variable(1), flag)
	ToG2HashBits := make([]frontend.Variable, 0)
	for i := 0; i < len(ToG2Hash); i++ {
		tempbits := bits.ToBinary(api, ToG2Hash)
		ToG2HashBits = append(ToG2HashBits, tempbits...)
	}
	negHashBits := make([]frontend.Variable, 0)
	for i := 0; i < len(negSigBytes); i++ {
		tempbits := bits.ToBinary(api, negSigBytes)
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
	// verify parentHash=Hash(parent head),and currentHash=Hash(current Hash)
	/*	currentHash := headerencode.RlpHash(api, current)
		for i := 0; i < len(currentHash); i++ {
			api.AssertIsEqual(c.currentHash[i], currentHash[i])
		}*/
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
