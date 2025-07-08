package circuit

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
)

type VerifyWrapper[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Current       HeaderParameters
	Parent        HeaderParameters
	RLPHashProof1 groth16.Proof[G1El, G2El]              `gnark:",secret"`
	RLPHashProof2 groth16.Proof[G1El, G2El]              `gnark:",secret"`
	RLPHashVk     groth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	ToG2HashProof groth16.Proof[G1El, G2El]              `gnark:",secret"`
	ToG2HashVk    groth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	ToG2Hash      [96]frontend.Variable                  `gnark:",secret"`
	ParentHash    [32]frontend.Variable                  `gnark:",public"`
	CurrentHash   [32]frontend.Variable                  `gnark:",public"`
	MixDigest     [32]frontend.Variable                  `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *VerifyWrapper[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verify := NewVerify[FR, G1El, G2El, GtEl](api)
	verify.Verify(api, c.Current, c.Parent, c.ParentHash[:], c.CurrentHash[:], c.MixDigest[:], c.RLPHashProof1, c.RLPHashProof2, c.RLPHashVk, c.ToG2HashProof, c.ToG2HashVk, c.ToG2Hash[:])
	return nil
}

func NewVerify[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](api frontend.API) Verify[FR, G1El, G2El, GtEl] {
	return Verify[FR, G1El, G2El, GtEl]{api: api}
}

type Verify[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	api frontend.API
}

func (verify *Verify[FR, G1El, G2El, GtEl]) Verify(api frontend.API, current HeaderParameters, parent HeaderParameters, parentHash []frontend.Variable, currentHash []frontend.Variable, MixDigest []frontend.Variable, RLPHashProof1 groth16.Proof[G1El, G2El], RLPHashProof2 groth16.Proof[G1El, G2El], RLPHashVk groth16.VerifyingKey[G1El, G2El, GtEl], ToG2HashProof groth16.Proof[G1El, G2El], ToG2HashVk groth16.VerifyingKey[G1El, G2El, GtEl], ToG2Hash []frontend.Variable) {
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
	rlpverifyInput1 := make([]frontend.Variable, 0)
	rlpverifyInput1 = append(rlpverifyInput1, parentHash[:]...)
	rlpverifyInput1 = append(rlpverifyInput1, serializePHeader...)
	rlpverifyInputElements1 := make([]emulated.Element[FR], len(rlpverifyInput1))
	for i := 0; i < len(rlpverifyInputElements1); i++ {
		bits := bits.ToBinary(api, rlpverifyInput1[i])
		rlpverifyInputElements1[i] = *field.FromBits(bits...)
	}
	verifier1, err := groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		panic(err)
	}
	err = verifier1.AssertProof(RLPHashVk, RLPHashProof1, groth16.Witness[FR]{Public: rlpverifyInputElements1}, groth16.WithCompleteArithmetic())
	if err != nil {
		panic(err)
	}
	//check parentHash=current.parentHash
	for i := 0; i < len(parentHash); i++ {
		api.AssertIsEqual(parentHash[i], current.ParentHash[i])
	}
	//to verify currenttHash=rlpencode(current header) in sub-circuit
	rlpverifyInput2 := make([]frontend.Variable, 0)
	rlpverifyInput2 = append(rlpverifyInput2, currentHash[:]...)
	rlpverifyInput2 = append(rlpverifyInput2, serializeCHeader...)
	rlpverifyInputElements2 := make([]emulated.Element[FR], len(rlpverifyInput2))
	for i := 0; i < len(rlpverifyInputElements2); i++ {
		bits := bits.ToBinary(api, rlpverifyInput2[i])
		rlpverifyInputElements2[i] = *field.FromBits(bits...)
	}
	verifier2, err := groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		panic(err)
	}
	err = verifier2.AssertProof(RLPHashVk, RLPHashProof2, groth16.Witness[FR]{Public: rlpverifyInputElements2}, groth16.WithCompleteArithmetic())
	if err != nil {
		panic(err)
	}
	//check MixDigest
	for i := 0; i < len(current.MixDigest); i++ {
		api.AssertIsEqual(MixDigest[i], current.MixDigest[i])
	}
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
	// to verify hash=g2.toHash(current header) in sub-circuit
	toG2HashVerifyInput := make([]frontend.Variable, 0)
	toG2HashVerifyInput = append(toG2HashVerifyInput, ToG2Hash[:]...)
	toG2HashVerifyInput = append(toG2HashVerifyInput, serializeCHeader...)
	toG2HashVerifyInputElements := make([]emulated.Element[FR], len(toG2HashVerifyInput))
	for i := 0; i < len(toG2HashVerifyInputElements); i++ {
		bits := bits.ToBinary(api, toG2HashVerifyInput[i])
		toG2HashVerifyInputElements[i] = *field.FromBits(bits...)
	}
	verifier3, err := groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		panic(err)
	}
	err = verifier3.AssertProof(ToG2HashVk, ToG2HashProof, groth16.Witness[FR]{Public: toG2HashVerifyInputElements}, groth16.WithCompleteArithmetic())
	if err != nil {
		panic(err)
	}
	ToG2HashU8s := make([]uints.U8, len(ToG2Hash))
	for i := 0; i < len(ToG2Hash); i++ {
		ToG2HashU8s[i] = uapi.ByteValueOf(ToG2Hash[i])
	}
	//get seal hash
	toG2HashPoint, err := g2.FromCompressedBytes(ToG2HashU8s)
	if err != nil {
		panic(err)
	}
	fmt.Println(toG2HashPoint)
	// Negate the sig in V1,current.Extra[0] == ExtraV1
	negSig := g2.Neg(*toG2HashPoint)
	negSigBytes, err := g2.ToCompressedBytes(negSig)
	if err != nil {
		panic(err)
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
