package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
)

type VerifyWrapper struct {
	Current HeaderParameters
	Parent  HeaderParameters
	Hash    sw_bls12381.G2Affine
	Sig     sw_bls12381.G2Affine
	Pub     sw_bls12381.G1Affine
}

// Define declares the circuit's constraints
func (c *VerifyWrapper) Define(api frontend.API) error {
	verify := NewVerify(api)
	verify.Verify(api, c.Current, c.Parent, c.Pub, c.Sig, c.Hash)
	return nil
}

func NewVerify(api frontend.API) Verify {
	return Verify{api: api}
}

type Verify struct {
	api frontend.API
}

func (verify *Verify) Verify(api frontend.API, current HeaderParameters, parent HeaderParameters, pk sw_bls12381.G1Affine, sig sw_bls12381.G2Affine, hash sw_bls12381.G2Affine) {
	// Check basic
	headerencode := NewHeaderEncode(api)
	parentHash := headerencode.RlpHash(api, parent)
	for i := 0; i < len(current.ParentHash); i++ {
		api.AssertIsEqual(current.ParentHash[i], parentHash[i])
	}
	//check current number=parent+1
	cn, err := BytesToIntVarible(api, current.Number)
	pn, err := BytesToIntVarible(api, parent.Number)
	api.AssertIsEqual(cn, api.Add(pn, frontend.Variable(1)))

	//compre time ,current.Time should bigger than parent
	ct, err := BytesToIntVarible(api, current.Time)
	pt, err := BytesToIntVarible(api, parent.Time)
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
	/*	sigBytes := current.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]

		cr, err := sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](api, sw_emulated.GetCurveParams[sw_bls12381.BaseField]())
		if err != nil {
			return
		}*/
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return
	}

	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return
	}
	g1.AssertIsOnG1(&pk)
	g2.AssertIsOnG2(&sig)

	/*	pkBits := cr.MarshalG1(pk)
		sgBits := g2.MarshalG2(sig)

		hashBits := g2.MarshalG2(hash)
		pkBytes := make([]frontend.Variable, len(pkBits)/8)
		for i := 0; i < len(pkBytes); i++ {
			tbits := pkBits[i*8 : (i+1)*8]
			treversebits := make([]frontend.Variable, len(tbits))
			for j := 0; j < len(tbits); j++ {
				treversebits[j] = tbits[len(tbits)-j-1]
			}
			pkBytes[i] = api.FromBinary(treversebits...)
		}

		sgBytes := make([]frontend.Variable, len(sgBits)/8)
		for i := 0; i < len(sgBytes); i++ {
			tbits := sgBits[i*8 : (i+1)*8]
			treversebits := make([]frontend.Variable, len(tbits))
			for j := 0; j < len(tbits); j++ {
				treversebits[j] = tbits[len(tbits)-j-1]
			}
			sgBytes[i] = api.FromBinary(treversebits...)
		}
		for i := 0; i < len(pkBytes); i++ {
			api.AssertIsEqual(pkBytes[i], pubBytes[i])
		}
		for i := 0; i < len(sigBytes); i++ {
			api.AssertIsEqual(sgBytes[i], sigBytes[i])
		}*/

	// Verify global public key
	keccak256 := NewKeccak256(api)
	exactConsensus := keccak256.Compute(pubBytes)
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
	blsVerify.Verify(api, &hash, &sig, &pk)

	//最后检查外部hash1==current hash
	//最后检查外部hash2==parent hash
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
