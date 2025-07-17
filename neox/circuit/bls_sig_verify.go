package circuit

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

func NewBlsSigVerify(api frontend.API) BlsSigVerify {
	return BlsSigVerify{api: api}
}

type BlsSigVerify struct {
	api frontend.API
}

func (blsSigVerify *BlsSigVerify) Verify(api frontend.API, hash *sw_bls12381.G2Affine, sig *sw_bls12381.G2Affine, pub *sw_bls12381.G1Affine) {
	_, _, g1, _ := bls12381.Generators()
	g1.Neg(&g1)
	oneG1 := sw_bls12381.NewG1Affine(g1)
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		panic(err)
	}
	pairing.AssertIsOnG1(pub)
	pairing.AssertIsOnG2(hash)
	pairing.AssertIsOnG2(sig)
	rL, err := pairing.Pair([]*sw_bls12381.G1Affine{pub}, []*sw_bls12381.G2Affine{hash})
	if err != nil {
		panic(err)
	}
	rR, err := pairing.Pair([]*sw_bls12381.G1Affine{&oneG1}, []*sw_bls12381.G2Affine{sig})
	if err != nil {
		panic(err)
	}
	pairing.AssertIsEqual(rL, rR)
}
