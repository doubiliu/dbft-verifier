package n3

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/ripemd160"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

type HeaderVerifier struct {
	api frontend.API
}

func (hv *HeaderVerifier) Verify(parent, current HeaderParameters, parentHash []uints.U8, currentHash []uints.U8, pubsPoint []ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], mappingRules []frontend.Variable, network uints.U32) {
	api := hv.api
	u32api, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	u64api, err := uints.New[uints.U64](api)
	if err != nil {
		panic(err)
	}
	encoder := NewHeaderEncoder(api)
	pParentHash, err := encoder.Encode(parent)
	if err != nil {
		panic(err)
	}
	pCurrentHash, err := encoder.Encode(current)
	if err != nil {
		panic(err)
	}
	//check parentHash=pParentHash,currentHash=pCurrentHash
	for i := 0; i < len(pParentHash); i++ {
		api.AssertIsEqual(pParentHash[i].Val, parentHash[i].Val)
	}
	for i := 0; i < len(pCurrentHash); i++ {
		api.AssertIsEqual(pCurrentHash[i].Val, currentHash[i].Val)
	}
	//check parentHash=current.parentHash
	for i := 0; i < len(pParentHash); i++ {
		api.AssertIsEqual(pParentHash[i].Val, current.PrevHash[i].Val)
	}
	//check current index=parent+1
	pAddOne := u32api.Add(parent.Index, uints.NewU32(1))
	u32api.AssertEq(current.Index, pAddOne)
	//check time ,current.Time should bigger than parent
	pt := u64api.ToValue(parent.Timestamp)
	ct := u64api.ToValue(current.Timestamp)
	cmp := api.Cmp(ct, pt)
	api.AssertIsEqual(cmp, frontend.Variable(1))
	// Format verification
	expectedConsensus := parent.NextConsensus
	VerificationScript := current.VerificationScript
	InvocationScript := current.InvocationScript
	//check exactConsensus.ScriptHash() == expectedConsensus
	sha256Hasher, err := sha2.New(api)
	if err != nil {
		panic(err)
	}
	sha256Hasher.Write(VerificationScript)
	sha256Data := sha256Hasher.Sum()
	ripemd160Hasher, err := ripemd160.New(api)
	if err != nil {
		panic(err)
	}
	ripemd160Hasher.Write(sha256Data)
	r160Data := ripemd160Hasher.Sum()
	for i := 0; i < len(r160Data); i++ {
		api.AssertIsEqual(r160Data[i].Val, expectedConsensus[i].Val)
	}
	//mapping rules can not be duplicated
	hv.CheckDuplicate(mappingRules)
	// verify sigs
	verify := NewMultiSigVerify[emulated.P256Fp, emulated.P256Fr](api)
	verify.Verify(pubsPoint, hv.NetSha256(network, currentHash), VerificationScript, InvocationScript, mappingRules)
}

func (hv *HeaderVerifier) CheckDuplicate(mappingRules []frontend.Variable) {
	api := hv.api
	for i := 0; i < len(mappingRules); i++ {
		for j := i + 1; j < len(mappingRules); j++ {
			api.AssertIsEqual(api.IsZero(api.Cmp(mappingRules[i], mappingRules[j])), frontend.Variable(0))
		}
	}
}

func (hv *HeaderVerifier) NetSha256(net uints.U32, hashData []uints.U8) [32]uints.U8 {
	data := make([]uints.U8, 0)
	data = append(data, net[:]...)
	data = append(data, hashData...)
	sha256Hasher, err := sha2.New(hv.api)
	if err != nil {
		panic(err)
	}
	sha256Hasher.Write(data)
	sha256Data := sha256Hasher.Sum()
	return [32]uints.U8(sha256Data)
}
