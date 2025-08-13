package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/nspcc-dev/neo-go/pkg/core/interop/interopnames"
	"github.com/nspcc-dev/neo-go/pkg/vm/opcode"
	"slices"
)

type MultiSigVerifyWrapper[T, S emulated.FieldParams] struct {
	Hash               [32]uints.U8
	PubKeys            []ecdsa.PublicKey[T, S]
	MappingRules       []frontend.Variable
	VerificationScript []uints.U8
	InvocationScript   []uints.U8
}

// Define declares the circuit's constraints
func (c *MultiSigVerifyWrapper[T, S]) Define(api frontend.API) error {
	verifyer := NewMultiSigVerify[T, S](api)
	verifyer.Verify(c.PubKeys, c.Hash, c.VerificationScript, c.InvocationScript, c.MappingRules)
	return nil
}

func NewMultiSigVerify[T, S emulated.FieldParams](api frontend.API) MultiSigVerify[T, S] {
	return MultiSigVerify[T, S]{api: api}
}

type MultiSigVerify[T, S emulated.FieldParams] struct {
	api frontend.API
}

func (multiSigVerify *MultiSigVerify[T, S]) CheckPubKeyFormat(pubsPoint ecdsa.PublicKey[T, S], pubs []frontend.Variable) {
	api := multiSigVerify.api
	cr, err := sw_emulated.New[T, S](api, sw_emulated.GetCurveParams[T]())
	if err != nil {
		panic(err)
	}
	field, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}
	//check pubKey format
	cr.AssertIsOnCurve((*sw_emulated.AffinePoint[T])(&pubsPoint))
	xBits := field.ToBits(&pubsPoint.X)
	yBits := field.ToBits(&pubsPoint.Y)
	pubReverseBytes := make([]frontend.Variable, len(pubs))
	for j := 0; j < len(pubReverseBytes); j++ {
		index := len(pubReverseBytes) - 1 - j
		pubReverseBytes[j] = pubs[index]
	}
	var pubReverseXBits []frontend.Variable
	for j := 0; j < len(pubReverseBytes)-1; j++ {
		tempBits := bits.ToBinary(api, pubReverseBytes[j], bits.WithNbDigits(8))
		pubReverseXBits = append(pubReverseXBits, tempBits...)
	}
	for j := range xBits {
		api.AssertIsEqual(pubReverseXBits[j], xBits[j])
	}
	api.AssertIsEqual(len(pubReverseXBits), len(xBits))
	//calculate first byte(compressed)=0x02 or0x03
	compressByte := pubs[0]
	twoBits := bits.ToBinary(api, byte(2), bits.WithNbDigits(8))
	compressedBits := make([]frontend.Variable, len(twoBits))
	for z := range twoBits {
		compressedBits[z] = api.Select(api.IsZero(z), api.Or(twoBits[z], yBits[0]), twoBits[z])
	}
	compressed := bits.FromBinary(api, compressedBits, bits.WithNbDigits(8))
	api.AssertIsEqual(compressed, compressByte)
}

func (multiSigVerify *MultiSigVerify[T, S]) Verify(pubsPoint []ecdsa.PublicKey[T, S], hash [32]uints.U8, VerificationScript []uints.U8, InvocationScript []uints.U8, mappingRules []frontend.Variable) {
	api := multiSigVerify.api
	pubCount := len(pubsPoint)
	sigCount := len(mappingRules)
	u32api, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	//VerificationScript>=7*PublicKeyDataLen+7;InvocationScript>=5*SignatureDataLen
	api.AssertIsLessOrEqual(frontend.Variable(pubCount*PublicKeyDataLen+7), frontend.Variable(len(VerificationScript)))
	api.AssertIsLessOrEqual(frontend.Variable(sigCount*SignatureDataLen), frontend.Variable(len(InvocationScript)))
	// Content verification
	// Verification script, need to analyze the script outside
	// Ref https://github.com/nspcc-dev/neo-go/blob/1436de45bfbe44b5e60710dafb117b647adddb24/pkg/smartcontract/contract.go#L16
	api.AssertIsEqual(VerificationScript[0].Val, frontend.Variable(byte(opcode.PUSH5)))
	pubs := make([][]uints.U8, pubCount)
	for i := 0; i < pubCount; i++ {
		api.AssertIsEqual(VerificationScript[i*PublicKeyDataLen+1].Val, frontend.Variable(byte(opcode.PUSHDATA1)))
		// Key length
		api.AssertIsEqual(VerificationScript[i*PublicKeyDataLen+2].Val, frontend.Variable(byte(PublickeyLen)))
		// Key data
		pubs[i] = VerificationScript[i*PublicKeyDataLen+3 : (i+1)*PublicKeyDataLen+1]
		pubU8s := make([]frontend.Variable, len(pubs[i]))
		for j := 0; j < len(pubs[i]); j++ {
			pubU8s[j] = pubs[i][j].Val
		}
		multiSigVerify.CheckPubKeyFormat(pubsPoint[i], pubU8s)
	}
	// Check the exact pubkey array length
	api.AssertIsEqual(VerificationScript[pubCount*PublicKeyDataLen+1].Val, frontend.Variable(byte(opcode.PUSH7)))
	// Check the syscall
	api.AssertIsEqual(VerificationScript[pubCount*PublicKeyDataLen+2].Val, frontend.Variable(byte(opcode.SYSCALL)))
	// Check interop ID
	interID := uints.NewU32(interopnames.ToID([]byte(interopnames.SystemCryptoCheckMultisig)))
	vinterID := u32api.PackLSB(VerificationScript[pubCount*PublicKeyDataLen+3 : pubCount*PublicKeyDataLen+7]...)
	u32api.AssertEq(vinterID, interID)
	// Invocation script, need to analyze the script outside
	// Ref https://github.com/nspcc-dev/neo-go/blob/1436de45bfbe44b5e60710dafb117b647adddb24/internal/testchain/address.go#L129
	field, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}
	frField, err := emulated.NewField[S](api)
	if err != nil {
		panic(err)
	}
	for i := 0; i < sigCount; i++ {
		api.AssertIsEqual(InvocationScript[i*SignatureDataLen].Val, frontend.Variable(byte(opcode.PUSHDATA1)))
		// Sig length
		api.AssertIsEqual(InvocationScript[i*SignatureDataLen+1].Val, frontend.Variable(byte(SignatureLen)))
		// Sig data
		signature := InvocationScript[i*SignatureDataLen+2 : (i+1)*SignatureDataLen]
		// [65] = [R | S | 0/1], we take the first 64 byte(R/S)
		RE, SE := signature[:32], signature[32:64]
		transformToFrElement := func(item [32]uints.U8) *emulated.Element[S] {
			slices.Reverse(item[:])
			bits := make([]frontend.Variable, 0)
			for i := 0; i < len(item); i++ {
				bits = append(bits, api.ToBinary(item[i].Val, 8)...)
			}
			return frField.FromBits(bits...)

		}
		sig := ecdsa.Signature[S]{
			R: *transformToFrElement([32]uints.U8(RE)),
			S: *transformToFrElement([32]uints.U8(SE)),
		}
		// select the public key corresponding to the signature
		selectorXbits := make([]frontend.Variable, len(field.ToBits(&pubsPoint[0].X)))
		selectorYbits := make([]frontend.Variable, len(field.ToBits(&pubsPoint[0].Y)))
		//init selector
		for k := 0; k < len(selectorXbits); k++ {
			selectorXbits[k] = frontend.Variable(byte(0))
		}
		for k := 0; k < len(selectorYbits); k++ {
			selectorYbits[k] = frontend.Variable(byte(0))
		}
		for j := 0; j < len(pubsPoint); j++ {
			x := pubsPoint[j].X
			y := pubsPoint[j].Y
			xBits := field.ToBits(&x)
			yBits := field.ToBits(&y)
			selector := api.IsZero(api.Cmp(mappingRules[i], frontend.Variable(j)))
			for k := 0; k < len(xBits); k++ {
				selectorXbits[k] = api.Add(selectorXbits[k], api.Mul(selector, xBits[k]))
			}
			for k := 0; k < len(yBits); k++ {
				selectorYbits[k] = api.Add(selectorYbits[k], api.Mul(selector, yBits[k]))
			}
		}
		selectorX := field.FromBits(selectorXbits...)
		selectorY := field.FromBits(selectorYbits...)
		selectPk := ecdsa.PublicKey[T, S]{X: *selectorX, Y: *selectorY}
		selectPk.Verify(api, sw_emulated.GetCurveParams[T](), transformToFrElement(hash), &sig)
	}
}
