package circuit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
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
