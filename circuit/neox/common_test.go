package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

type CompressHeaderWrapper struct {
	Header         HeaderParameters
	CompressHeader CompressHeaderParameters
}

func (c *CompressHeaderWrapper) Define(api frontend.API) error {
	noSigHeader, err := c.Header.NoSigHeader()
	if err != nil {
		return err
	}
	compress := noSigHeader.Compress(api)
	fmt.Println(111, len(compress.Serialize()))
	fmt.Println(222, len(c.CompressHeader.Serialize()))
	r := compress.Decompressed(api)
	assertIsSame := func(a []frontend.Variable, b []frontend.Variable) {
		api.AssertIsEqual(len(a), len(b))
		for i := 0; i < len(a); i++ {
			api.AssertIsEqual(a[i], b[i])
		}
	}
	check := func(h HeaderParameters, recov HeaderParameters) {
		assertIsSame(h.ParentHash[:], recov.ParentHash[:])
		assertIsSame(h.UncleHash[:], recov.UncleHash[:])
		assertIsSame(h.Coinbase[:], recov.Coinbase[:])
		assertIsSame(h.Root[:], recov.Root[:])
		assertIsSame(h.ReceiptHash[:], recov.ReceiptHash[:])
		assertIsSame(h.TxHash[:], recov.TxHash[:])
		assertIsSame(h.Bloom[:], recov.Bloom[:])
		assertIsSame(h.Difficulty[:], recov.Difficulty[:])
		assertIsSame(h.GasLimit[:], recov.GasLimit[:])
		assertIsSame(h.GasUsed[:], recov.GasUsed[:])
		assertIsSame(h.Nonce[:], recov.Nonce[:])
		assertIsSame(h.Number[:], recov.Number[:])
		assertIsSame(h.Time[:], recov.Time[:])
		assertIsSame(h.Extra[:], recov.Extra[:])

		assertIsSame(h.MixDigest[:], recov.MixDigest[:])
		assertIsSame(h.BaseFee[:], recov.BaseFee[:])
		assertIsSame(h.WithdrawalsHash[:], recov.WithdrawalsHash[:])
		api.AssertIsEqual(c.Header.hashableExtraLen, recov.hashableExtraLen)
	}
	check(noSigHeader, r)
	fromCompressR := c.CompressHeader.Decompressed(api)
	fromCompressNoSig, err := fromCompressR.NoSigHeader()
	if err != nil {
		return err
	}
	check(noSigHeader, fromCompressNoSig)
	return nil
}

func TestCompressCircuit(t *testing.T) {
	parent, _ := HeaderTestData(ExtraV1)
	h := NewNeoxBlockHeader(parent)
	header, err := h.ToHeaderParameter()
	assert.NoError(t, err)
	noSig, err := header.NoSigHeader()
	assert.NoError(t, err)
	compressHeader, err := h.ToCompressedHeaderParameters()
	assert.NoError(t, err)
	fmt.Println(333, len(compressHeader.Extra.Variables), compressHeader.Extra.Length)
	circuit := CompressHeaderWrapper{Header: noSig, CompressHeader: compressHeader}
	assignment := CompressHeaderWrapper{Header: noSig, CompressHeader: compressHeader}
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(t, err)
}
