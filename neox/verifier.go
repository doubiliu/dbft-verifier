package main

//
//import (
//	"bytes"
//	"errors"
//	"math/big"
//	"sort"
//
//	btc_ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
//	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
//	"github.com/ethereum/go-ethereum/common"
//	"github.com/ethereum/go-ethereum/core/types"
//	"github.com/ethereum/go-ethereum/crypto"
//	"github.com/ethereum/go-ethereum/rlp"
//	"golang.org/x/crypto/sha3"
//)
//
//const (
//	// ExtraV0 is the zero version of block's Extra. Extra of this version includes sorted
//	// list of validators addresses followed by BFT number validators signatures.
//	ExtraV0 byte = 0x00
//	// ExtraV1 is the 1-st version of block's Extra. Extra of this version includes global
//	// TPKE public key followed by aggregated validators' threshold signature.
//	ExtraV1 byte = 0x01
//	// ExtraV2 is the 2-nd version of block's Extra. Extra of this version includes global
//	// TPKE public key followed by aggregated validators' threshold signature compatible
//	// with Ethereum CL.
//	ExtraV2 byte = 0x02
//	// ExtraV1ECDSAScheme denotes fallback ECDSA multisignature block signing scheme
//	// for ExtraV1 extra.
//	ExtraV1ECDSAScheme byte = 0x00
//	// ExtraV1ThresholdScheme denotes primary threshold signature block signing scheme
//	// for ExtraV1 extra.
//	ExtraV1ThresholdScheme byte = 0x01
//	// HashableExtraV0Len is the length of hashable part of block extra data for
//	// ExtraV0 extra version.
//	HashableExtraV0Len = 1
//	// HashableExtraV1Len is the length of hashable part of block extra data for
//	// ExtraV1 extra version.
//	HashableExtraV1Len = 1 + 1 + common.HashLength
//	// BLSPublicKeyLen is the length of global public key for signature verification.
//	BLSPublicKeyLen = bls12381.SizeOfG1AffineCompressed
//	// BLSSignatureLen is the length of block signature.
//	BLSSignatureLen = bls12381.SizeOfG2AffineCompressed
//)
//
//var (
//	BLSDomain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
//)
//
//func VerifyUpdateHeader(parent, current *types.Header) bool {
//	// Check basic
//	if current.ParentHash != parent.Hash() {
//		return false
//	}
//	if current.Number.Cmp(new(big.Int).Add(parent.Number, big.NewInt(1))) != 0 {
//		return false
//	}
//	if current.Time <= parent.Time {
//		return false
//	}
//	expectConsensus := parent.MixDigest
//	if len(current.Extra) < 1 {
//		return false
//	}
//	switch current.Extra[0] {
//	case ExtraV0:
//		// Check format
//		if len(current.Extra) != HashableExtraV0Len+7*common.AddressLength+5*crypto.SignatureLength {
//			return false
//		}
//		// Get CNs and sigs
//		addrBytes := current.Extra[HashableExtraV0Len : HashableExtraV0Len+7*common.AddressLength]
//		sigBytes := current.Extra[HashableExtraV0Len+7*common.AddressLength:]
//		addrs := make([]common.Address, 7)
//		for i := range addrs {
//			copy(addrs[i][:], addrBytes[i*common.AddressLength:(i+1)*common.AddressLength])
//		}
//		sigs := make([][]byte, 5)
//		for i := range sigs {
//			sigs[i] = sigBytes[i*crypto.SignatureLength : (i+1)*crypto.SignatureLength]
//		}
//		// Verify CNs
//		exactConsensus := common.BytesToHash(crypto.Keccak256(addrBytes))
//		if exactConsensus != expectConsensus {
//			return false
//		}
//		// Get seal hash
//		data, err := encodeSigHeader(current)
//		if err != nil {
//			return false
//		}
//		hasher := sha3.NewLegacyKeccak256()
//		hasher.Write(data)
//		// Verify sigs
//		return verifyMultiSigs(hasher.Sum(nil), sigs, addrs)
//	case ExtraV1, ExtraV2:
//		if len(current.Extra) < 2 {
//			return false
//		}
//		switch current.Extra[1] {
//		case ExtraV1ECDSAScheme:
//			// Check format
//			if len(current.Extra) != HashableExtraV1Len+7*common.AddressLength+5*crypto.SignatureLength {
//				return false
//			}
//			// Get CNs and sigs
//			addrBytes := current.Extra[HashableExtraV1Len : HashableExtraV1Len+7*common.AddressLength]
//			sigBytes := current.Extra[HashableExtraV1Len+7*common.AddressLength:]
//			addrs := make([]common.Address, 7)
//			for i := range addrs {
//				copy(addrs[i][:], addrBytes[i*common.AddressLength:(i+1)*common.AddressLength])
//			}
//			sigs := make([][]byte, 5)
//			for i := range sigs {
//				sigs[i] = sigBytes[i*crypto.SignatureLength : (i+1)*crypto.SignatureLength]
//			}
//			// Verify CNs
//			exactConsensus := common.BytesToHash(crypto.Keccak256(addrBytes))
//			if exactConsensus != expectConsensus {
//				return false
//			}
//			// Get seal hash
//			data, err := encodeSigHeader(current)
//			if err != nil {
//				return false
//			}
//			hasher := sha3.NewLegacyKeccak256()
//			hasher.Write(data)
//			// Verify sigs
//			return verifyMultiSigs(hasher.Sum(nil), sigs, addrs)
//		case ExtraV1ThresholdScheme:
//			// Check format
//			if len(current.Extra) != HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen {
//				return false
//			}
//			// Get global public key and sig
//			pubBytes := current.Extra[HashableExtraV1Len : HashableExtraV1Len+BLSPublicKeyLen]
//			sigBytes := current.Extra[HashableExtraV1Len+BLSPublicKeyLen : HashableExtraV1Len+BLSPublicKeyLen+BLSSignatureLen]
//			pk := new(bls12381.G1Affine)
//			_, err := pk.SetBytes(pubBytes)
//			if err != nil {
//				return false
//			}
//			sig := new(bls12381.G2Affine)
//			_, err = sig.SetBytes(sigBytes)
//			if err != nil {
//				return false
//			}
//			// Verify global public key
//			exactConsensus := common.BytesToHash(crypto.Keccak256(pubBytes))
//			if exactConsensus != expectConsensus {
//				return false
//			}
//			// Get seal hash
//			data, err := encodeSigHeader(current)
//			if err != nil {
//				return false
//			}
//			hash, _ := bls12381.HashToG2(data, BLSDomain)
//			// Negate the sig in V1
//			if current.Extra[0] == ExtraV1 {
//				sig.Neg(sig)
//			}
//			// Verify sig
//			return verifyBLSSig(hash, sig, pk)
//		default:
//			return false
//		}
//	default:
//		return false
//	}
//}
//
//func encodeSigHeader(header *types.Header) ([]byte, error) {
//	var hashableExtraLen int
//	switch v := header.Extra[0]; v {
//	case ExtraV0:
//		hashableExtraLen = HashableExtraV0Len
//	case ExtraV1, ExtraV2:
//		hashableExtraLen = HashableExtraV1Len
//	default:
//		return nil, errors.New("unexpected extra version")
//	}
//	enc := []interface{}{
//		header.ParentHash,
//		header.UncleHash,
//		header.Coinbase,
//		header.Root,
//		header.TxHash,
//		header.ReceiptHash,
//		header.Bloom,
//		header.Difficulty,
//		header.Number,
//		header.GasLimit,
//		header.GasUsed,
//		header.Time,
//		header.Extra[:hashableExtraLen], // Yes, this will panic if extra is too short
//		header.MixDigest,
//		header.Nonce,
//	}
//	if header.BaseFee != nil {
//		enc = append(enc, header.BaseFee)
//	}
//	if header.WithdrawalsHash != nil {
//		enc = append(enc, header.WithdrawalsHash)
//	}
//	return rlp.EncodeToBytes(enc)
//}
//
//func verifyMultiSigs(hash []byte, sigs [][]byte, addrs []common.Address) bool {
//	signers := make([]common.Address, len(sigs))
//	for i := range signers {
//		btcsig := make([]byte, crypto.SignatureLength)
//		btcsig[0] = sigs[i][64] + 27
//		copy(btcsig[1:], sigs[i])
//		pub, _, err := btc_ecdsa.RecoverCompact(btcsig, hash)
//		if err != nil {
//			return false
//		}
//		pubBytes := pub.SerializeUncompressed()
//		signers[i] = common.BytesToAddress(crypto.Keccak256(pubBytes[1:])[12:])
//	}
//	sort.Slice(addrs, func(i, j int) bool {
//		return bytes.Compare(addrs[i][:], addrs[j][:]) < 0
//	})
//	var vi int
//	for si := range signers {
//		var match bool
//		for vi < len(addrs) {
//			if addrs[vi] == signers[si] {
//				match = true
//			}
//			vi++
//			if match {
//				break
//			}
//		}
//		if !match {
//			return false
//		}
//	}
//	return true
//}
//
//func verifyBLSSig(hash bls12381.G2Affine, sig *bls12381.G2Affine, pub *bls12381.G1Affine) bool {
//	_, _, g1, _ := bls12381.Generators()
//	g1.Neg(&g1)
//	// e(pk,g2Hash)=e(g1,sig)
//	ok, err := bls12381.PairingCheck([]bls12381.G1Affine{*pub, g1}, []bls12381.G2Affine{hash, *sig})
//	if err != nil {
//		return false
//	}
//	return ok
//}
