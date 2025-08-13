package verifier

import (
	"crypto/elliptic"
	"encoding/binary"

	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/nspcc-dev/neo-go/pkg/core/interop/interopnames"
	"github.com/nspcc-dev/neo-go/pkg/crypto/hash"
	"github.com/nspcc-dev/neo-go/pkg/vm"
	"github.com/nspcc-dev/neo-go/pkg/vm/opcode"
)

const (
	PublickeyLen     = 33               // Length of public key in bytes.
	SignatureLen     = 64               // Length of signature in bytes.
	PublicKeyDataLen = PublickeyLen + 2 // Length of public key data in script (PUSHDATA1 + key length + public key).
	SignatureDataLen = SignatureLen + 2 // Length of signature data in script (PUSHDATA1 + signature length + signature).
)

func VerifyUpdateHeader(parent, current *block.Header, network uint32) bool {
	if current.PrevHash != parent.Hash() {
		return false
	}
	if current.Index != parent.Index+1 {
		return false
	}
	if current.Timestamp <= parent.Timestamp {
		return false
	}
	// Format verification
	expectedConsensus := parent.NextConsensus
	exactConsensus := current.Script
	if exactConsensus.ScriptHash() != expectedConsensus {
		return false
	}
	if len(exactConsensus.VerificationScript) < 7*PublicKeyDataLen+7 {
		return false
	}
	if len(exactConsensus.InvocationScript) < 5*SignatureDataLen {
		return false
	}
	// Content verification
	// Verification script, need to analyze the script outside
	// Ref https://github.com/nspcc-dev/neo-go/blob/1436de45bfbe44b5e60710dafb117b647adddb24/pkg/smartcontract/contract.go#L16
	if exactConsensus.VerificationScript[0] != byte(opcode.PUSH5) {
		return false
	}
	pubs := make([][]byte, 7)
	for i := 0; i < 7; i++ {
		if exactConsensus.VerificationScript[i*PublicKeyDataLen+1] != byte(opcode.PUSHDATA1) {
			return false
		}
		// Key length
		if exactConsensus.VerificationScript[i*PublicKeyDataLen+2] != byte(PublickeyLen) {
			return false
		}
		// Key data
		pubs[i] = exactConsensus.VerificationScript[i*PublicKeyDataLen+3 : (i+1)*PublicKeyDataLen+1]
	}
	// Check the exact pubkey array length
	if exactConsensus.VerificationScript[7*PublicKeyDataLen+1] != byte(opcode.PUSH7) {
		return false
	}
	// Check the syscall
	if exactConsensus.VerificationScript[7*PublicKeyDataLen+2] != byte(opcode.SYSCALL) {
		return false
	}
	if binary.LittleEndian.Uint32(exactConsensus.VerificationScript[7*PublicKeyDataLen+3:7*PublicKeyDataLen+7]) != interopnames.ToID([]byte(interopnames.SystemCryptoCheckMultisig)) {
		return false
	}
	// Invocation script, need to analyze the script outside
	// Ref https://github.com/nspcc-dev/neo-go/blob/1436de45bfbe44b5e60710dafb117b647adddb24/internal/testchain/address.go#L129
	sigs := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		if exactConsensus.InvocationScript[i*SignatureDataLen] != byte(opcode.PUSHDATA1) {
			return false
		}
		// Sig length
		if exactConsensus.InvocationScript[i*SignatureDataLen+1] != byte(SignatureLen) {
			return false
		}
		// Sig data
		sigs[i] = exactConsensus.InvocationScript[i*SignatureDataLen+2 : (i+1)*SignatureDataLen]
	}
	// Check multi-sigs
	return vm.CheckMultisigPar(elliptic.P256(), hash.NetSha256(network, current).BytesBE(), pubs, sigs)
}
