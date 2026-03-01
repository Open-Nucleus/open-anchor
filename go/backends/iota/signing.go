package iota

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// intentPrefix is the 3-byte prefix prepended to transaction bytes before
// signing, per the IOTA/Sui intent-message convention.
// [0x00 = TransactionData, 0x00 = PersonalMessage scope, 0x00 = version 0]
var intentPrefix = []byte{0x00, 0x00, 0x00}

// DeriveAddress computes an IOTA address from an Ed25519 public key.
// The address is Blake2b-256(0x00 || pubkey), hex-encoded with "0x" prefix.
// The 0x00 flag byte indicates Ed25519 key scheme.
func DeriveAddress(pub ed25519.PublicKey) string {
	data := make([]byte, 1+len(pub))
	data[0] = 0x00 // Ed25519 scheme flag
	copy(data[1:], pub)

	hash := blake2b.Sum256(data)
	return "0x" + hex.EncodeToString(hash[:])
}

// SignTransaction signs IOTA transaction bytes using the intent-message
// convention:
//  1. Prepend intent prefix [0x00, 0x00, 0x00] to txBytes
//  2. Blake2b-256 hash the intent message
//  3. Ed25519 sign the 32-byte hash
//  4. Assemble: [0x00] || signature(64) || pubkey(32) = 97 bytes
//  5. Base64-encode and return
func SignTransaction(txBytes []byte, privKey ed25519.PrivateKey) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key length: %d", len(privKey))
	}

	// 1. Build intent message.
	intentMsg := make([]byte, len(intentPrefix)+len(txBytes))
	copy(intentMsg, intentPrefix)
	copy(intentMsg[len(intentPrefix):], txBytes)

	// 2. Blake2b-256 hash.
	hash := blake2b.Sum256(intentMsg)

	// 3. Ed25519 sign the hash.
	sig := ed25519.Sign(privKey, hash[:])

	// 4. Assemble: flag(1) + signature(64) + pubkey(32) = 97 bytes.
	pub := privKey.Public().(ed25519.PublicKey)
	serialized := make([]byte, 1+len(sig)+len(pub))
	serialized[0] = 0x00 // Ed25519 scheme flag
	copy(serialized[1:], sig)
	copy(serialized[1+len(sig):], pub)

	// 5. Base64 encode.
	return base64.StdEncoding.EncodeToString(serialized), nil
}

// ObjectRef is a reference to an on-chain object (ID, version, digest).
type ObjectRef struct {
	ID      string `json:"objectId"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// ParseObjectRef extracts an ObjectRef from an ObjectResponse.
func ParseObjectRef(resp *ObjectResponse) ObjectRef {
	ref := ObjectRef{
		ID: resp.Data.ObjectID,
	}
	if resp.Data.Content != nil {
		ref.Version = resp.Data.Version
		ref.Digest = resp.Data.Digest
	}
	return ref
}
