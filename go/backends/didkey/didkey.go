// Package didkey implements the did:key DID method for Ed25519 keys.
// Resolution is instant and requires no network access — the public key
// is encoded directly in the DID string.
package didkey

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	anchor "github.com/Open-Nucleus/open-anchor/go"
	"github.com/Open-Nucleus/open-anchor/go/internal/base58"
)

var (
	// ErrImmutableDID is returned when attempting to update or deactivate a did:key.
	ErrImmutableDID = errors.New("did:key is immutable and cannot be updated or deactivated")
)

// Backend implements the DIDBackend interface for did:key.
type Backend struct{}

// New creates a new did:key backend.
func New() *Backend {
	return &Backend{}
}

// Name returns the DID method name.
func (b *Backend) Name() string { return "key" }

// Method returns the full DID method prefix.
func (b *Backend) Method() string { return "did:key" }

// Create generates a did:key from an Ed25519 public key.
func (b *Backend) Create(ctx context.Context, pub ed25519.PublicKey, opts anchor.DIDOptions) (*anchor.DIDDocument, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(pub))
	}

	did := encodeDID(pub)
	return buildDIDDocument(did, pub, opts), nil
}

// Resolve parses the public key from the DID string and builds a DID Document.
func (b *Backend) Resolve(ctx context.Context, did string) (*anchor.DIDDocument, error) {
	pub, err := decodeDID(did)
	if err != nil {
		return nil, err
	}
	return buildDIDDocument(did, pub, anchor.DIDOptions{}), nil
}

// Update returns ErrImmutableDID — did:key identifiers cannot be updated.
func (b *Backend) Update(ctx context.Context, did string, updates anchor.DIDUpdate, signingKey ed25519.PrivateKey) (*anchor.DIDDocument, error) {
	return nil, ErrImmutableDID
}

// Deactivate returns ErrImmutableDID — did:key identifiers cannot be deactivated.
func (b *Backend) Deactivate(ctx context.Context, did string, signingKey ed25519.PrivateKey) error {
	return ErrImmutableDID
}

// RequiresNetwork returns false — did:key is fully offline.
func (b *Backend) RequiresNetwork() bool { return false }

// encodeDID creates a "did:key:z6Mk..." string from an Ed25519 public key.
func encodeDID(pub ed25519.PublicKey) string {
	// Multicodec prefix for Ed25519: 0xed, 0x01
	data := make([]byte, 2+len(pub))
	data[0] = 0xed
	data[1] = 0x01
	copy(data[2:], pub)

	// Multibase encode: base58btc with 'z' prefix.
	return "did:key:z" + base58.Encode(data)
}

// decodeDID extracts the Ed25519 public key from a "did:key:z..." string.
func decodeDID(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, "did:key:z") {
		return nil, fmt.Errorf("invalid did:key format: %q", did)
	}

	// Strip "did:key:z" prefix.
	encoded := did[len("did:key:z"):]
	decoded := base58.Decode(encoded)
	if decoded == nil {
		return nil, fmt.Errorf("invalid base58 in did:key: %q", did)
	}

	// Verify and strip multicodec prefix.
	if len(decoded) < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("invalid multicodec prefix in did:key: %q", did)
	}

	pub := decoded[2:]
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 key length in did:key: %d", len(pub))
	}

	return ed25519.PublicKey(pub), nil
}

// buildDIDDocument constructs a W3C-compliant DID Document.
func buildDIDDocument(did string, pub ed25519.PublicKey, opts anchor.DIDOptions) *anchor.DIDDocument {
	keyID := did + "#keys-1"
	multibase := anchor.PublicKeyToMultibase(pub)

	controller := did
	if opts.Controller != "" {
		controller = opts.Controller
	}

	doc := &anchor.DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: did,
		VerificationMethod: []anchor.VerificationMethod{
			{
				ID:                 keyID,
				Type:               "Ed25519VerificationKey2020",
				Controller:         controller,
				PublicKeyMultibase: multibase,
			},
		},
		Authentication:  []string{keyID},
		AssertionMethod: []string{keyID},
	}

	if opts.Controller != "" {
		doc.Controller = []string{opts.Controller}
	}

	if len(opts.Services) > 0 {
		doc.Service = opts.Services
	}

	return doc
}
