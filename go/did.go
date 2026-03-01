package anchor

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
)

// DIDBackend is the interface for decentralised identity operations.
type DIDBackend interface {
	// Name returns the DID method name (e.g. "key", "iota", "hedera").
	Name() string

	// Method returns the full DID method prefix (e.g. "did:key", "did:iota").
	Method() string

	// Create generates a new DID from an Ed25519 public key.
	Create(ctx context.Context, publicKey ed25519.PublicKey, opts DIDOptions) (*DIDDocument, error)

	// Resolve fetches and returns the DID Document for a given DID string.
	Resolve(ctx context.Context, did string) (*DIDDocument, error)

	// Update modifies an existing DID Document.
	Update(ctx context.Context, did string, updates DIDUpdate, signingKey ed25519.PrivateKey) (*DIDDocument, error)

	// Deactivate marks a DID as deactivated.
	Deactivate(ctx context.Context, did string, signingKey ed25519.PrivateKey) error

	// RequiresNetwork returns true if this method needs connectivity for create/resolve.
	RequiresNetwork() bool
}

// DIDOptions configures DID creation.
type DIDOptions struct {
	Controller     string           `json:"controller,omitempty"`
	Services       []DIDService     `json:"services,omitempty"`
	AdditionalKeys []ed25519.PublicKey `json:"-"`
}

// DIDUpdate describes changes to apply to a DID Document.
type DIDUpdate struct {
	AddServices    []DIDService       `json:"addServices,omitempty"`
	RemoveServices []string           `json:"removeServices,omitempty"`
	AddKeys        []ed25519.PublicKey `json:"-"`
}

// DIDDocument follows the W3C DID Core specification.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	Controller         []string             `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	KeyAgreement       []string             `json:"keyAgreement,omitempty"`
	Service            []DIDService         `json:"service,omitempty"`
	Created            string               `json:"created,omitempty"`
	Updated            string               `json:"updated,omitempty"`
	Deactivated        bool                 `json:"deactivated,omitempty"`
}

// VerificationMethod represents a public key in a DID Document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// DIDService represents a service endpoint in a DID Document.
type DIDService struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// IdentityEngine manages DID operations, credential issuance, and verification.
type IdentityEngine struct {
	backends        map[string]DIDBackend
	cache           map[string]*DIDDocument
	staleCache      map[string]*DIDDocument
	revocationLists map[string]*RevocationList
	mu              sync.RWMutex
}

// NewIdentityEngine creates an identity engine with the specified DID backends.
func NewIdentityEngine(backends ...DIDBackend) *IdentityEngine {
	e := &IdentityEngine{
		backends:        make(map[string]DIDBackend),
		cache:           make(map[string]*DIDDocument),
		staleCache:      make(map[string]*DIDDocument),
		revocationLists: make(map[string]*RevocationList),
	}
	for _, b := range backends {
		e.backends[b.Name()] = b
	}
	return e
}

// CreateDID generates a new DID using the specified method.
func (e *IdentityEngine) CreateDID(ctx context.Context, method string, publicKey ed25519.PublicKey, opts DIDOptions) (*DIDDocument, error) {
	backend, ok := e.backends[method]
	if !ok {
		return nil, fmt.Errorf("unsupported DID method: %s", method)
	}
	doc, err := backend.Create(ctx, publicKey, opts)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	e.cache[doc.ID] = doc
	e.mu.Unlock()

	return doc, nil
}

// ResolveDID resolves any supported DID to its DID Document.
// Resolution follows: cache -> did:key (offline) -> network backend -> stale cache fallback.
func (e *IdentityEngine) ResolveDID(ctx context.Context, did string) (*DIDDocument, error) {
	method := extractMethod(did)

	// 1. Try local cache first.
	e.mu.RLock()
	if doc, ok := e.cache[did]; ok {
		e.mu.RUnlock()
		return doc, nil
	}
	e.mu.RUnlock()

	// 2. If did:key, resolve offline (always works).
	if method == "key" {
		backend, ok := e.backends["key"]
		if !ok {
			return nil, fmt.Errorf("did:key backend not registered")
		}
		doc, err := backend.Resolve(ctx, did)
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		e.cache[did] = doc
		e.mu.Unlock()
		return doc, nil
	}

	// 3. Try the appropriate network backend.
	backend, ok := e.backends[method]
	if !ok {
		return nil, fmt.Errorf("unsupported DID method: %s", method)
	}

	doc, err := backend.Resolve(ctx, did)
	if err != nil {
		// 4. Fall back to stale cache if network unavailable.
		e.mu.RLock()
		if doc, ok := e.staleCache[did]; ok {
			e.mu.RUnlock()
			return doc, nil
		}
		e.mu.RUnlock()
		return nil, err
	}

	// 5. Cache the result.
	e.mu.Lock()
	e.cache[did] = doc
	e.staleCache[did] = doc
	e.mu.Unlock()

	return doc, nil
}

// ClearCache removes a DID from the main cache (but not the stale cache).
// This is exported for testing purposes.
func (e *IdentityEngine) ClearCache(did string) {
	e.mu.Lock()
	delete(e.cache, did)
	e.mu.Unlock()
}

// extractMethod parses "did:method:..." and returns "method".
func extractMethod(did string) string {
	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 || parts[0] != "did" {
		return ""
	}
	return parts[1]
}
