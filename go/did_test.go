package anchor_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	anchor "github.com/Open-Nucleus/open-anchor/go"
	"github.com/Open-Nucleus/open-anchor/go/backends/didkey"
)

func TestIdentityEngine_CreateDID_DidKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	engine := anchor.NewIdentityEngine(didkey.New())
	doc, err := engine.CreateDID(context.Background(), "key", pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatalf("CreateDID: %v", err)
	}
	if doc.ID == "" {
		t.Error("DID ID is empty")
	}
	if len(doc.VerificationMethod) == 0 {
		t.Error("no verification methods")
	}
}

func TestIdentityEngine_ResolveDID_DidKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	engine := anchor.NewIdentityEngine(didkey.New())
	doc, err := engine.CreateDID(context.Background(), "key", pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatalf("CreateDID: %v", err)
	}

	resolved, err := engine.ResolveDID(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("ResolveDID: %v", err)
	}
	if resolved.ID != doc.ID {
		t.Errorf("resolved ID = %q, want %q", resolved.ID, doc.ID)
	}
}

func TestIdentityEngine_ResolveDID_Cache(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	engine := anchor.NewIdentityEngine(didkey.New())
	doc, _ := engine.CreateDID(context.Background(), "key", pub, anchor.DIDOptions{})

	// First resolve caches it (CreateDID already caches).
	// Second resolve should hit cache.
	resolved, err := engine.ResolveDID(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("ResolveDID from cache: %v", err)
	}
	if resolved.ID != doc.ID {
		t.Error("cache miss")
	}
}

func TestIdentityEngine_ResolveDID_UnsupportedMethod(t *testing.T) {
	engine := anchor.NewIdentityEngine(didkey.New())
	_, err := engine.ResolveDID(context.Background(), "did:web:example.com")
	if err == nil {
		t.Error("expected error for unsupported method")
	}
}

// mockDIDBackend simulates a network-dependent DID backend.
type mockDIDBackend struct {
	name      string
	methodStr string
	docs      map[string]*anchor.DIDDocument
	available bool
}

func (m *mockDIDBackend) Name() string   { return m.name }
func (m *mockDIDBackend) Method() string { return m.methodStr }

func (m *mockDIDBackend) Create(_ context.Context, pub ed25519.PublicKey, _ anchor.DIDOptions) (*anchor.DIDDocument, error) {
	did := "did:" + m.name + ":test123"
	doc := &anchor.DIDDocument{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      did,
		VerificationMethod: []anchor.VerificationMethod{
			{
				ID:                 did + "#keys-1",
				Type:               "Ed25519VerificationKey2020",
				Controller:         did,
				PublicKeyMultibase: anchor.PublicKeyToMultibase(pub),
			},
		},
		Authentication:  []string{did + "#keys-1"},
		AssertionMethod: []string{did + "#keys-1"},
	}
	m.docs[did] = doc
	return doc, nil
}

func (m *mockDIDBackend) Resolve(_ context.Context, did string) (*anchor.DIDDocument, error) {
	if !m.available {
		return nil, errors.New("network unavailable")
	}
	doc, ok := m.docs[did]
	if !ok {
		return nil, errors.New("DID not found")
	}
	return doc, nil
}

func (m *mockDIDBackend) Update(_ context.Context, _ string, _ anchor.DIDUpdate, _ ed25519.PrivateKey) (*anchor.DIDDocument, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDIDBackend) Deactivate(_ context.Context, _ string, _ ed25519.PrivateKey) error {
	return errors.New("not implemented")
}

func (m *mockDIDBackend) RequiresNetwork() bool { return true }

func TestIdentityEngine_ResolveDID_StaleCacheFallback(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	mock := &mockDIDBackend{
		name:      "test",
		methodStr: "did:test",
		docs:      make(map[string]*anchor.DIDDocument),
		available: true,
	}

	engine := anchor.NewIdentityEngine(didkey.New(), mock)

	// Create while network is available.
	doc, err := engine.CreateDID(context.Background(), "test", pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatalf("CreateDID: %v", err)
	}

	// Clear cache to force network resolution.
	engine.ClearCache(doc.ID)

	// Resolve goes to network, populates stale cache.
	resolved, err := engine.ResolveDID(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("ResolveDID (online): %v", err)
	}
	if resolved.ID != doc.ID {
		t.Error("resolved ID mismatch")
	}

	// Network goes down, clear main cache.
	mock.available = false
	engine.ClearCache(doc.ID)

	// Should fall back to stale cache.
	resolved, err = engine.ResolveDID(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("ResolveDID (stale fallback): %v", err)
	}
	if resolved.ID != doc.ID {
		t.Error("stale cache resolution failed")
	}
}
