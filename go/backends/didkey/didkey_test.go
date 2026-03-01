package didkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	anchor "github.com/Open-Nucleus/open-anchor/go"
)

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func TestCreate_Format(t *testing.T) {
	pub, _ := generateTestKey(t)
	b := New()

	doc, err := b.Create(context.Background(), pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !strings.HasPrefix(doc.ID, "did:key:z6Mk") {
		t.Errorf("DID = %q, want prefix did:key:z6Mk", doc.ID)
	}
}

func TestResolve_Roundtrip(t *testing.T) {
	pub, _ := generateTestKey(t)
	b := New()

	doc, err := b.Create(context.Background(), pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	resolved, err := b.Resolve(context.Background(), doc.ID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Extract public key from the resolved document.
	resolvedPub, err := anchor.PublicKeyFromMultibase(resolved.VerificationMethod[0].PublicKeyMultibase)
	if err != nil {
		t.Fatalf("decode resolved key: %v", err)
	}

	if !bytes.Equal(pub, resolvedPub) {
		t.Error("resolved public key does not match original")
	}
}

func TestResolve_InvalidDID(t *testing.T) {
	b := New()
	ctx := context.Background()

	tests := []struct {
		name string
		did  string
	}{
		{"empty", ""},
		{"no prefix", "z6Mkf5rGMoatrSj1f"},
		{"wrong method", "did:web:example.com"},
		{"no z prefix", "did:key:6Mkf5rGMoatrSj1f"},
		{"invalid base58", "did:key:z!!!invalid!!!"},
		{"wrong multicodec", "did:key:z2J"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.Resolve(ctx, tc.did)
			if err == nil {
				t.Errorf("Resolve(%q) should have returned error", tc.did)
			}
		})
	}
}

func TestDIDDocument_W3CCompliance(t *testing.T) {
	pub, _ := generateTestKey(t)
	b := New()

	doc, err := b.Create(context.Background(), pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Check @context.
	if len(doc.Context) != 2 {
		t.Fatalf("expected 2 contexts, got %d", len(doc.Context))
	}
	if doc.Context[0] != "https://www.w3.org/ns/did/v1" {
		t.Errorf("context[0] = %q", doc.Context[0])
	}
	if doc.Context[1] != "https://w3id.org/security/suites/ed25519-2020/v1" {
		t.Errorf("context[1] = %q", doc.Context[1])
	}

	// Check verificationMethod.
	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("expected 1 verification method, got %d", len(doc.VerificationMethod))
	}
	vm := doc.VerificationMethod[0]
	if vm.Type != "Ed25519VerificationKey2020" {
		t.Errorf("type = %q", vm.Type)
	}
	if !strings.HasSuffix(vm.ID, "#keys-1") {
		t.Errorf("ID = %q, want suffix #keys-1", vm.ID)
	}
	if vm.Controller != doc.ID {
		t.Errorf("controller = %q, want %q", vm.Controller, doc.ID)
	}

	// Check authentication refs.
	if len(doc.Authentication) != 1 || doc.Authentication[0] != vm.ID {
		t.Errorf("authentication = %v", doc.Authentication)
	}

	// Check assertionMethod refs.
	if len(doc.AssertionMethod) != 1 || doc.AssertionMethod[0] != vm.ID {
		t.Errorf("assertionMethod = %v", doc.AssertionMethod)
	}
}

func TestDIDDocument_WithServices(t *testing.T) {
	pub, _ := generateTestKey(t)
	b := New()

	opts := anchor.DIDOptions{
		Services: []anchor.DIDService{
			{
				ID:              "#open-nucleus-node",
				Type:            "OpenNucleusNode",
				ServiceEndpoint: "nucleus://node-sheffield-01",
			},
		},
	}

	doc, err := b.Create(context.Background(), pub, opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if len(doc.Service) != 1 {
		t.Fatalf("expected 1 service, got %d", len(doc.Service))
	}
	if doc.Service[0].Type != "OpenNucleusNode" {
		t.Errorf("service type = %q", doc.Service[0].Type)
	}
}

func TestUpdate_ReturnsError(t *testing.T) {
	b := New()
	_, err := b.Update(context.Background(), "did:key:z6Mk...", anchor.DIDUpdate{}, nil)
	if err != ErrImmutableDID {
		t.Errorf("Update error = %v, want ErrImmutableDID", err)
	}
}

func TestDeactivate_ReturnsError(t *testing.T) {
	b := New()
	err := b.Deactivate(context.Background(), "did:key:z6Mk...", nil)
	if err != ErrImmutableDID {
		t.Errorf("Deactivate error = %v, want ErrImmutableDID", err)
	}
}

func TestRequiresNetwork_False(t *testing.T) {
	b := New()
	if b.RequiresNetwork() {
		t.Error("did:key should not require network")
	}
}
