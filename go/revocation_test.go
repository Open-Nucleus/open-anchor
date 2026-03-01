package anchor_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	anchor "github.com/Open-Nucleus/open-anchor/go"
	"github.com/Open-Nucleus/open-anchor/go/backends/didkey"
)

func TestRevokeCredential(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	engine := anchor.NewIdentityEngine(didkey.New())
	ctx := context.Background()

	doc, err := engine.CreateDID(ctx, "key", pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatal(err)
	}

	list, err := engine.RevokeCredential(ctx, doc.ID, priv, "urn:test:cred-1")
	if err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	if list.Issuer != doc.ID {
		t.Errorf("issuer = %q", list.Issuer)
	}
	if len(list.Revoked) != 1 || list.Revoked[0] != "urn:test:cred-1" {
		t.Errorf("revoked = %v", list.Revoked)
	}
	if list.Proof.Type != "Ed25519Signature2020" {
		t.Errorf("proof type = %q", list.Proof.Type)
	}
}

func TestIsRevoked_True(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	engine := anchor.NewIdentityEngine(didkey.New())
	ctx := context.Background()

	doc, _ := engine.CreateDID(ctx, "key", pub, anchor.DIDOptions{})

	// Issue a credential with an ID.
	claims := anchor.CredentialClaims{
		ID:      "urn:test:cred-revoke",
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": "did:key:zTest"},
	}
	vc, err := engine.IssueCredential(ctx, doc.ID, priv, claims)
	if err != nil {
		t.Fatal(err)
	}

	// Revoke it.
	_, err = engine.RevokeCredential(ctx, doc.ID, priv, "urn:test:cred-revoke")
	if err != nil {
		t.Fatal(err)
	}

	// Verify should show revoked.
	result, err := engine.VerifyCredential(ctx, vc)
	if err != nil {
		t.Fatal(err)
	}
	if result.NotRevoked {
		t.Error("expected credential to be revoked")
	}
	if result.Valid {
		t.Error("expected invalid credential")
	}
}

func TestIsRevoked_False(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	engine := anchor.NewIdentityEngine(didkey.New())
	ctx := context.Background()

	doc, _ := engine.CreateDID(ctx, "key", pub, anchor.DIDOptions{})

	// Issue credential without revoking it.
	claims := anchor.CredentialClaims{
		ID:      "urn:test:cred-ok",
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": "did:key:zTest"},
	}
	vc, _ := engine.IssueCredential(ctx, doc.ID, priv, claims)

	result, _ := engine.VerifyCredential(ctx, vc)
	if !result.NotRevoked {
		t.Error("expected credential to NOT be revoked")
	}
}

func TestIsRevoked_NoListAvailable(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	engine := anchor.NewIdentityEngine(didkey.New())
	ctx := context.Background()

	doc, _ := engine.CreateDID(ctx, "key", pub, anchor.DIDOptions{})

	// Issue credential — no revocation list exists for this issuer.
	claims := anchor.CredentialClaims{
		ID:      "urn:test:cred-nolist",
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": "did:key:zTest"},
	}
	vc, _ := engine.IssueCredential(ctx, doc.ID, priv, claims)

	result, _ := engine.VerifyCredential(ctx, vc)
	if !result.NotRevoked {
		t.Error("expected not revoked when no revocation list exists")
	}
}

func TestRevocationList_SignatureVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	engine := anchor.NewIdentityEngine(didkey.New())
	ctx := context.Background()

	doc, _ := engine.CreateDID(ctx, "key", pub, anchor.DIDOptions{})

	// Revoke a credential (this creates a signed revocation list).
	list, err := engine.RevokeCredential(ctx, doc.ID, priv, "urn:test:cred-sig")
	if err != nil {
		t.Fatal(err)
	}

	// Create a new engine and add the revocation list (it should verify the signature).
	engine2 := anchor.NewIdentityEngine(didkey.New())
	err = engine2.AddRevocationList(list)
	if err != nil {
		t.Fatalf("AddRevocationList: %v", err)
	}

	// Issue a credential as if from the same issuer and check revocation.
	claims := anchor.CredentialClaims{
		ID:      "urn:test:cred-sig",
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": "did:key:zTest"},
	}
	vc, _ := engine2.IssueCredential(ctx, doc.ID, priv, claims)

	result, _ := engine2.VerifyCredential(ctx, vc)
	if result.NotRevoked {
		t.Error("expected credential to be revoked in engine2")
	}
}
