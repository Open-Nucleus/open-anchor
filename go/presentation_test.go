package anchor_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	anchor "github.com/Open-Nucleus/open-anchor/go"
	"github.com/Open-Nucleus/open-anchor/go/backends/didkey"
)

func TestCreatePresentation_SingleVC(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	// Create a holder.
	holderPub, holderPriv, _ := ed25519.GenerateKey(nil)
	holderDoc, err := engine.CreateDID(context.Background(), "key", holderPub, anchor.DIDOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Issue a credential to the holder.
	claims := anchor.CredentialClaims{
		Type:    []string{"VerifiableCredential", anchor.CredTypePractitionerLicense},
		Subject: map[string]interface{}{"id": holderDoc.ID, "name": "Dr Test"},
	}
	vc, err := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}

	// Create a presentation.
	vp, err := engine.CreatePresentation(context.Background(), holderDoc.ID, holderPriv, []anchor.VerifiableCredential{*vc})
	if err != nil {
		t.Fatalf("CreatePresentation: %v", err)
	}

	if vp.Holder != holderDoc.ID {
		t.Errorf("holder = %q", vp.Holder)
	}
	if len(vp.VerifiableCredential) != 1 {
		t.Errorf("credentials count = %d", len(vp.VerifiableCredential))
	}
	if vp.Proof.Type != "Ed25519Signature2020" {
		t.Errorf("proof type = %q", vp.Proof.Type)
	}
}

func TestCreatePresentation_MultipleVCs(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	holderPub, holderPriv, _ := ed25519.GenerateKey(nil)
	holderDoc, _ := engine.CreateDID(context.Background(), "key", holderPub, anchor.DIDOptions{})

	var creds []anchor.VerifiableCredential
	for i := 0; i < 3; i++ {
		claims := anchor.CredentialClaims{
			Type:    []string{"VerifiableCredential"},
			Subject: map[string]interface{}{"id": holderDoc.ID},
		}
		vc, err := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		creds = append(creds, *vc)
	}

	vp, err := engine.CreatePresentation(context.Background(), holderDoc.ID, holderPriv, creds)
	if err != nil {
		t.Fatalf("CreatePresentation: %v", err)
	}
	if len(vp.VerifiableCredential) != 3 {
		t.Errorf("credentials count = %d, want 3", len(vp.VerifiableCredential))
	}
}

func TestVerifyPresentation_Valid(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	holderPub, holderPriv, _ := ed25519.GenerateKey(nil)
	holderDoc, _ := engine.CreateDID(context.Background(), "key", holderPub, anchor.DIDOptions{})

	claims := anchor.CredentialClaims{
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": holderDoc.ID},
	}
	vc, _ := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
	vp, _ := engine.CreatePresentation(context.Background(), holderDoc.ID, holderPriv, []anchor.VerifiableCredential{*vc})

	result, err := engine.VerifyPresentation(context.Background(), vp)
	if err != nil {
		t.Fatalf("VerifyPresentation: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid presentation")
	}
	if !result.HolderValid {
		t.Error("expected valid holder signature")
	}
	if len(result.CredentialResults) != 1 {
		t.Fatalf("credential results count = %d", len(result.CredentialResults))
	}
	if !result.CredentialResults[0].Valid {
		t.Error("expected valid embedded credential")
	}
}

func TestVerifyPresentation_InvalidHolderSignature(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	holderPub, holderPriv, _ := ed25519.GenerateKey(nil)
	holderDoc, _ := engine.CreateDID(context.Background(), "key", holderPub, anchor.DIDOptions{})

	// Create a second key pair (attacker).
	_, attackerPriv, _ := ed25519.GenerateKey(nil)

	claims := anchor.CredentialClaims{
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": holderDoc.ID},
	}
	vc, _ := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)

	// Sign the VP with the wrong key.
	_ = holderPriv
	vp, _ := engine.CreatePresentation(context.Background(), holderDoc.ID, attackerPriv, []anchor.VerifiableCredential{*vc})

	result, err := engine.VerifyPresentation(context.Background(), vp)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Error("expected invalid presentation (wrong holder key)")
	}
	if result.HolderValid {
		t.Error("expected invalid holder signature")
	}
}

func TestVerifyPresentation_OneInvalidVC(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	holderPub, holderPriv, _ := ed25519.GenerateKey(nil)
	holderDoc, _ := engine.CreateDID(context.Background(), "key", holderPub, anchor.DIDOptions{})

	// Issue a valid credential.
	validClaims := anchor.CredentialClaims{
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": holderDoc.ID},
	}
	validVC, _ := engine.IssueCredential(context.Background(), issuerDID, issuerKey, validClaims)

	// Issue and then tamper with a second credential.
	tamperedClaims := anchor.CredentialClaims{
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": holderDoc.ID, "name": "Original"},
	}
	tamperedVC, _ := engine.IssueCredential(context.Background(), issuerDID, issuerKey, tamperedClaims)
	tamperedVC.Subject["name"] = "Tampered"

	vp, _ := engine.CreatePresentation(context.Background(), holderDoc.ID, holderPriv, []anchor.VerifiableCredential{*validVC, *tamperedVC})

	result, err := engine.VerifyPresentation(context.Background(), vp)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Error("expected invalid presentation (one invalid VC)")
	}
}

func TestFullOfflineFlow(t *testing.T) {
	engine := anchor.NewIdentityEngine(didkey.New())
	ctx := context.Background()

	// 1. Create issuer DID.
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(nil)
	issuerDoc, err := engine.CreateDID(ctx, "key", issuerPub, anchor.DIDOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Create holder DID.
	holderPub, holderPriv, _ := ed25519.GenerateKey(nil)
	holderDoc, err := engine.CreateDID(ctx, "key", holderPub, anchor.DIDOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Issue credential.
	claims := anchor.CredentialClaims{
		Type: []string{"VerifiableCredential", anchor.CredTypePractitionerLicense},
		Subject: map[string]interface{}{
			"id":        holderDoc.ID,
			"name":      "Dr Test",
			"license":   "TEST/2026/001",
			"specialty": "Paediatrics",
		},
	}
	vc, err := engine.IssueCredential(ctx, issuerDoc.ID, issuerPriv, claims)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Verify credential.
	vcResult, err := engine.VerifyCredential(ctx, vc)
	if err != nil {
		t.Fatal(err)
	}
	if !vcResult.Valid {
		t.Error("credential should be valid")
	}

	// 5. Create presentation.
	vp, err := engine.CreatePresentation(ctx, holderDoc.ID, holderPriv, []anchor.VerifiableCredential{*vc})
	if err != nil {
		t.Fatal(err)
	}

	// 6. Verify presentation.
	vpResult, err := engine.VerifyPresentation(ctx, vp)
	if err != nil {
		t.Fatal(err)
	}
	if !vpResult.Valid {
		t.Error("presentation should be valid")
	}
	if !vpResult.HolderValid {
		t.Error("holder should be valid")
	}
	if vpResult.CredentialResults[0].ResolutionMethod != "offline" {
		t.Errorf("resolution method = %q, want offline", vpResult.CredentialResults[0].ResolutionMethod)
	}
}
