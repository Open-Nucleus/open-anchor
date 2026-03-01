package anchor_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	anchor "github.com/Open-Nucleus/open-anchor/go"
	"github.com/Open-Nucleus/open-anchor/go/backends/didkey"
)

func setupCredentialTest(t *testing.T) (*anchor.IdentityEngine, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	engine := anchor.NewIdentityEngine(didkey.New())
	doc, err := engine.CreateDID(context.Background(), "key", pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return engine, doc.ID, priv
}

func TestIssueCredential_ValidSignature(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	claims := anchor.CredentialClaims{
		Type: []string{"VerifiableCredential", anchor.CredTypePractitionerLicense},
		Subject: map[string]interface{}{
			"id":       "did:key:zSubject123",
			"name":     "Dr Test",
			"license":  "TEST/2026/001",
			"specialty": "General",
		},
	}

	vc, err := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
	if err != nil {
		t.Fatalf("IssueCredential: %v", err)
	}

	if vc.Issuer != issuerDID {
		t.Errorf("issuer = %q, want %q", vc.Issuer, issuerDID)
	}
	if vc.Proof.Type != "Ed25519Signature2020" {
		t.Errorf("proof type = %q", vc.Proof.Type)
	}
	if vc.Proof.ProofPurpose != "assertionMethod" {
		t.Errorf("proof purpose = %q", vc.Proof.ProofPurpose)
	}
	if vc.Proof.ProofValue == "" {
		t.Error("proof value is empty")
	}
}

func TestIssueCredential_AllTypes(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	types := []string{
		anchor.CredTypePractitionerLicense,
		anchor.CredTypePractitionerRole,
		anchor.CredTypeDataIntegrity,
		anchor.CredTypeAuditTrail,
		anchor.CredTypeAuthorisedDeployment,
		anchor.CredTypeSiteAccreditation,
		anchor.CredTypePatientConsent,
		anchor.CredTypeImmunisationRecord,
	}

	for _, credType := range types {
		t.Run(credType, func(t *testing.T) {
			claims := anchor.CredentialClaims{
				Type:    []string{"VerifiableCredential", credType},
				Subject: map[string]interface{}{"id": "did:key:zTest"},
			}
			vc, err := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
			if err != nil {
				t.Fatalf("IssueCredential(%s): %v", credType, err)
			}
			if vc.Type[1] != credType {
				t.Errorf("type = %q, want %q", vc.Type[1], credType)
			}
		})
	}
}

func TestVerifyCredential_Valid(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	claims := anchor.CredentialClaims{
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": "did:key:zTest"},
	}

	vc, err := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.VerifyCredential(context.Background(), vc)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid credential")
	}
	if !result.SignatureValid {
		t.Error("expected valid signature")
	}
	if !result.NotExpired {
		t.Error("expected not expired")
	}
	if !result.NotRevoked {
		t.Error("expected not revoked")
	}
	if !result.IssuerResolved {
		t.Error("expected issuer resolved")
	}
	if result.ResolutionMethod != "offline" {
		t.Errorf("resolution method = %q, want offline", result.ResolutionMethod)
	}
}

func TestVerifyCredential_ExpiredCredential(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	claims := anchor.CredentialClaims{
		Type:           []string{"VerifiableCredential"},
		ExpirationDate: time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339),
		Subject:        map[string]interface{}{"id": "did:key:zTest"},
	}

	vc, err := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.VerifyCredential(context.Background(), vc)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Error("expected invalid credential (expired)")
	}
	if result.NotExpired {
		t.Error("expected expired")
	}
}

func TestVerifyCredential_RevokedCredential(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	claims := anchor.CredentialClaims{
		ID:      "urn:test:cred-1",
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": "did:key:zTest"},
	}

	vc, err := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}

	// Revoke the credential.
	_, err = engine.RevokeCredential(context.Background(), issuerDID, issuerKey, "urn:test:cred-1")
	if err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	result, err := engine.VerifyCredential(context.Background(), vc)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Error("expected invalid credential (revoked)")
	}
	if result.NotRevoked {
		t.Error("expected revoked")
	}
}

func TestVerifyCredential_UnknownIssuer(t *testing.T) {
	engine := anchor.NewIdentityEngine(didkey.New())

	vc := &anchor.VerifiableCredential{
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       "did:web:unknown.example.com",
		IssuanceDate: time.Now().UTC().Format(time.RFC3339),
		Subject:      map[string]interface{}{"id": "did:key:zTest"},
		Proof: anchor.CredentialProof{
			Type:               "Ed25519Signature2020",
			Created:            time.Now().UTC().Format(time.RFC3339),
			VerificationMethod: "did:web:unknown.example.com#keys-1",
			ProofPurpose:       "assertionMethod",
			ProofValue:         "invalidbase64==",
		},
	}

	result, err := engine.VerifyCredential(context.Background(), vc)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Error("expected invalid credential (unknown issuer)")
	}
	if result.IssuerResolved {
		t.Error("expected issuer not resolved")
	}
}

func TestVerifyCredential_TamperedPayload(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	claims := anchor.CredentialClaims{
		Type:    []string{"VerifiableCredential"},
		Subject: map[string]interface{}{"id": "did:key:zTest", "name": "Original"},
	}

	vc, err := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the credential subject.
	vc.Subject["name"] = "Tampered"

	result, err := engine.VerifyCredential(context.Background(), vc)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Error("expected invalid credential (tampered)")
	}
	if result.SignatureValid {
		t.Error("expected signature invalid")
	}
}

func TestCredentialJSON_W3CCompliance(t *testing.T) {
	engine, issuerDID, issuerKey := setupCredentialTest(t)

	claims := anchor.CredentialClaims{
		Type: []string{"VerifiableCredential", anchor.CredTypeDataIntegrity},
		Subject: map[string]interface{}{
			"id":   "did:key:zSubject",
			"type": "DataIntegrityProof",
		},
	}

	vc, err := engine.IssueCredential(context.Background(), issuerDID, issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(vc)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	// Check required W3C fields.
	if _, ok := raw["@context"]; !ok {
		t.Error("missing @context")
	}
	if _, ok := raw["type"]; !ok {
		t.Error("missing type")
	}
	if _, ok := raw["issuer"]; !ok {
		t.Error("missing issuer")
	}
	if _, ok := raw["issuanceDate"]; !ok {
		t.Error("missing issuanceDate")
	}
	if _, ok := raw["credentialSubject"]; !ok {
		t.Error("missing credentialSubject")
	}
	if _, ok := raw["proof"]; !ok {
		t.Error("missing proof")
	}

	// Check proof structure.
	proof, ok := raw["proof"].(map[string]interface{})
	if !ok {
		t.Fatal("proof is not an object")
	}
	if proof["type"] != "Ed25519Signature2020" {
		t.Errorf("proof.type = %v", proof["type"])
	}
	if proof["proofPurpose"] != "assertionMethod" {
		t.Errorf("proof.proofPurpose = %v", proof["proofPurpose"])
	}
}
