package anchor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// VerifiablePresentation bundles one or more VCs with a proof from the holder.
type VerifiablePresentation struct {
	Context              []string               `json:"@context"`
	Type                 []string               `json:"type"`
	Holder               string                 `json:"holder"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential"`
	Proof                CredentialProof        `json:"proof"`
}

// PresentationVerification is the result of verifying a VP.
type PresentationVerification struct {
	Valid              bool                      `json:"valid"`
	HolderValid        bool                      `json:"holderValid"`
	CredentialResults  []CredentialVerification  `json:"credentialResults"`
}

// CreatePresentation bundles credentials into a signed presentation.
func (e *IdentityEngine) CreatePresentation(
	ctx context.Context,
	holderDID string,
	holderKey ed25519.PrivateKey,
	credentials []VerifiableCredential,
) (*VerifiablePresentation, error) {
	if len(credentials) == 0 {
		return nil, errors.New("at least one credential is required")
	}

	vp := &VerifiablePresentation{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		Type:                 []string{"VerifiablePresentation"},
		Holder:               holderDID,
		VerifiableCredential: credentials,
	}

	// Resolve holder DID for key reference.
	doc, err := e.ResolveDID(ctx, holderDID)
	if err != nil {
		return nil, fmt.Errorf("resolve holder: %w", err)
	}
	if len(doc.VerificationMethod) == 0 {
		return nil, errors.New("holder has no verification methods")
	}
	keyRef := doc.VerificationMethod[0].ID

	// Canonical JSON of VP (excluding proof).
	canonical, err := canonicalJSON(struct {
		Context              []string               `json:"@context"`
		Type                 []string               `json:"type"`
		Holder               string                 `json:"holder"`
		VerifiableCredential []VerifiableCredential `json:"verifiableCredential"`
	}{
		Context:              vp.Context,
		Type:                 vp.Type,
		Holder:               vp.Holder,
		VerifiableCredential: vp.VerifiableCredential,
	})
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}

	sig := ed25519.Sign(holderKey, canonical)

	vp.Proof = CredentialProof{
		Type:               "Ed25519Signature2020",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: keyRef,
		ProofPurpose:       "authentication",
		ProofValue:         encodeProofValue(sig),
	}

	return vp, nil
}

// VerifyPresentation checks the presentation signature and all embedded credentials.
func (e *IdentityEngine) VerifyPresentation(
	ctx context.Context,
	vp *VerifiablePresentation,
) (*PresentationVerification, error) {
	result := &PresentationVerification{}

	// 1. Resolve holder DID and verify VP signature.
	doc, err := e.ResolveDID(ctx, vp.Holder)
	if err != nil {
		return result, nil
	}
	if len(doc.VerificationMethod) == 0 {
		return result, nil
	}

	pubKey, err := decodePublicKeyMultibase(doc.VerificationMethod[0].PublicKeyMultibase)
	if err != nil {
		return result, nil
	}

	canonical, err := canonicalJSON(struct {
		Context              []string               `json:"@context"`
		Type                 []string               `json:"type"`
		Holder               string                 `json:"holder"`
		VerifiableCredential []VerifiableCredential `json:"verifiableCredential"`
	}{
		Context:              vp.Context,
		Type:                 vp.Type,
		Holder:               vp.Holder,
		VerifiableCredential: vp.VerifiableCredential,
	})
	if err != nil {
		return result, nil
	}

	sig, err := decodeProofValue(vp.Proof.ProofValue)
	if err != nil {
		return result, nil
	}

	result.HolderValid = ed25519.Verify(pubKey, canonical, sig)

	// 2. Verify each embedded credential.
	allValid := result.HolderValid
	for i := range vp.VerifiableCredential {
		vcResult, err := e.VerifyCredential(ctx, &vp.VerifiableCredential[i])
		if err != nil {
			result.CredentialResults = append(result.CredentialResults, CredentialVerification{})
			allValid = false
			continue
		}
		result.CredentialResults = append(result.CredentialResults, *vcResult)
		if !vcResult.Valid {
			allValid = false
		}
	}

	result.Valid = allValid
	return result, nil
}
