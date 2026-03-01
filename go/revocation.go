package anchor

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RevocationList is a signed list of revoked credential IDs maintained by an issuer.
type RevocationList struct {
	Issuer    string          `json:"issuer"`
	Revoked   []string        `json:"revoked"`
	UpdatedAt string          `json:"updatedAt"`
	Proof     CredentialProof `json:"proof"`
}

// AddRevocationList verifies and stores a revocation list.
func (e *IdentityEngine) AddRevocationList(list *RevocationList) error {
	if list == nil {
		return errors.New("revocation list is nil")
	}

	// Verify the list signature.
	doc, err := e.ResolveDID(context.Background(), list.Issuer)
	if err != nil {
		return fmt.Errorf("resolve issuer for revocation list: %w", err)
	}

	if len(doc.VerificationMethod) == 0 {
		return errors.New("issuer has no verification methods")
	}

	pubKey, err := decodePublicKeyMultibase(doc.VerificationMethod[0].PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("decode issuer public key: %w", err)
	}

	// Reconstruct the canonical JSON without the proof (must match RevokeCredential signing).
	canonical, err := canonicalJSON(struct {
		Issuer    string   `json:"issuer"`
		Revoked   []string `json:"revoked"`
		UpdatedAt string   `json:"updatedAt"`
	}{
		Issuer:    list.Issuer,
		Revoked:   list.Revoked,
		UpdatedAt: list.UpdatedAt,
	})
	if err != nil {
		return fmt.Errorf("canonical JSON: %w", err)
	}

	sig, err := decodeProofValue(list.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(pubKey, canonical, sig) {
		return errors.New("revocation list signature verification failed")
	}

	e.mu.Lock()
	e.revocationLists[list.Issuer] = list
	e.mu.Unlock()

	return nil
}

// RevokeCredential adds a credential ID to the issuer's revocation list.
func (e *IdentityEngine) RevokeCredential(ctx context.Context, issuerDID string, issuerKey ed25519.PrivateKey, credentialID string) (*RevocationList, error) {
	e.mu.Lock()
	list, ok := e.revocationLists[issuerDID]
	if !ok {
		list = &RevocationList{
			Issuer:  issuerDID,
			Revoked: []string{},
		}
	}

	// Check if already revoked.
	for _, id := range list.Revoked {
		if id == credentialID {
			e.mu.Unlock()
			return list, nil
		}
	}

	list.Revoked = append(list.Revoked, credentialID)
	list.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	list.Proof = CredentialProof{} // Clear old proof.
	e.mu.Unlock()

	// Sign the updated list.
	canonical, err := canonicalJSON(struct {
		Issuer    string   `json:"issuer"`
		Revoked   []string `json:"revoked"`
		UpdatedAt string   `json:"updatedAt"`
	}{
		Issuer:    list.Issuer,
		Revoked:   list.Revoked,
		UpdatedAt: list.UpdatedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}

	sig := ed25519.Sign(issuerKey, canonical)

	doc, err := e.ResolveDID(ctx, issuerDID)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer: %w", err)
	}

	keyRef := doc.VerificationMethod[0].ID

	list.Proof = CredentialProof{
		Type:               "Ed25519Signature2020",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: keyRef,
		ProofPurpose:       "assertionMethod",
		ProofValue:         encodeProofValue(sig),
	}

	e.mu.Lock()
	e.revocationLists[issuerDID] = list
	e.mu.Unlock()

	return list, nil
}

// isRevoked checks whether a credential has been revoked by its issuer.
func (e *IdentityEngine) isRevoked(vc *VerifiableCredential) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list, ok := e.revocationLists[vc.Issuer]
	if !ok {
		return false
	}
	for _, id := range list.Revoked {
		if id == vc.ID {
			return true
		}
	}
	return false
}

// canonicalJSON marshals v to sorted-key JSON.
func canonicalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
