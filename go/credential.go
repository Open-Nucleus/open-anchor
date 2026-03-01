package anchor

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/Open-Nucleus/open-anchor/go/internal/base58"
)

// Healthcare credential type constants.
const (
	CredTypePractitionerLicense  = "PractitionerLicenseCredential"
	CredTypePractitionerRole     = "PractitionerRoleCredential"
	CredTypeDataIntegrity        = "DataIntegrityCredential"
	CredTypeAuditTrail           = "AuditTrailCredential"
	CredTypeAuthorisedDeployment = "AuthorisedDeploymentCredential"
	CredTypeSiteAccreditation    = "SiteAccreditationCredential"
	CredTypePatientConsent       = "PatientConsentCredential"
	CredTypeImmunisationRecord   = "ImmunisationRecordCredential"
)

// CredentialClaims represents the claims in a Verifiable Credential.
type CredentialClaims struct {
	Context        []string               `json:"@context"`
	ID             string                 `json:"id,omitempty"`
	Type           []string               `json:"type"`
	Issuer         string                 `json:"issuer"`
	IssuanceDate   string                 `json:"issuanceDate"`
	ExpirationDate string                 `json:"expirationDate,omitempty"`
	Subject        map[string]interface{} `json:"credentialSubject"`
}

// VerifiableCredential is a signed credential.
type VerifiableCredential struct {
	Context        []string               `json:"@context"`
	ID             string                 `json:"id,omitempty"`
	Type           []string               `json:"type"`
	Issuer         string                 `json:"issuer"`
	IssuanceDate   string                 `json:"issuanceDate"`
	ExpirationDate string                 `json:"expirationDate,omitempty"`
	Subject        map[string]interface{} `json:"credentialSubject"`
	Proof          CredentialProof        `json:"proof"`
}

// CredentialProof is the Ed25519Signature2020 proof block.
type CredentialProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

// CredentialVerification is the result of verifying a VC.
type CredentialVerification struct {
	Valid            bool   `json:"valid"`
	SignatureValid   bool   `json:"signatureValid"`
	NotExpired       bool   `json:"notExpired"`
	NotRevoked       bool   `json:"notRevoked"`
	IssuerResolved   bool   `json:"issuerResolved"`
	ResolutionMethod string `json:"resolutionMethod"`
}

// IssueCredential creates a signed Verifiable Credential.
func (e *IdentityEngine) IssueCredential(
	ctx context.Context,
	issuerDID string,
	issuerKey ed25519.PrivateKey,
	claims CredentialClaims,
) (*VerifiableCredential, error) {
	// Set defaults.
	if len(claims.Context) == 0 {
		claims.Context = []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://open-nucleus.dev/credentials/v1",
		}
	}
	if len(claims.Type) == 0 {
		claims.Type = []string{"VerifiableCredential"}
	}

	claims.Issuer = issuerDID
	claims.IssuanceDate = time.Now().UTC().Format(time.RFC3339)

	// Resolve the issuer DID to get the key reference.
	doc, err := e.ResolveDID(ctx, issuerDID)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer: %w", err)
	}
	if len(doc.VerificationMethod) == 0 {
		return nil, errors.New("issuer has no verification methods")
	}
	keyRef := doc.VerificationMethod[0].ID

	// Build the VC without proof for signing.
	vc := &VerifiableCredential{
		Context:        claims.Context,
		ID:             claims.ID,
		Type:           claims.Type,
		Issuer:         claims.Issuer,
		IssuanceDate:   claims.IssuanceDate,
		ExpirationDate: claims.ExpirationDate,
		Subject:        claims.Subject,
	}

	// Create canonical JSON of the VC (without proof).
	canonical, err := canonicalJSON(struct {
		Context        []string               `json:"@context"`
		ID             string                 `json:"id,omitempty"`
		Type           []string               `json:"type"`
		Issuer         string                 `json:"issuer"`
		IssuanceDate   string                 `json:"issuanceDate"`
		ExpirationDate string                 `json:"expirationDate,omitempty"`
		Subject        map[string]interface{} `json:"credentialSubject"`
	}{
		Context:        vc.Context,
		ID:             vc.ID,
		Type:           vc.Type,
		Issuer:         vc.Issuer,
		IssuanceDate:   vc.IssuanceDate,
		ExpirationDate: vc.ExpirationDate,
		Subject:        vc.Subject,
	})
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}

	sig := ed25519.Sign(issuerKey, canonical)

	vc.Proof = CredentialProof{
		Type:               "Ed25519Signature2020",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: keyRef,
		ProofPurpose:       "assertionMethod",
		ProofValue:         encodeProofValue(sig),
	}

	return vc, nil
}

// VerifyCredential checks the signature and validity of a VC.
func (e *IdentityEngine) VerifyCredential(
	ctx context.Context,
	vc *VerifiableCredential,
) (*CredentialVerification, error) {
	result := &CredentialVerification{}

	// 1. Resolve the issuer's DID.
	doc, err := e.ResolveDID(ctx, vc.Issuer)
	if err != nil {
		return result, nil
	}
	result.IssuerResolved = true

	// Determine resolution method.
	method := extractMethod(vc.Issuer)
	if method == "key" {
		result.ResolutionMethod = "offline"
	} else {
		result.ResolutionMethod = "network"
	}

	if len(doc.VerificationMethod) == 0 {
		return result, nil
	}

	// 2. Verify the Ed25519 signature.
	pubKey, err := decodePublicKeyMultibase(doc.VerificationMethod[0].PublicKeyMultibase)
	if err != nil {
		return result, nil
	}

	canonical, err := canonicalJSON(struct {
		Context        []string               `json:"@context"`
		ID             string                 `json:"id,omitempty"`
		Type           []string               `json:"type"`
		Issuer         string                 `json:"issuer"`
		IssuanceDate   string                 `json:"issuanceDate"`
		ExpirationDate string                 `json:"expirationDate,omitempty"`
		Subject        map[string]interface{} `json:"credentialSubject"`
	}{
		Context:        vc.Context,
		ID:             vc.ID,
		Type:           vc.Type,
		Issuer:         vc.Issuer,
		IssuanceDate:   vc.IssuanceDate,
		ExpirationDate: vc.ExpirationDate,
		Subject:        vc.Subject,
	})
	if err != nil {
		return result, nil
	}

	sig, err := decodeProofValue(vc.Proof.ProofValue)
	if err != nil {
		return result, nil
	}

	result.SignatureValid = ed25519.Verify(pubKey, canonical, sig)

	// 3. Check expiration.
	result.NotExpired = true
	if vc.ExpirationDate != "" {
		expiry, err := time.Parse(time.RFC3339, vc.ExpirationDate)
		if err == nil && time.Now().After(expiry) {
			result.NotExpired = false
		}
	}

	// 4. Check revocation.
	result.NotRevoked = !e.isRevoked(vc)

	result.Valid = result.SignatureValid && result.NotExpired && result.NotRevoked
	return result, nil
}

// decodePublicKeyMultibase decodes a multibase (base58btc) encoded Ed25519 public key.
func decodePublicKeyMultibase(multibase string) (ed25519.PublicKey, error) {
	if len(multibase) == 0 {
		return nil, errors.New("empty multibase key")
	}
	if multibase[0] != 'z' {
		return nil, fmt.Errorf("unsupported multibase prefix: %c", multibase[0])
	}
	decoded := base58.Decode(multibase[1:])
	if decoded == nil {
		return nil, errors.New("invalid base58 encoding")
	}
	// Strip the multicodec Ed25519 prefix (0xed, 0x01).
	if len(decoded) < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, errors.New("invalid multicodec prefix for Ed25519")
	}
	pubKey := decoded[2:]
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(pubKey))
	}
	return ed25519.PublicKey(pubKey), nil
}

// encodeProofValue encodes a signature as a base64 string.
func encodeProofValue(sig []byte) string {
	return base64.StdEncoding.EncodeToString(sig)
}

// decodeProofValue decodes a base64-encoded signature.
func decodeProofValue(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}


// encodePublicKeyMultibase encodes an Ed25519 public key as multibase (base58btc).
func encodePublicKeyMultibase(pub ed25519.PublicKey) string {
	// Prepend multicodec Ed25519 prefix: 0xed, 0x01
	data := make([]byte, 2+len(pub))
	data[0] = 0xed
	data[1] = 0x01
	copy(data[2:], pub)
	return "z" + base58.Encode(data)
}

// PublicKeyFromMultibase extracts an Ed25519 public key from a multibase string.
// Exported for use by backend packages.
func PublicKeyFromMultibase(multibase string) (ed25519.PublicKey, error) {
	return decodePublicKeyMultibase(multibase)
}

// PublicKeyToMultibase encodes an Ed25519 public key as a multibase string.
// Exported for use by backend packages.
func PublicKeyToMultibase(pub ed25519.PublicKey) string {
	return encodePublicKeyMultibase(pub)
}

