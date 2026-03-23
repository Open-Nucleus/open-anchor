package hedera

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

// CredentialMetadata is the on-chain metadata for a practitioner credential NFT.
type CredentialMetadata struct {
	Type           string `json:"type"`
	PractitionerID string `json:"practitioner_id"`
	Role           string `json:"role"`
	SiteID         string `json:"site_id"`
	IssuedAt       string `json:"issued_at"`
	IssuerDID      string `json:"issuer_did,omitempty"`
}

// NFTInfo holds details about a minted NFT.
type NFTInfo struct {
	TokenID      string             `json:"token_id"`
	SerialNumber int64              `json:"serial_number"`
	Metadata     CredentialMetadata `json:"metadata"`
}

// TokenService provides HTS (Hedera Token Service) operations for
// practitioner credential NFTs.
type TokenService struct {
	client  *hiero.Client
	network string
}

// NewTokenService creates a new HTS token service.
func NewTokenService(config Config, signingKey ed25519.PrivateKey) (*TokenService, error) {
	client, err := newClient(config, signingKey)
	if err != nil {
		return nil, fmt.Errorf("hedera token service: create client: %w", err)
	}
	return &TokenService{client: client, network: config.Network}, nil
}

// CreateNFTCollection creates an HTS NFT token type for practitioner credentials.
// Returns the Token ID string (e.g., "0.0.12345").
func (ts *TokenService) CreateNFTCollection(ctx context.Context, name, symbol string) (string, error) {
	operatorID := ts.client.GetOperatorAccountID()
	operatorKey := ts.client.GetOperatorPublicKey()

	tx, err := hiero.NewTokenCreateTransaction().
		SetTokenName(name).
		SetTokenSymbol(symbol).
		SetTokenType(hiero.TokenTypeNonFungibleUnique).
		SetDecimals(0).
		SetInitialSupply(0).
		SetTreasuryAccountID(operatorID).
		SetSupplyKey(operatorKey).
		SetAdminKey(operatorKey).
		SetTokenMemo("Open Nucleus Practitioner Credentials").
		Execute(ts.client)
	if err != nil {
		return "", fmt.Errorf("create NFT collection: %w", err)
	}

	receipt, err := tx.GetReceipt(ts.client)
	if err != nil {
		return "", fmt.Errorf("create NFT collection receipt: %w", err)
	}

	if receipt.TokenID == nil {
		return "", fmt.Errorf("create NFT collection: no token ID in receipt")
	}

	return receipt.TokenID.String(), nil
}

// MintCredentialNFT mints a single NFT with practitioner credential metadata.
// Returns the serial number of the minted NFT.
func (ts *TokenService) MintCredentialNFT(ctx context.Context, tokenIDStr string, metadata CredentialMetadata) (int64, error) {
	tokenID, err := hiero.TokenIDFromString(tokenIDStr)
	if err != nil {
		return 0, fmt.Errorf("parse token ID: %w", err)
	}

	// Set issued timestamp if not set
	if metadata.IssuedAt == "" {
		metadata.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("marshal metadata: %w", err)
	}

	tx, err := hiero.NewTokenMintTransaction().
		SetTokenID(tokenID).
		SetMetadatas([][]byte{metadataBytes}).
		Execute(ts.client)
	if err != nil {
		return 0, fmt.Errorf("mint NFT: %w", err)
	}

	receipt, err := tx.GetReceipt(ts.client)
	if err != nil {
		return 0, fmt.Errorf("mint NFT receipt: %w", err)
	}

	if len(receipt.SerialNumbers) == 0 {
		return 0, fmt.Errorf("mint NFT: no serial numbers in receipt")
	}

	return receipt.SerialNumbers[0], nil
}

// Close releases the Hedera client resources.
func (ts *TokenService) Close() error {
	if ts.client != nil {
		return ts.client.Close()
	}
	return nil
}
