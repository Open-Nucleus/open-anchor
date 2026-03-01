package iota

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	anchor "github.com/Open-Nucleus/open-anchor/go"
)

// DIDBackend implements anchor.DIDBackend for the did:iota method on IOTA Rebased.
type DIDBackend struct {
	config        Config
	rpc           *RPCClient
	submitter     ed25519.PrivateKey
	submitterAddr string
}

// NewDIDBackend creates a new did:iota backend.
// The submitterKey is used to pay gas for on-chain transactions and may differ
// from the DID subject's key.
func NewDIDBackend(config Config, submitterKey ed25519.PrivateKey) (*DIDBackend, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if len(submitterKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("iota: invalid Ed25519 private key length: %d", len(submitterKey))
	}

	pub := submitterKey.Public().(ed25519.PublicKey)
	return &DIDBackend{
		config:        config,
		rpc:           NewRPCClient(config.RPCURL),
		submitter:     submitterKey,
		submitterAddr: DeriveAddress(pub),
	}, nil
}

// Name returns the DID method name.
func (b *DIDBackend) Name() string { return "iota" }

// Method returns the full DID method prefix.
func (b *DIDBackend) Method() string { return "did:iota" }

// RequiresNetwork returns true — did:iota requires the IOTA network.
func (b *DIDBackend) RequiresNetwork() bool { return true }

// Create generates a new did:iota DID on the IOTA network.
func (b *DIDBackend) Create(ctx context.Context, publicKey ed25519.PublicKey, opts anchor.DIDOptions) (*anchor.DIDDocument, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("iota did: invalid Ed25519 public key length: %d", len(publicKey))
	}

	// Get a gas coin.
	coins, err := b.rpc.GetCoins(ctx, b.submitterAddr)
	if err != nil {
		return nil, fmt.Errorf("iota did create: get coins: %w", err)
	}
	if len(coins) == 0 {
		return nil, fmt.Errorf("iota did create: no gas coins available for %s", b.submitterAddr)
	}

	// Build a minimal DID Document to store on-chain.
	multibase := anchor.PublicKeyToMultibase(publicKey)
	docPayload := map[string]interface{}{
		"publicKeyMultibase": multibase,
		"keyType":            "Ed25519VerificationKey2020",
	}
	docBytes, err := json.Marshal(docPayload)
	if err != nil {
		return nil, fmt.Errorf("iota did create: marshal doc: %w", err)
	}

	// Build the Move call.
	packageID := b.config.IdentityPackageID
	if packageID == "" {
		packageID = b.config.AnchorPackageID
	}

	txBytes, err := b.rpc.MoveCall(ctx, MoveCallParams{
		Sender:          b.submitterAddr,
		PackageObjectID: packageID,
		Module:          "identity",
		Function:        "create",
		TypeArguments:   []string{},
		Arguments:       []string{string(docBytes)},
		Gas:             coins[0].CoinObjectID,
		GasBudget:       fmt.Sprintf("%d", b.config.GasBudget),
	})
	if err != nil {
		return nil, fmt.Errorf("iota did create: move call: %w", err)
	}

	// Sign and execute.
	signature, err := SignTransaction(txBytes, b.submitter)
	if err != nil {
		return nil, fmt.Errorf("iota did create: sign: %w", err)
	}

	txResp, err := b.rpc.ExecuteTransaction(ctx, txBytes, signature)
	if err != nil {
		return nil, fmt.Errorf("iota did create: execute: %w", err)
	}

	// Extract created object ID from the response.
	objectID, err := extractCreatedObjectID(txResp)
	if err != nil {
		return nil, fmt.Errorf("iota did create: extract object: %w", err)
	}

	// Build the DID string.
	network := b.config.NetworkID
	if network == "" {
		network = "testnet"
	}
	did := fmt.Sprintf("did:iota:%s:%s", network, objectID)

	// Build W3C-compliant DID Document.
	now := time.Now().UTC().Format(time.RFC3339)
	keyID := did + "#keys-1"

	controller := did
	if opts.Controller != "" {
		controller = opts.Controller
	}

	doc := &anchor.DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: did,
		VerificationMethod: []anchor.VerificationMethod{
			{
				ID:                 keyID,
				Type:               "Ed25519VerificationKey2020",
				Controller:         controller,
				PublicKeyMultibase: multibase,
			},
		},
		Authentication:  []string{keyID},
		AssertionMethod: []string{keyID},
		Created:         now,
	}

	if opts.Controller != "" {
		doc.Controller = []string{opts.Controller}
	}
	if len(opts.Services) > 0 {
		doc.Service = opts.Services
	}

	return doc, nil
}

// Resolve fetches a did:iota DID Document from the IOTA network.
func (b *DIDBackend) Resolve(ctx context.Context, did string) (*anchor.DIDDocument, error) {
	objectID, err := parseDIDObjectID(did)
	if err != nil {
		return nil, err
	}

	resp, err := b.rpc.GetObject(ctx, objectID, true)
	if err != nil {
		return nil, fmt.Errorf("iota did resolve: get object: %w", err)
	}

	// Parse the DID Document from the object content.
	doc, err := parseDIDDocumentFromObject(did, resp)
	if err != nil {
		return nil, fmt.Errorf("iota did resolve: parse doc: %w", err)
	}
	return doc, nil
}

// Update modifies an existing did:iota DID Document on the IOTA network.
func (b *DIDBackend) Update(ctx context.Context, did string, updates anchor.DIDUpdate, signingKey ed25519.PrivateKey) (*anchor.DIDDocument, error) {
	objectID, err := parseDIDObjectID(did)
	if err != nil {
		return nil, err
	}

	// Determine the signing address.
	signer := b.submitter
	signerAddr := b.submitterAddr
	if len(signingKey) == ed25519.PrivateKeySize {
		signer = signingKey
		signerAddr = DeriveAddress(signer.Public().(ed25519.PublicKey))
	}

	// Get gas.
	coins, err := b.rpc.GetCoins(ctx, signerAddr)
	if err != nil {
		return nil, fmt.Errorf("iota did update: get coins: %w", err)
	}
	if len(coins) == 0 {
		return nil, fmt.Errorf("iota did update: no gas coins available for %s", signerAddr)
	}

	// Serialize update payload.
	updateBytes, err := json.Marshal(updates)
	if err != nil {
		return nil, fmt.Errorf("iota did update: marshal updates: %w", err)
	}

	packageID := b.config.IdentityPackageID
	if packageID == "" {
		packageID = b.config.AnchorPackageID
	}

	txBytes, err := b.rpc.MoveCall(ctx, MoveCallParams{
		Sender:          signerAddr,
		PackageObjectID: packageID,
		Module:          "identity",
		Function:        "update",
		TypeArguments:   []string{},
		Arguments:       []string{objectID, string(updateBytes)},
		Gas:             coins[0].CoinObjectID,
		GasBudget:       fmt.Sprintf("%d", b.config.GasBudget),
	})
	if err != nil {
		return nil, fmt.Errorf("iota did update: move call: %w", err)
	}

	signature, err := SignTransaction(txBytes, signer)
	if err != nil {
		return nil, fmt.Errorf("iota did update: sign: %w", err)
	}

	_, err = b.rpc.ExecuteTransaction(ctx, txBytes, signature)
	if err != nil {
		return nil, fmt.Errorf("iota did update: execute: %w", err)
	}

	// Re-resolve to get the updated document.
	return b.Resolve(ctx, did)
}

// Deactivate marks a did:iota DID as deactivated on the IOTA network.
func (b *DIDBackend) Deactivate(ctx context.Context, did string, signingKey ed25519.PrivateKey) error {
	objectID, err := parseDIDObjectID(did)
	if err != nil {
		return err
	}

	signer := b.submitter
	signerAddr := b.submitterAddr
	if len(signingKey) == ed25519.PrivateKeySize {
		signer = signingKey
		signerAddr = DeriveAddress(signer.Public().(ed25519.PublicKey))
	}

	coins, err := b.rpc.GetCoins(ctx, signerAddr)
	if err != nil {
		return fmt.Errorf("iota did deactivate: get coins: %w", err)
	}
	if len(coins) == 0 {
		return fmt.Errorf("iota did deactivate: no gas coins available for %s", signerAddr)
	}

	packageID := b.config.IdentityPackageID
	if packageID == "" {
		packageID = b.config.AnchorPackageID
	}

	txBytes, err := b.rpc.MoveCall(ctx, MoveCallParams{
		Sender:          signerAddr,
		PackageObjectID: packageID,
		Module:          "identity",
		Function:        "deactivate",
		TypeArguments:   []string{},
		Arguments:       []string{objectID},
		Gas:             coins[0].CoinObjectID,
		GasBudget:       fmt.Sprintf("%d", b.config.GasBudget),
	})
	if err != nil {
		return fmt.Errorf("iota did deactivate: move call: %w", err)
	}

	signature, err := SignTransaction(txBytes, signer)
	if err != nil {
		return fmt.Errorf("iota did deactivate: sign: %w", err)
	}

	_, err = b.rpc.ExecuteTransaction(ctx, txBytes, signature)
	if err != nil {
		return fmt.Errorf("iota did deactivate: execute: %w", err)
	}
	return nil
}

// --- Helpers ---

// parseDIDObjectID extracts the object ID from a "did:iota:<network>:<objectID>" string.
func parseDIDObjectID(did string) (string, error) {
	if !strings.HasPrefix(did, "did:iota:") {
		return "", fmt.Errorf("invalid did:iota format: %q", did)
	}
	parts := strings.SplitN(did, ":", 4)
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid did:iota format (expected did:iota:<network>:<objectID>): %q", did)
	}
	objectID := parts[3]
	if objectID == "" {
		return "", fmt.Errorf("empty object ID in did:iota: %q", did)
	}
	return objectID, nil
}

// extractCreatedObjectID finds the first created object ID in a transaction response.
func extractCreatedObjectID(txResp *TxResponse) (string, error) {
	// Try objectChanges first.
	if len(txResp.ObjectChanges) > 0 {
		var changes []struct {
			Type     string `json:"type"`
			ObjectID string `json:"objectId"`
		}
		if err := json.Unmarshal(txResp.ObjectChanges, &changes); err == nil {
			for _, c := range changes {
				if c.Type == "created" && c.ObjectID != "" {
					return c.ObjectID, nil
				}
			}
		}
	}

	// Fall back to parsing effects for created objects.
	if len(txResp.Effects) > 0 {
		var effects struct {
			Created []struct {
				Reference struct {
					ObjectID string `json:"objectId"`
				} `json:"reference"`
			} `json:"created"`
		}
		if err := json.Unmarshal(txResp.Effects, &effects); err == nil {
			for _, c := range effects.Created {
				if c.Reference.ObjectID != "" {
					return c.Reference.ObjectID, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no created object found in transaction response")
}

// parseDIDDocumentFromObject builds a DIDDocument from an on-chain object response.
func parseDIDDocumentFromObject(did string, resp *ObjectResponse) (*anchor.DIDDocument, error) {
	if resp.Data.Content == nil {
		return nil, fmt.Errorf("object has no content")
	}

	// Parse the content to extract the stored DID data.
	var content struct {
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(resp.Data.Content, &content); err != nil {
		return nil, fmt.Errorf("unmarshal content: %w", err)
	}

	// Extract public key multibase from the stored fields.
	var multibase string
	if raw, ok := content.Fields["publicKeyMultibase"]; ok {
		json.Unmarshal(raw, &multibase)
	}

	// If we can't find the key in fields, try a flat content parse.
	if multibase == "" {
		var flat struct {
			PublicKeyMultibase string `json:"publicKeyMultibase"`
		}
		if err := json.Unmarshal(resp.Data.Content, &flat); err == nil && flat.PublicKeyMultibase != "" {
			multibase = flat.PublicKeyMultibase
		}
	}

	if multibase == "" {
		return nil, fmt.Errorf("no public key found in object content")
	}

	keyID := did + "#keys-1"
	doc := &anchor.DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: did,
		VerificationMethod: []anchor.VerificationMethod{
			{
				ID:                 keyID,
				Type:               "Ed25519VerificationKey2020",
				Controller:         did,
				PublicKeyMultibase: multibase,
			},
		},
		Authentication:  []string{keyID},
		AssertionMethod: []string{keyID},
	}

	return doc, nil
}
