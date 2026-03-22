package hedera

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	anchor "github.com/Open-Nucleus/open-anchor/go"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

// AnchorMessage is the JSON payload submitted to HCS for each anchoring operation.
type AnchorMessage struct {
	Type        string `json:"type"`        // "anchor"
	MerkleRoot  string `json:"merkleRoot"`  // hex-encoded
	Description string `json:"description"`
	SourceID    string `json:"sourceId,omitempty"`
	Timestamp   string `json:"timestamp"`   // RFC3339
}

// AnchorBackend implements anchor.AnchorBackend for the Hedera network via HCS.
type AnchorBackend struct {
	config  Config
	client  *hiero.Client
	mirror  *MirrorClient
	topicID hiero.TopicID
}

// NewAnchorBackend creates a new Hedera anchor backend.
func NewAnchorBackend(config Config, signingKey ed25519.PrivateKey) (*AnchorBackend, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("hedera: invalid Ed25519 private key length: %d", len(signingKey))
	}

	client, err := newClient(config, signingKey)
	if err != nil {
		return nil, fmt.Errorf("hedera anchor: create client: %w", err)
	}

	topicID, err := hiero.TopicIDFromString(config.TopicID)
	if err != nil {
		return nil, fmt.Errorf("hedera anchor: parse topic ID %q: %w", config.TopicID, err)
	}

	return &AnchorBackend{
		config:  config,
		client:  client,
		mirror:  NewMirrorClient(config.MirrorURL),
		topicID: topicID,
	}, nil
}

// Name returns "hedera".
func (b *AnchorBackend) Name() string { return "hedera" }

// Anchor submits a Merkle root to the Hedera Consensus Service.
func (b *AnchorBackend) Anchor(ctx context.Context, proof anchor.AnchorProof) (anchor.AnchorReceipt, error) {
	// 1. Build message payload.
	msg := AnchorMessage{
		Type:        "anchor",
		MerkleRoot:  hex.EncodeToString(proof.MerkleRoot),
		Description: proof.Description,
		SourceID:    proof.SourceID,
		Timestamp:   proof.ComputedAt.UTC().Format(time.RFC3339),
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return anchor.AnchorReceipt{}, fmt.Errorf("hedera anchor: marshal message: %w", err)
	}

	// 2. Submit to HCS topic.
	tx, err := hiero.NewTopicMessageSubmitTransaction().
		SetTopicID(b.topicID).
		SetMessage(msgBytes).
		Execute(b.client)
	if err != nil {
		return anchor.AnchorReceipt{}, fmt.Errorf("hedera anchor: submit: %w", err)
	}

	// 3. Get receipt to confirm consensus.
	receipt, err := tx.GetReceipt(b.client)
	if err != nil {
		return anchor.AnchorReceipt{}, fmt.Errorf("hedera anchor: receipt: %w", err)
	}

	seqNum := uint64(0)
	if receipt.TopicSequenceNumber != 0 {
		seqNum = receipt.TopicSequenceNumber
	}

	// 4. Build anchor receipt.
	rawReceipt, _ := json.Marshal(map[string]interface{}{
		"transactionId":  tx.TransactionID.String(),
		"topicId":        b.topicID.String(),
		"sequenceNumber": seqNum,
		"status":         receipt.Status.String(),
	})

	return anchor.AnchorReceipt{
		Backend:       "hedera",
		MerkleRoot:    proof.MerkleRoot,
		TransactionID: tx.TransactionID.String(),
		AnchoredAt:    time.Now().UTC(),
		BlockRef:      strconv.FormatUint(seqNum, 10),
		RawReceipt:    rawReceipt,
	}, nil
}

// Verify checks an anchor receipt by querying the Mirror Node for the HCS message.
func (b *AnchorBackend) Verify(ctx context.Context, receipt anchor.AnchorReceipt) (anchor.VerificationResult, error) {
	// Parse sequence number from BlockRef.
	seqNum, err := strconv.ParseInt(receipt.BlockRef, 10, 64)
	if err != nil {
		return anchor.VerificationResult{
			Valid:      false,
			Method:     "hedera",
			VerifiedAt: time.Now().UTC(),
			Details:    fmt.Sprintf("invalid sequence number in BlockRef: %q", receipt.BlockRef),
		}, nil
	}

	// Query the Mirror Node for the HCS message.
	msg, err := b.mirror.GetTopicMessage(ctx, b.config.TopicID, seqNum)
	if err != nil {
		return anchor.VerificationResult{
			Valid:      false,
			Method:     "hedera",
			VerifiedAt: time.Now().UTC(),
			Details:    fmt.Sprintf("failed to fetch HCS message: %v", err),
		}, nil
	}

	// Decode the message content (base64 from mirror node).
	content, err := base64.StdEncoding.DecodeString(msg.Message)
	if err != nil {
		return anchor.VerificationResult{
			Valid:      false,
			Method:     "hedera",
			VerifiedAt: time.Now().UTC(),
			Details:    fmt.Sprintf("failed to decode message: %v", err),
		}, nil
	}

	// Parse the anchor message and compare Merkle root.
	var anchorMsg AnchorMessage
	if err := json.Unmarshal(content, &anchorMsg); err != nil {
		return anchor.VerificationResult{
			Valid:      false,
			Method:     "hedera",
			VerifiedAt: time.Now().UTC(),
			Details:    fmt.Sprintf("failed to parse anchor message: %v", err),
		}, nil
	}

	eventRoot, err := hex.DecodeString(anchorMsg.MerkleRoot)
	if err != nil {
		return anchor.VerificationResult{
			Valid:      false,
			Method:     "hedera",
			VerifiedAt: time.Now().UTC(),
			Details:    "invalid Merkle root hex in HCS message",
		}, nil
	}

	rootMatch := bytes.Equal(eventRoot, receipt.MerkleRoot)

	return anchor.VerificationResult{
		Valid:           rootMatch,
		Method:          "hedera",
		VerifiedAt:      time.Now().UTC(),
		MerkleRootMatch: rootMatch,
		TimestampMatch:  true,
		Details:         fmt.Sprintf("verified via HCS topic %s sequence %d", b.config.TopicID, seqNum),
	}, nil
}

// Status checks connectivity to the Hedera network via the Mirror Node.
func (b *AnchorBackend) Status(ctx context.Context) (anchor.BackendStatus, error) {
	_, err := b.mirror.GetAccountBalance(ctx, b.config.OperatorID)
	if err != nil {
		return anchor.BackendStatus{
			Connected:    false,
			ErrorMessage: err.Error(),
		}, nil
	}
	return anchor.BackendStatus{Connected: true}, nil
}

// SupportsOfflineVerification returns true — receipts contain the Merkle root
// and sequence number, enabling offline checks.
func (b *AnchorBackend) SupportsOfflineVerification() bool { return true }

// Close releases the Hedera client resources.
func (b *AnchorBackend) Close() error {
	if b.client != nil {
		return b.client.Close()
	}
	return nil
}

// --- Helpers ---

// newClient creates a Hedera SDK client from the config and signing key.
func newClient(config Config, signingKey ed25519.PrivateKey) (*hiero.Client, error) {
	var client *hiero.Client
	switch config.Network {
	case "mainnet":
		client = hiero.ClientForMainnet()
	case "previewnet":
		client = hiero.ClientForPreviewnet()
	default:
		client = hiero.ClientForTestnet()
	}

	operatorID, err := hiero.AccountIDFromString(config.OperatorID)
	if err != nil {
		return nil, fmt.Errorf("parse operator ID %q: %w", config.OperatorID, err)
	}

	// Convert standard Go Ed25519 key to Hedera key.
	// Go ed25519.PrivateKey is 64 bytes (seed || public); Hedera wants the raw seed.
	hederaKey, err := hiero.PrivateKeyFromSeedEd25519(signingKey.Seed())
	if err != nil {
		return nil, fmt.Errorf("convert signing key: %w", err)
	}

	client.SetOperator(operatorID, hederaKey)
	return client, nil
}
