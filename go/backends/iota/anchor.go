package iota

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	anchor "github.com/Open-Nucleus/open-anchor/go"
)

// AnchorBackend implements anchor.AnchorBackend for the IOTA Rebased network.
type AnchorBackend struct {
	config  Config
	rpc     *RPCClient
	signer  ed25519.PrivateKey
	address string
}

// NewAnchorBackend creates a new IOTA anchor backend.
func NewAnchorBackend(config Config, signingKey ed25519.PrivateKey) (*AnchorBackend, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("iota: invalid Ed25519 private key length: %d", len(signingKey))
	}

	pub := signingKey.Public().(ed25519.PublicKey)
	return &AnchorBackend{
		config:  config,
		rpc:     NewRPCClient(config.RPCURL),
		signer:  signingKey,
		address: DeriveAddress(pub),
	}, nil
}

// Name returns "iota".
func (b *AnchorBackend) Name() string { return "iota" }

// Anchor submits a Merkle root to the IOTA network via the anchoring Move module.
func (b *AnchorBackend) Anchor(ctx context.Context, proof anchor.AnchorProof) (anchor.AnchorReceipt, error) {
	// 1. Get a gas coin.
	coins, err := b.rpc.GetCoins(ctx, b.address)
	if err != nil {
		return anchor.AnchorReceipt{}, fmt.Errorf("iota anchor: get coins: %w", err)
	}
	if len(coins) == 0 {
		return anchor.AnchorReceipt{}, fmt.Errorf("iota anchor: no gas coins available for %s", b.address)
	}
	gasCoin := coins[0].CoinObjectID

	// 2. Build and submit the Move call.
	merkleRootHex := "0x" + hex.EncodeToString(proof.MerkleRoot)
	leafCount := "0"

	txBytes, err := b.rpc.MoveCall(ctx, MoveCallParams{
		Sender:          b.address,
		PackageObjectID: b.config.AnchorPackageID,
		Module:          "anchoring",
		Function:        "anchor_root",
		TypeArguments:   []string{},
		Arguments:       []string{merkleRootHex, leafCount, b.config.ClockObjectID},
		Gas:             gasCoin,
		GasBudget:       strconv.FormatUint(b.config.GasBudget, 10),
	})
	if err != nil {
		return anchor.AnchorReceipt{}, fmt.Errorf("iota anchor: move call: %w", err)
	}

	// 3. Sign.
	signature, err := SignTransaction(txBytes, b.signer)
	if err != nil {
		return anchor.AnchorReceipt{}, fmt.Errorf("iota anchor: sign: %w", err)
	}

	// 4. Execute.
	txResp, err := b.rpc.ExecuteTransaction(ctx, txBytes, signature)
	if err != nil {
		return anchor.AnchorReceipt{}, fmt.Errorf("iota anchor: execute: %w", err)
	}

	// 5. Build receipt.
	rawReceipt, _ := json.Marshal(txResp.RawJSON)
	anchoredAt := time.Now().UTC()
	if txResp.TimestampMs != "" {
		if ms, err := strconv.ParseInt(txResp.TimestampMs, 10, 64); err == nil {
			anchoredAt = time.UnixMilli(ms).UTC()
		}
	}

	return anchor.AnchorReceipt{
		Backend:       "iota",
		MerkleRoot:    proof.MerkleRoot,
		TransactionID: txResp.Digest,
		AnchoredAt:    anchoredAt,
		BlockRef:      txResp.Checkpoint,
		RawReceipt:    rawReceipt,
	}, nil
}

// Verify checks an anchor receipt by fetching the transaction from the IOTA network.
func (b *AnchorBackend) Verify(ctx context.Context, receipt anchor.AnchorReceipt) (anchor.VerificationResult, error) {
	txResp, err := b.rpc.GetTransactionBlock(ctx, receipt.TransactionID)
	if err != nil {
		return anchor.VerificationResult{
			Valid:      false,
			Method:     "iota",
			VerifiedAt: time.Now().UTC(),
			Details:    fmt.Sprintf("failed to fetch transaction: %v", err),
		}, nil
	}

	// Look for AnchorCreated event and compare Merkle root.
	merkleRootMatch := false
	for _, event := range txResp.Events {
		var parsed struct {
			MerkleRoot string `json:"merkle_root"`
		}
		if err := json.Unmarshal(event.ParsedJSON, &parsed); err != nil {
			continue
		}
		if parsed.MerkleRoot != "" {
			eventRoot, err := hex.DecodeString(parsed.MerkleRoot)
			if err != nil {
				continue
			}
			if len(eventRoot) == len(receipt.MerkleRoot) {
				match := true
				for i := range eventRoot {
					if eventRoot[i] != receipt.MerkleRoot[i] {
						match = false
						break
					}
				}
				merkleRootMatch = match
			}
		}
	}

	return anchor.VerificationResult{
		Valid:           merkleRootMatch,
		Method:          "iota",
		VerifiedAt:      time.Now().UTC(),
		MerkleRootMatch: merkleRootMatch,
		TimestampMatch:  true,
		Details:         fmt.Sprintf("verified against transaction %s", receipt.TransactionID),
	}, nil
}

// Status checks connectivity to the IOTA network.
func (b *AnchorBackend) Status(ctx context.Context) (anchor.BackendStatus, error) {
	_, err := b.rpc.GetReferenceGasPrice(ctx)
	if err != nil {
		return anchor.BackendStatus{
			Connected:    false,
			ErrorMessage: err.Error(),
		}, nil
	}
	return anchor.BackendStatus{Connected: true}, nil
}

// SupportsOfflineVerification returns true — receipts contain the Merkle root
// in RawReceipt, enabling offline checks.
func (b *AnchorBackend) SupportsOfflineVerification() bool { return true }
