// Package anchor provides blockchain-agnostic data integrity anchoring,
// decentralised identity (DIDs), and W3C Verifiable Credentials.
package anchor

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"
)

// AnchorBackend is the interface every blockchain integration must implement.
type AnchorBackend interface {
	// Name returns the backend identifier (e.g. "iota", "hedera").
	Name() string

	// Anchor submits a proof to the external ledger.
	Anchor(ctx context.Context, proof AnchorProof) (AnchorReceipt, error)

	// Verify checks an existing receipt against the external ledger.
	Verify(ctx context.Context, receipt AnchorReceipt) (VerificationResult, error)

	// Status returns the current backend connectivity and health.
	Status(ctx context.Context) (BackendStatus, error)

	// SupportsOfflineVerification returns true if the backend provides
	// enough data in the receipt to verify without network access.
	SupportsOfflineVerification() bool
}

// AnchorProof represents data to be anchored.
type AnchorProof struct {
	MerkleRoot  []byte              `json:"merkleRoot"`
	Description string              `json:"description"`
	SourceID    string              `json:"sourceId"`
	ComputedAt  time.Time           `json:"computedAt"`
	MerkleTree  *MerkleTree         `json:"-"`
	SigningKey  ed25519.PrivateKey   `json:"-"`
}

// AnchorReceipt is the proof-of-anchoring returned by a backend.
type AnchorReceipt struct {
	Backend       string    `json:"backend"`
	MerkleRoot    []byte    `json:"merkleRoot"`
	TransactionID string    `json:"transactionId"`
	AnchoredAt    time.Time `json:"anchoredAt"`
	Proof         []byte    `json:"proof,omitempty"`
	BlockRef      string    `json:"blockRef,omitempty"`
	RawReceipt    []byte    `json:"rawReceipt,omitempty"`
	Signature     []byte    `json:"signature,omitempty"`
}

// VerificationResult contains the outcome of a verification check.
type VerificationResult struct {
	Valid           bool      `json:"valid"`
	Method          string    `json:"method"`
	VerifiedAt      time.Time `json:"verifiedAt"`
	MerkleRootMatch bool      `json:"merkleRootMatch"`
	TimestampMatch  bool      `json:"timestampMatch"`
	Details         string    `json:"details"`
}

// BackendStatus reports the health of a backend connection.
type BackendStatus struct {
	Connected    bool      `json:"connected"`
	LastAnchor   time.Time `json:"lastAnchor,omitempty"`
	LastVerify   time.Time `json:"lastVerify,omitempty"`
	QueueDepth   int       `json:"queueDepth"`
	ErrorMessage string    `json:"errorMessage,omitempty"`
}

// AnchorResult is returned by AnchorEngine.Anchor and AnchorRoot.
type AnchorResult struct {
	MerkleRoot []byte         `json:"merkleRoot"`
	Queued     bool           `json:"queued"`
	Receipt    *AnchorReceipt `json:"receipt,omitempty"`
	QueueID    string         `json:"queueId,omitempty"`
}

// QueueStatus describes the current state of the offline queue.
type QueueStatus struct {
	Pending   int `json:"pending"`
	Submitted int `json:"submitted"`
	Confirmed int `json:"confirmed"`
	Failed    int `json:"failed"`
}

// EngineOption configures an AnchorEngine.
type EngineOption func(*AnchorEngine)

// WithQueue enables the offline anchor queue backed by SQLite at the given path.
func WithQueue(dbPath string) EngineOption {
	return func(e *AnchorEngine) {
		e.queuePath = dbPath
	}
}

// AnchorEngine provides Merkle-tree-based data anchoring against a pluggable backend.
type AnchorEngine struct {
	backend   AnchorBackend
	queue     *Queue
	queuePath string
}

// NewAnchorEngine creates an anchor engine with the specified backend.
func NewAnchorEngine(backend AnchorBackend, opts ...EngineOption) *AnchorEngine {
	e := &AnchorEngine{backend: backend}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Anchor computes a Merkle root from the given leaves and submits it to the backend.
// If the backend is unavailable and a queue is configured, the operation is queued.
func (e *AnchorEngine) Anchor(ctx context.Context, leaves []MerkleLeaf) (*AnchorResult, error) {
	tree, err := NewMerkleTree(leaves)
	if err != nil {
		return nil, fmt.Errorf("merkle tree: %w", err)
	}

	proof := AnchorProof{
		MerkleRoot:  tree.GetRoot(),
		Description: fmt.Sprintf("anchor %d leaves", len(leaves)),
		ComputedAt:  time.Now().UTC(),
		MerkleTree:  tree,
	}

	receipt, err := e.backend.Anchor(ctx, proof)
	if err != nil {
		// If a queue is available, enqueue instead of failing.
		if e.queue != nil {
			queueID, qErr := e.queue.Enqueue(proof)
			if qErr != nil {
				return nil, fmt.Errorf("anchor failed and queue error: %w (original: %v)", qErr, err)
			}
			return &AnchorResult{
				MerkleRoot: proof.MerkleRoot,
				Queued:     true,
				QueueID:    queueID,
			}, nil
		}
		return nil, fmt.Errorf("anchor: %w", err)
	}

	return &AnchorResult{
		MerkleRoot: proof.MerkleRoot,
		Receipt:    &receipt,
	}, nil
}

// AnchorRoot submits a pre-computed Merkle root to the backend.
func (e *AnchorEngine) AnchorRoot(ctx context.Context, root []byte, description string) (*AnchorResult, error) {
	proof := AnchorProof{
		MerkleRoot:  root,
		Description: description,
		ComputedAt:  time.Now().UTC(),
	}

	receipt, err := e.backend.Anchor(ctx, proof)
	if err != nil {
		if e.queue != nil {
			queueID, qErr := e.queue.Enqueue(proof)
			if qErr != nil {
				return nil, fmt.Errorf("anchor failed and queue error: %w (original: %v)", qErr, err)
			}
			return &AnchorResult{
				MerkleRoot: proof.MerkleRoot,
				Queued:     true,
				QueueID:    queueID,
			}, nil
		}
		return nil, fmt.Errorf("anchor: %w", err)
	}

	return &AnchorResult{
		MerkleRoot: proof.MerkleRoot,
		Receipt:    &receipt,
	}, nil
}

// Verify checks an anchor receipt against the backend.
func (e *AnchorEngine) Verify(ctx context.Context, receipt AnchorReceipt) (*VerificationResult, error) {
	result, err := e.backend.Verify(ctx, receipt)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	return &result, nil
}

// VerifyOffline checks an anchor receipt using only local data.
func (e *AnchorEngine) VerifyOffline(receipt AnchorReceipt) (*VerificationResult, error) {
	if !e.backend.SupportsOfflineVerification() {
		return &VerificationResult{
			Valid:      false,
			Method:     "offline",
			VerifiedAt: time.Now().UTC(),
			Details:    "backend does not support offline verification",
		}, nil
	}

	return &VerificationResult{
		Valid:           receipt.Proof != nil && len(receipt.MerkleRoot) > 0,
		Method:          "offline",
		VerifiedAt:      time.Now().UTC(),
		MerkleRootMatch: len(receipt.MerkleRoot) == 32,
		Details:         "verified using local receipt data",
	}, nil
}

// ProcessQueue attempts to submit all pending anchor operations.
func (e *AnchorEngine) ProcessQueue(ctx context.Context) (int, error) {
	if e.queue == nil {
		return 0, nil
	}
	return e.queue.Process(ctx)
}

// QueueStatus returns the current state of the offline queue.
func (e *AnchorEngine) QueueStatus() QueueStatus {
	if e.queue == nil {
		return QueueStatus{}
	}
	return e.queue.Status()
}

// InitQueue initialises the offline queue. Call after NewAnchorEngine if WithQueue was used.
func (e *AnchorEngine) InitQueue(policy RetryPolicy) error {
	if e.queuePath == "" {
		return nil
	}
	q, err := NewQueue(e.queuePath, e.backend, policy)
	if err != nil {
		return fmt.Errorf("init queue: %w", err)
	}
	e.queue = q
	return nil
}

// Close releases resources held by the engine (e.g. the queue database).
func (e *AnchorEngine) Close() error {
	if e.queue != nil {
		return e.queue.Close()
	}
	return nil
}
