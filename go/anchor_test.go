package anchor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"
)

// mockBackend is an in-memory AnchorBackend for testing.
type mockBackend struct {
	name      string
	receipts  map[string]AnchorReceipt
	available bool
	offline   bool
}

func newMockBackend(available bool) *mockBackend {
	return &mockBackend{
		name:      "mock",
		receipts:  make(map[string]AnchorReceipt),
		available: available,
		offline:   true,
	}
}

func (m *mockBackend) Name() string { return m.name }

func (m *mockBackend) Anchor(_ context.Context, proof AnchorProof) (AnchorReceipt, error) {
	if !m.available {
		return AnchorReceipt{}, errors.New("backend unavailable")
	}
	txID := fmt.Sprintf("tx-%x", proof.MerkleRoot[:8])
	receipt := AnchorReceipt{
		Backend:       m.name,
		MerkleRoot:    proof.MerkleRoot,
		TransactionID: txID,
		AnchoredAt:    time.Now().UTC(),
		Proof:         proof.MerkleRoot,
		BlockRef:      "block-1",
	}
	m.receipts[txID] = receipt
	return receipt, nil
}

func (m *mockBackend) Verify(_ context.Context, receipt AnchorReceipt) (VerificationResult, error) {
	if !m.available {
		return VerificationResult{}, errors.New("backend unavailable")
	}
	stored, ok := m.receipts[receipt.TransactionID]
	if !ok {
		return VerificationResult{
			Valid:      false,
			Method:     "ledger_query",
			VerifiedAt: time.Now().UTC(),
			Details:    "transaction not found",
		}, nil
	}
	match := equal(stored.MerkleRoot, receipt.MerkleRoot)
	return VerificationResult{
		Valid:           match,
		Method:          "ledger_query",
		VerifiedAt:      time.Now().UTC(),
		MerkleRootMatch: match,
		TimestampMatch:  true,
		Details:         "verified against mock ledger",
	}, nil
}

func (m *mockBackend) Status(_ context.Context) (BackendStatus, error) {
	return BackendStatus{Connected: m.available}, nil
}

func (m *mockBackend) SupportsOfflineVerification() bool {
	return m.offline
}

func TestAnchorEngine_Anchor(t *testing.T) {
	backend := newMockBackend(true)
	engine := NewAnchorEngine(backend)

	leaves := []MerkleLeaf{
		{Path: "a.txt", Hash: sha256sum([]byte("aaa"))},
		{Path: "b.txt", Hash: sha256sum([]byte("bbb"))},
	}

	result, err := engine.Anchor(context.Background(), leaves)
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if result.Queued {
		t.Error("expected immediate anchoring, not queued")
	}
	if result.Receipt == nil {
		t.Fatal("receipt is nil")
	}
	if result.Receipt.Backend != "mock" {
		t.Errorf("backend = %q", result.Receipt.Backend)
	}
	if len(result.MerkleRoot) != 32 {
		t.Errorf("root length = %d", len(result.MerkleRoot))
	}
}

func TestAnchorEngine_AnchorRoot(t *testing.T) {
	backend := newMockBackend(true)
	engine := NewAnchorEngine(backend)

	root := sha256sum([]byte("test-root"))
	result, err := engine.AnchorRoot(context.Background(), root, "test anchor")
	if err != nil {
		t.Fatalf("AnchorRoot: %v", err)
	}
	if result.Receipt == nil {
		t.Fatal("receipt is nil")
	}
	if !equal(result.MerkleRoot, root) {
		t.Error("root mismatch")
	}
}

func TestAnchorEngine_Verify(t *testing.T) {
	backend := newMockBackend(true)
	engine := NewAnchorEngine(backend)

	leaves := []MerkleLeaf{
		{Path: "a.txt", Hash: sha256sum([]byte("aaa"))},
	}

	result, err := engine.Anchor(context.Background(), leaves)
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}

	vr, err := engine.Verify(context.Background(), *result.Receipt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !vr.Valid {
		t.Error("expected valid verification")
	}
	if !vr.MerkleRootMatch {
		t.Error("expected root match")
	}
}

func TestAnchorEngine_VerifyOffline(t *testing.T) {
	backend := newMockBackend(true)
	engine := NewAnchorEngine(backend)

	receipt := AnchorReceipt{
		Backend:       "mock",
		MerkleRoot:    sha256sum([]byte("root")),
		TransactionID: "tx-123",
		Proof:         []byte("proof-data"),
	}

	vr, err := engine.VerifyOffline(receipt)
	if err != nil {
		t.Fatalf("VerifyOffline: %v", err)
	}
	if !vr.Valid {
		t.Error("expected valid offline verification")
	}
	if vr.Method != "offline" {
		t.Errorf("method = %q", vr.Method)
	}
}

func TestAnchorEngine_BackendUnavailable(t *testing.T) {
	backend := newMockBackend(false)
	engine := NewAnchorEngine(backend)

	// Without a queue, Anchor should fail.
	_, err := engine.Anchor(context.Background(), []MerkleLeaf{
		{Path: "a.txt", Hash: sha256sum([]byte("aaa"))},
	})
	if err == nil {
		t.Fatal("expected error when backend unavailable and no queue")
	}

	// With a queue, the operation should be queued.
	q, _ := NewQueue("", backend, DefaultRetryPolicy())
	engine.queue = q

	result, err := engine.Anchor(context.Background(), []MerkleLeaf{
		{Path: "a.txt", Hash: sha256sum([]byte("aaa"))},
	})
	if err != nil {
		t.Fatalf("Anchor with queue: %v", err)
	}
	if !result.Queued {
		t.Error("expected queued result")
	}
	if result.QueueID == "" {
		t.Error("expected non-empty queue ID")
	}
}

func sha256sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
