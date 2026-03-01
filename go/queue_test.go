package anchor

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// failingBackend fails for the first N calls, then succeeds.
type failingBackend struct {
	failCount int
	calls     int
	receipts  map[string]AnchorReceipt
}

func newFailingBackend(failCount int) *failingBackend {
	return &failingBackend{
		failCount: failCount,
		receipts:  make(map[string]AnchorReceipt),
	}
}

func (f *failingBackend) Name() string { return "failing" }

func (f *failingBackend) Anchor(_ context.Context, proof AnchorProof) (AnchorReceipt, error) {
	f.calls++
	if f.calls <= f.failCount {
		return AnchorReceipt{}, errors.New("backend temporarily unavailable")
	}
	receipt := AnchorReceipt{
		Backend:       "failing",
		MerkleRoot:    proof.MerkleRoot,
		TransactionID: "tx-success",
		AnchoredAt:    time.Now().UTC(),
	}
	return receipt, nil
}

func (f *failingBackend) Verify(_ context.Context, r AnchorReceipt) (VerificationResult, error) {
	return VerificationResult{Valid: true}, nil
}

func (f *failingBackend) Status(_ context.Context) (BackendStatus, error) {
	return BackendStatus{Connected: true}, nil
}

func (f *failingBackend) SupportsOfflineVerification() bool { return false }

func testProof() AnchorProof {
	h := sha256.Sum256([]byte("test"))
	return AnchorProof{
		MerkleRoot:  h[:],
		Description: "test anchor",
		SourceID:    "test-node",
		ComputedAt:  time.Now().UTC(),
	}
}

func TestQueue_Enqueue(t *testing.T) {
	backend := newFailingBackend(100) // always fail
	q, err := NewQueue(":memory:", backend, DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	id, err := q.Enqueue(testProof())
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if id == "" {
		t.Error("expected non-empty ID")
	}

	status := q.Status()
	if status.Pending != 1 {
		t.Errorf("pending = %d, want 1", status.Pending)
	}
}

func TestQueue_ProcessSuccess(t *testing.T) {
	backend := newFailingBackend(0) // always succeed
	q, err := NewQueue(":memory:", backend, DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	q.Enqueue(testProof())

	processed, err := q.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if processed != 1 {
		t.Errorf("processed = %d, want 1", processed)
	}

	status := q.Status()
	if status.Confirmed != 1 {
		t.Errorf("confirmed = %d, want 1", status.Confirmed)
	}
	if status.Pending != 0 {
		t.Errorf("pending = %d, want 0", status.Pending)
	}
}

func TestQueue_ProcessRetry(t *testing.T) {
	backend := newFailingBackend(2) // fail first 2 calls
	policy := RetryPolicy{
		MaxRetries:     5,
		InitialBackoff: 1 * time.Millisecond, // tiny backoff for testing
		MaxBackoff:     10 * time.Millisecond,
		BackoffFactor:  2.0,
	}
	q, err := NewQueue(":memory:", backend, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	q.Enqueue(testProof())

	// First attempt: fails, increases backoff.
	processed, _ := q.Process(context.Background())
	if processed != 0 {
		t.Errorf("first process = %d, want 0", processed)
	}

	// Wait for backoff to expire.
	time.Sleep(5 * time.Millisecond)

	// Second attempt: fails again.
	processed, _ = q.Process(context.Background())
	if processed != 0 {
		t.Errorf("second process = %d, want 0", processed)
	}

	// Wait again.
	time.Sleep(10 * time.Millisecond)

	// Third attempt: should succeed.
	processed, _ = q.Process(context.Background())
	if processed != 1 {
		t.Errorf("third process = %d, want 1", processed)
	}

	status := q.Status()
	if status.Confirmed != 1 {
		t.Errorf("confirmed = %d, want 1", status.Confirmed)
	}
}

func TestQueue_MaxRetriesExceeded(t *testing.T) {
	backend := newFailingBackend(100) // always fail
	policy := RetryPolicy{
		MaxRetries:     2,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
		BackoffFactor:  1.0,
	}
	q, err := NewQueue(":memory:", backend, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	q.Enqueue(testProof())

	// Process twice to hit max retries.
	q.Process(context.Background())
	time.Sleep(2 * time.Millisecond)
	q.Process(context.Background())

	status := q.Status()
	if status.Failed != 1 {
		t.Errorf("failed = %d, want 1", status.Failed)
	}
	if status.Pending != 0 {
		t.Errorf("pending = %d, want 0", status.Pending)
	}
}

func TestQueue_StatusTransitions(t *testing.T) {
	backend := newFailingBackend(0) // always succeed
	q, err := NewQueue(":memory:", backend, DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Initially empty.
	status := q.Status()
	if status.Pending != 0 || status.Confirmed != 0 {
		t.Error("expected empty queue")
	}

	// Enqueue → pending.
	q.Enqueue(testProof())
	status = q.Status()
	if status.Pending != 1 {
		t.Errorf("pending = %d after enqueue", status.Pending)
	}

	// Process → confirmed.
	q.Process(context.Background())
	status = q.Status()
	if status.Confirmed != 1 {
		t.Errorf("confirmed = %d after process", status.Confirmed)
	}
	if status.Pending != 0 {
		t.Errorf("pending = %d after process", status.Pending)
	}
}

func TestQueue_DrainMultiple(t *testing.T) {
	backend := newFailingBackend(0) // always succeed
	q, err := NewQueue(":memory:", backend, DefaultRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	for i := 0; i < 10; i++ {
		if _, err := q.Enqueue(testProof()); err != nil {
			t.Fatal(err)
		}
	}

	status := q.Status()
	if status.Pending != 10 {
		t.Errorf("pending = %d, want 10", status.Pending)
	}

	processed, err := q.Process(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if processed != 10 {
		t.Errorf("processed = %d, want 10", processed)
	}

	status = q.Status()
	if status.Confirmed != 10 {
		t.Errorf("confirmed = %d, want 10", status.Confirmed)
	}
}
