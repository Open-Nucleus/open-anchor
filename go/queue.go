package anchor

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// RetryPolicy configures the exponential backoff for the offline queue.
type RetryPolicy struct {
	MaxRetries     int           `json:"maxRetries"`
	InitialBackoff time.Duration `json:"initialBackoff"`
	MaxBackoff     time.Duration `json:"maxBackoff"`
	BackoffFactor  float64       `json:"backoffFactor"`
}

// DefaultRetryPolicy returns the default retry policy.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries:     10,
		InitialBackoff: 1 * time.Minute,
		MaxBackoff:     24 * time.Hour,
		BackoffFactor:  2.0,
	}
}

// QueuedAnchor represents a pending anchor operation in the queue.
type QueuedAnchor struct {
	ID        string      `json:"id"`
	Proof     AnchorProof `json:"proof"`
	QueuedAt  time.Time   `json:"queuedAt"`
	Attempts  int         `json:"attempts"`
	NextRetry time.Time   `json:"nextRetry"`
	LastError string      `json:"lastError,omitempty"`
	Status    string      `json:"status"`
}

// Queue manages pending anchor operations with retry logic, backed by SQLite.
type Queue struct {
	db          *sql.DB
	backend     AnchorBackend
	retryPolicy RetryPolicy
}

const createTableSQL = `
CREATE TABLE IF NOT EXISTS anchor_queue (
    id TEXT PRIMARY KEY,
    merkle_root BLOB NOT NULL,
    description TEXT,
    source_id TEXT,
    computed_at TEXT NOT NULL,
    proof_data BLOB,
    queued_at TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    next_retry TEXT,
    last_error TEXT,
    status TEXT DEFAULT 'pending',
    receipt_data BLOB
);
CREATE INDEX IF NOT EXISTS idx_queue_status ON anchor_queue(status);
CREATE INDEX IF NOT EXISTS idx_queue_retry ON anchor_queue(next_retry);
`

// NewQueue creates a new offline anchor queue backed by SQLite at dbPath.
// Use ":memory:" for an in-memory database (useful for testing).
func NewQueue(dbPath string, backend AnchorBackend, policy RetryPolicy) (*Queue, error) {
	if dbPath == "" {
		dbPath = ":memory:"
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	return &Queue{
		db:          db,
		backend:     backend,
		retryPolicy: policy,
	}, nil
}

// Enqueue adds a proof to the anchor queue.
func (q *Queue) Enqueue(proof AnchorProof) (string, error) {
	id := generateID()
	now := time.Now().UTC()

	proofData, err := json.Marshal(serializableProof{
		MerkleRoot:  proof.MerkleRoot,
		Description: proof.Description,
		SourceID:    proof.SourceID,
		ComputedAt:  proof.ComputedAt,
	})
	if err != nil {
		return "", fmt.Errorf("marshal proof: %w", err)
	}

	_, err = q.db.Exec(
		`INSERT INTO anchor_queue (id, merkle_root, description, source_id, computed_at, proof_data, queued_at, next_retry, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
		id,
		proof.MerkleRoot,
		proof.Description,
		proof.SourceID,
		proof.ComputedAt.Format(time.RFC3339),
		proofData,
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)
	if err != nil {
		return "", fmt.Errorf("insert: %w", err)
	}

	return id, nil
}

// Process attempts to submit all pending proofs whose retry time has passed.
// Returns the number of successfully confirmed anchors.
func (q *Queue) Process(ctx context.Context) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	rows, err := q.db.QueryContext(ctx,
		`SELECT id, proof_data, attempts FROM anchor_queue
		 WHERE status = 'pending' AND (next_retry IS NULL OR next_retry <= ?)
		 ORDER BY queued_at ASC`, now)
	if err != nil {
		return 0, fmt.Errorf("query pending: %w", err)
	}
	defer rows.Close()

	type pendingItem struct {
		id       string
		proof    serializableProof
		attempts int
	}

	var items []pendingItem
	for rows.Next() {
		var item pendingItem
		var proofData []byte
		if err := rows.Scan(&item.id, &proofData, &item.attempts); err != nil {
			return 0, fmt.Errorf("scan: %w", err)
		}
		if err := json.Unmarshal(proofData, &item.proof); err != nil {
			return 0, fmt.Errorf("unmarshal proof: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("rows: %w", err)
	}

	var processed int
	for _, item := range items {
		anchorProof := AnchorProof{
			MerkleRoot:  item.proof.MerkleRoot,
			Description: item.proof.Description,
			SourceID:    item.proof.SourceID,
			ComputedAt:  item.proof.ComputedAt,
		}

		receipt, err := q.backend.Anchor(ctx, anchorProof)
		attempts := item.attempts + 1

		if err != nil {
			// Update with error info and next retry.
			if attempts >= q.retryPolicy.MaxRetries {
				q.db.Exec(
					`UPDATE anchor_queue SET status = 'failed', attempts = ?, last_error = ? WHERE id = ?`,
					attempts, err.Error(), item.id)
			} else {
				backoff := q.calculateBackoff(attempts)
				nextRetry := time.Now().UTC().Add(backoff).Format(time.RFC3339)
				q.db.Exec(
					`UPDATE anchor_queue SET attempts = ?, last_error = ?, next_retry = ? WHERE id = ?`,
					attempts, err.Error(), nextRetry, item.id)
			}
			continue
		}

		// Success — store receipt and mark confirmed.
		receiptData, _ := json.Marshal(receipt)
		q.db.Exec(
			`UPDATE anchor_queue SET status = 'confirmed', attempts = ?, receipt_data = ? WHERE id = ?`,
			attempts, receiptData, item.id)
		processed++
	}

	return processed, nil
}

// Status returns the current queue state.
func (q *Queue) Status() QueueStatus {
	var s QueueStatus
	rows, err := q.db.Query(
		`SELECT status, COUNT(*) FROM anchor_queue GROUP BY status`)
	if err != nil {
		return s
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		switch status {
		case "pending":
			s.Pending = count
		case "submitted":
			s.Submitted = count
		case "confirmed":
			s.Confirmed = count
		case "failed":
			s.Failed = count
		}
	}
	return s
}

// Close releases resources held by the queue database.
func (q *Queue) Close() error {
	if q.db != nil {
		return q.db.Close()
	}
	return nil
}

func (q *Queue) calculateBackoff(attempts int) time.Duration {
	backoff := q.retryPolicy.InitialBackoff
	for i := 1; i < attempts; i++ {
		backoff = time.Duration(float64(backoff) * q.retryPolicy.BackoffFactor)
		if backoff > q.retryPolicy.MaxBackoff {
			backoff = q.retryPolicy.MaxBackoff
			break
		}
	}
	return backoff
}

// serializableProof is the JSON-serializable form of AnchorProof (no func fields).
type serializableProof struct {
	MerkleRoot  []byte    `json:"merkleRoot"`
	Description string    `json:"description"`
	SourceID    string    `json:"sourceId"`
	ComputedAt  time.Time `json:"computedAt"`
}

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to time-based ID.
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}
