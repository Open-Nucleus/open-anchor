package hedera

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// MirrorClient is a thin HTTP wrapper for the Hedera Mirror Node REST API.
type MirrorClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewMirrorClient creates a new Mirror Node REST client.
func NewMirrorClient(baseURL string) *MirrorClient {
	return &MirrorClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{},
	}
}

// --- Response types ---

// TopicMessage represents a single HCS message from the Mirror Node.
type TopicMessage struct {
	ConsensusTimestamp string `json:"consensus_timestamp"`
	Message            string `json:"message"` // base64-encoded
	RunningHash        string `json:"running_hash"`
	RunningHashVersion int    `json:"running_hash_version"`
	SequenceNumber     int64  `json:"sequence_number"`
	TopicID            string `json:"topic_id"`
}

// TopicMessagesResponse wraps a paginated list of topic messages.
type TopicMessagesResponse struct {
	Messages []TopicMessage `json:"messages"`
	Links    struct {
		Next string `json:"next,omitempty"`
	} `json:"links"`
}

// TransactionResponse represents a transaction from the Mirror Node.
type TransactionResponse struct {
	Transactions []TransactionDetail `json:"transactions"`
}

// TransactionDetail holds fields of a single transaction.
type TransactionDetail struct {
	ConsensusTimestamp string `json:"consensus_timestamp"`
	TransactionID      string `json:"transaction_id"`
	Result             string `json:"result"`
	Name               string `json:"name"`
	ValidStartTimestamp string `json:"valid_start_timestamp"`
}

// AccountResponse represents account info from the Mirror Node.
type AccountResponse struct {
	AccountID string `json:"account"`
	Balance   struct {
		Balance  int64 `json:"balance"`
		Timestamp string `json:"timestamp"`
	} `json:"balance"`
}

// --- Core HTTP call ---

func (c *MirrorClient) get(ctx context.Context, path string, result interface{}) error {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mirror GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mirror %s returned %d: %s", path, resp.StatusCode, string(body))
	}

	if result != nil {
		if err := json.Unmarshal(body, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}
	return nil
}

// --- Public methods ---

// GetTopicMessages fetches messages for a topic, optionally filtered by sequence number.
func (c *MirrorClient) GetTopicMessages(ctx context.Context, topicID string, afterSeq int64, limit int) (*TopicMessagesResponse, error) {
	path := fmt.Sprintf("/api/v1/topics/%s/messages?limit=%d&order=asc", topicID, limit)
	if afterSeq > 0 {
		path += fmt.Sprintf("&sequencenumber=gt:%d", afterSeq)
	}

	var result TopicMessagesResponse
	if err := c.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTopicMessage fetches a single HCS message by topic and sequence number.
func (c *MirrorClient) GetTopicMessage(ctx context.Context, topicID string, seqNum int64) (*TopicMessage, error) {
	path := fmt.Sprintf("/api/v1/topics/%s/messages/%d", topicID, seqNum)

	var result TopicMessage
	if err := c.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTransaction fetches a transaction by its ID.
func (c *MirrorClient) GetTransaction(ctx context.Context, txID string) (*TransactionResponse, error) {
	path := fmt.Sprintf("/api/v1/transactions/%s", txID)

	var result TransactionResponse
	if err := c.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetAccountBalance fetches the account balance (used as a health check).
func (c *MirrorClient) GetAccountBalance(ctx context.Context, accountID string) (*AccountResponse, error) {
	path := fmt.Sprintf("/api/v1/accounts/%s", accountID)

	var result AccountResponse
	if err := c.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
