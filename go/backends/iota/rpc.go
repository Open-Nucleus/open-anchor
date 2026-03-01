package iota

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
)

// RPCClient is a thin HTTP wrapper for IOTA JSON-RPC 2.0 calls.
type RPCClient struct {
	endpoint   string
	httpClient *http.Client
	nextID     atomic.Int64
}

// NewRPCClient creates a new JSON-RPC client for the given endpoint.
func NewRPCClient(endpoint string) *RPCClient {
	return &RPCClient{
		endpoint:   endpoint,
		httpClient: &http.Client{},
	}
}

// --- JSON-RPC 2.0 envelope types ---

type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// --- Response types ---

// ObjectResponse is the parsed result of iota_getObject.
type ObjectResponse struct {
	Data ObjectData `json:"data"`
}

// ObjectData holds the inner fields of an object query.
type ObjectData struct {
	ObjectID string          `json:"objectId"`
	Version  string          `json:"version"`
	Digest   string          `json:"digest"`
	Content  json.RawMessage `json:"content,omitempty"`
}

// TxResponse is the parsed result of iota_executeTransactionBlock.
type TxResponse struct {
	Digest       string          `json:"digest"`
	Effects      json.RawMessage `json:"effects,omitempty"`
	Events       []Event         `json:"events,omitempty"`
	TimestampMs  string          `json:"timestampMs,omitempty"`
	Checkpoint   string          `json:"checkpoint,omitempty"`
	RawJSON      json.RawMessage `json:"-"` // full response for RawReceipt
	ObjectChanges json.RawMessage `json:"objectChanges,omitempty"`
}

// CoinObject represents a gas coin returned by iotax_getCoins.
type CoinObject struct {
	CoinObjectID string `json:"coinObjectId"`
	Version      string `json:"version"`
	Digest       string `json:"digest"`
	Balance      string `json:"balance"`
}

// CoinsResponse wraps the paginated coins result.
type CoinsResponse struct {
	Data []CoinObject `json:"data"`
}

// Event represents an emitted Move event.
type Event struct {
	Type          string          `json:"type"`
	ParsedJSON    json.RawMessage `json:"parsedJson"`
	TxDigest      string          `json:"txDigest,omitempty"`
	TimestampMs   string          `json:"timestampMs,omitempty"`
}

// EventPage is a paginated list of events from iota_queryEvents.
type EventPage struct {
	Data       []Event         `json:"data"`
	NextCursor json.RawMessage `json:"nextCursor,omitempty"`
	HasNext    bool            `json:"hasNextPage"`
}

// MoveCallParams are the arguments for unsafe_moveCall.
type MoveCallParams struct {
	Sender          string   `json:"sender"`
	PackageObjectID string   `json:"packageObjectId"`
	Module          string   `json:"module"`
	Function        string   `json:"function"`
	TypeArguments   []string `json:"typeArguments"`
	Arguments       []string `json:"arguments"`
	Gas             string   `json:"gas,omitempty"`
	GasBudget       string   `json:"gasBudget"`
}

// --- Core RPC call ---

func (c *RPCClient) call(ctx context.Context, method string, params interface{}, result interface{}) error {
	id := c.nextID.Add(1)
	reqBody := rpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("rpc call %s: %w", method, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return rpcResp.Error
	}

	if result != nil {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return fmt.Errorf("unmarshal result: %w", err)
		}
	}
	return nil
}

// --- Public methods ---

// GetObject fetches an on-chain object by ID.
func (c *RPCClient) GetObject(ctx context.Context, objectID string, showContent bool) (*ObjectResponse, error) {
	opts := map[string]bool{"showContent": showContent}
	params := []interface{}{objectID, opts}

	var result ObjectResponse
	if err := c.call(ctx, "iota_getObject", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExecuteTransaction submits a signed transaction for execution.
func (c *RPCClient) ExecuteTransaction(ctx context.Context, txBytes []byte, signature string) (*TxResponse, error) {
	b64Tx := base64.StdEncoding.EncodeToString(txBytes)
	params := []interface{}{
		b64Tx,
		[]string{signature},
		map[string]string{
			"showEffects":       "true",
			"showEvents":        "true",
			"showObjectChanges": "true",
		},
	}

	var rawResult json.RawMessage
	if err := c.call(ctx, "iota_executeTransactionBlock", params, &rawResult); err != nil {
		return nil, err
	}

	var result TxResponse
	if err := json.Unmarshal(rawResult, &result); err != nil {
		return nil, fmt.Errorf("unmarshal tx response: %w", err)
	}
	result.RawJSON = rawResult
	return &result, nil
}

// MoveCall invokes unsafe_moveCall and returns the unsigned transaction bytes.
func (c *RPCClient) MoveCall(ctx context.Context, params MoveCallParams) ([]byte, error) {
	args := []interface{}{
		params.Sender,
		params.PackageObjectID,
		params.Module,
		params.Function,
		params.TypeArguments,
		params.Arguments,
	}
	if params.Gas != "" {
		args = append(args, params.Gas)
	} else {
		args = append(args, nil)
	}
	args = append(args, params.GasBudget)

	var result struct {
		TxBytes string `json:"txBytes"`
	}
	if err := c.call(ctx, "unsafe_moveCall", args, &result); err != nil {
		return nil, err
	}

	txBytes, err := base64.StdEncoding.DecodeString(result.TxBytes)
	if err != nil {
		return nil, fmt.Errorf("decode tx bytes: %w", err)
	}
	return txBytes, nil
}

// GetCoins returns coins owned by an address (for gas selection).
func (c *RPCClient) GetCoins(ctx context.Context, owner string) ([]CoinObject, error) {
	params := []interface{}{owner}

	var result CoinsResponse
	if err := c.call(ctx, "iotax_getCoins", params, &result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// GetReferenceGasPrice returns the current reference gas price (as a health check).
func (c *RPCClient) GetReferenceGasPrice(ctx context.Context) (string, error) {
	var result string
	if err := c.call(ctx, "iota_getReferenceGasPrice", []interface{}{}, &result); err != nil {
		return "", err
	}
	return result, nil
}

// GetTransactionBlock fetches a previously executed transaction by its digest.
func (c *RPCClient) GetTransactionBlock(ctx context.Context, digest string) (*TxResponse, error) {
	params := []interface{}{
		digest,
		map[string]string{
			"showEffects": "true",
			"showEvents":  "true",
		},
	}

	var rawResult json.RawMessage
	if err := c.call(ctx, "iota_getTransactionBlock", params, &rawResult); err != nil {
		return nil, err
	}

	var result TxResponse
	if err := json.Unmarshal(rawResult, &result); err != nil {
		return nil, fmt.Errorf("unmarshal tx response: %w", err)
	}
	result.RawJSON = rawResult
	return &result, nil
}

// QueryEvents fetches events matching a filter.
func (c *RPCClient) QueryEvents(ctx context.Context, filter interface{}, cursor interface{}, limit int) (*EventPage, error) {
	params := []interface{}{filter, cursor, limit, false}

	var result EventPage
	if err := c.call(ctx, "iota_queryEvents", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
