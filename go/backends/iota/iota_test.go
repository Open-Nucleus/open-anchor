package iota_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	anchor "github.com/Open-Nucleus/open-anchor/go"
	"github.com/Open-Nucleus/open-anchor/go/backends/didkey"
	iotabackend "github.com/Open-Nucleus/open-anchor/go/backends/iota"
)

// --- Test helpers ---

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// fakeTxBytes simulates unsigned transaction bytes returned by unsafe_moveCall.
var fakeTxBytes = []byte("fake-transaction-bytes-for-testing-purposes-1234")

// fakeTxDigest is a deterministic transaction digest for test assertions.
const fakeTxDigest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// fakeObjectID is a deterministic object ID for created objects.
const fakeObjectID = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

// fakeCheckpoint is a test checkpoint number.
const fakeCheckpoint = "12345"

// newMockServer creates an httptest.Server that simulates IOTA JSON-RPC responses.
func newMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      int64           `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "unsafe_moveCall":
			b64 := base64.StdEncoding.EncodeToString(fakeTxBytes)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"txBytes":"%s"}}`, req.ID, b64)

		case "iota_executeTransactionBlock":
			resp := fmt.Sprintf(`{
				"jsonrpc":"2.0","id":%d,"result":{
					"digest":"%s",
					"effects":{"status":{"status":"success"},"created":[{"reference":{"objectId":"%s"}}]},
					"events":[{
						"type":"0xpkg::anchoring::AnchorCreated",
						"parsedJson":{"merkle_root":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","submitter":"0x123","timestamp_ms":"1000","leaf_count":"4","anchor_id":"0xabc"}
					}],
					"timestampMs":"1700000000000",
					"checkpoint":"%s",
					"objectChanges":[{"type":"created","objectId":"%s"}]
				}}`, req.ID, fakeTxDigest, fakeObjectID, fakeCheckpoint, fakeObjectID)
			fmt.Fprint(w, resp)

		case "iota_getObject":
			resp := fmt.Sprintf(`{
				"jsonrpc":"2.0","id":%d,"result":{
					"data":{
						"objectId":"%s",
						"version":"1",
						"digest":"objdigest123",
						"content":{"fields":{"publicKeyMultibase":"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}}
					}
				}}`, req.ID, fakeObjectID)
			fmt.Fprint(w, resp)

		case "iotax_getCoins":
			resp := fmt.Sprintf(`{
				"jsonrpc":"2.0","id":%d,"result":{
					"data":[{"coinObjectId":"0xcoin1","version":"1","digest":"coindigest","balance":"1000000000"}]
				}}`, req.ID)
			fmt.Fprint(w, resp)

		case "iota_getReferenceGasPrice":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":"1000"}`, req.ID)

		case "iota_getTransactionBlock":
			resp := fmt.Sprintf(`{
				"jsonrpc":"2.0","id":%d,"result":{
					"digest":"%s",
					"effects":{"status":{"status":"success"}},
					"events":[{
						"type":"0xpkg::anchoring::AnchorCreated",
						"parsedJson":{"merkle_root":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","submitter":"0x123","timestamp_ms":"1000","leaf_count":"4"}
					}],
					"timestampMs":"1700000000000",
					"checkpoint":"%s"
				}}`, req.ID, fakeTxDigest, fakeCheckpoint)
			fmt.Fprint(w, resp)

		case "iota_queryEvents":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"data":[],"hasNextPage":false}}`, req.ID)

		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"error":{"code":-32601,"message":"method not found: %s"}}`, req.ID, req.Method)
		}
	}))
}

// newMockConfig builds a Config pointing to the mock server.
func newMockConfig(serverURL string) iotabackend.Config {
	return iotabackend.Config{
		RPCURL:            serverURL,
		NetworkID:         "testnet",
		AnchorPackageID:   "0xpkg",
		IdentityPackageID: "0xidentity",
		ClockObjectID:     "0x6",
		GasBudget:         10_000_000,
	}
}

// --- Signing tests ---

func TestDeriveAddress(t *testing.T) {
	pub, _ := generateTestKey(t)
	addr := iotabackend.DeriveAddress(pub)

	if !strings.HasPrefix(addr, "0x") {
		t.Errorf("address should start with 0x, got %q", addr)
	}
	// Blake2b-256 produces 32 bytes → 64 hex chars + "0x" prefix = 66 chars.
	if len(addr) != 66 {
		t.Errorf("address length = %d, want 66", len(addr))
	}

	// Same key should always produce same address.
	addr2 := iotabackend.DeriveAddress(pub)
	if addr != addr2 {
		t.Error("DeriveAddress is not deterministic")
	}
}

func TestDeriveAddress_KnownKey(t *testing.T) {
	// Use a deterministic seed for a known key.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	addr := iotabackend.DeriveAddress(pub)

	// Address must be valid hex.
	hexPart := addr[2:] // strip "0x"
	_, err := hex.DecodeString(hexPart)
	if err != nil {
		t.Fatalf("address is not valid hex: %v", err)
	}

	// Re-derive to confirm determinism.
	if addr != iotabackend.DeriveAddress(pub) {
		t.Error("address derivation is not deterministic")
	}
}

func TestSignTransaction(t *testing.T) {
	_, priv := generateTestKey(t)
	txBytes := []byte("test transaction bytes")

	sig, err := iotabackend.SignTransaction(txBytes, priv)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	// Decode and check length: 1 (flag) + 64 (sig) + 32 (pubkey) = 97 bytes.
	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(decoded) != 97 {
		t.Errorf("decoded signature length = %d, want 97", len(decoded))
	}

	// First byte should be 0x00 (Ed25519 scheme flag).
	if decoded[0] != 0x00 {
		t.Errorf("scheme flag = 0x%02x, want 0x00", decoded[0])
	}

	// Last 32 bytes should be the public key.
	pub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(decoded[65:97], pub) {
		t.Error("public key in signature does not match")
	}
}

func TestSignTransaction_IntentPrefix(t *testing.T) {
	_, priv := generateTestKey(t)
	txBytes := []byte("some tx data")

	// Sign the same data twice — result should be deterministic.
	sig1, err := iotabackend.SignTransaction(txBytes, priv)
	if err != nil {
		t.Fatalf("sign 1: %v", err)
	}
	sig2, err := iotabackend.SignTransaction(txBytes, priv)
	if err != nil {
		t.Fatalf("sign 2: %v", err)
	}

	if sig1 != sig2 {
		t.Error("signing same data with same key should be deterministic (Ed25519)")
	}

	// Different data must produce different signature.
	sig3, err := iotabackend.SignTransaction([]byte("different tx data"), priv)
	if err != nil {
		t.Fatalf("sign 3: %v", err)
	}
	if sig1 == sig3 {
		t.Error("different data should produce different signatures")
	}
}

func TestSignTransaction_InvalidKey(t *testing.T) {
	_, err := iotabackend.SignTransaction([]byte("data"), []byte("short"))
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

// --- Config tests ---

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  iotabackend.Config
		wantErr bool
	}{
		{
			name: "valid with anchor package",
			config: iotabackend.Config{
				RPCURL:          "https://api.testnet.iota.cafe",
				AnchorPackageID: "0xpkg",
			},
			wantErr: false,
		},
		{
			name: "valid with identity package",
			config: iotabackend.Config{
				RPCURL:            "https://api.testnet.iota.cafe",
				IdentityPackageID: "0xid",
			},
			wantErr: false,
		},
		{
			name:    "missing RPCURL",
			config:  iotabackend.Config{AnchorPackageID: "0xpkg"},
			wantErr: true,
		},
		{
			name:    "missing both package IDs",
			config:  iotabackend.Config{RPCURL: "https://example.com"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfig_Defaults(t *testing.T) {
	cfg := iotabackend.Config{
		RPCURL:          "https://api.testnet.iota.cafe",
		AnchorPackageID: "0xpkg",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if cfg.GasBudget != iotabackend.DefaultGasBudget {
		t.Errorf("GasBudget = %d, want %d", cfg.GasBudget, iotabackend.DefaultGasBudget)
	}
	if cfg.ClockObjectID != iotabackend.DefaultClockObjectID {
		t.Errorf("ClockObjectID = %q, want %q", cfg.ClockObjectID, iotabackend.DefaultClockObjectID)
	}
}

// --- RPC client tests ---

func TestRPCClient_GetObject(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	rpc := iotabackend.NewRPCClient(server.URL)
	ctx := context.Background()

	resp, err := rpc.GetObject(ctx, fakeObjectID, true)
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if resp.Data.ObjectID != fakeObjectID {
		t.Errorf("ObjectID = %q, want %q", resp.Data.ObjectID, fakeObjectID)
	}
	if resp.Data.Version != "1" {
		t.Errorf("Version = %q, want %q", resp.Data.Version, "1")
	}
}

func TestRPCClient_ExecuteTransaction(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	rpc := iotabackend.NewRPCClient(server.URL)
	ctx := context.Background()

	resp, err := rpc.ExecuteTransaction(ctx, fakeTxBytes, "fakesig")
	if err != nil {
		t.Fatalf("ExecuteTransaction: %v", err)
	}
	if resp.Digest != fakeTxDigest {
		t.Errorf("Digest = %q, want %q", resp.Digest, fakeTxDigest)
	}
	if resp.Checkpoint != fakeCheckpoint {
		t.Errorf("Checkpoint = %q, want %q", resp.Checkpoint, fakeCheckpoint)
	}
}

func TestRPCClient_MoveCall(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	rpc := iotabackend.NewRPCClient(server.URL)
	ctx := context.Background()

	txBytes, err := rpc.MoveCall(ctx, iotabackend.MoveCallParams{
		Sender:          "0xsender",
		PackageObjectID: "0xpkg",
		Module:          "anchoring",
		Function:        "anchor_root",
		TypeArguments:   []string{},
		Arguments:       []string{"0xroot", "4", "0x6"},
		GasBudget:       "10000000",
	})
	if err != nil {
		t.Fatalf("MoveCall: %v", err)
	}
	if !bytes.Equal(txBytes, fakeTxBytes) {
		t.Errorf("txBytes mismatch")
	}
}

func TestRPCClient_ErrorHandling(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	rpc := iotabackend.NewRPCClient(server.URL)
	ctx := context.Background()

	// Call a non-existent method.
	_, err := rpc.GetObject(ctx, "0x1", true)
	// Our mock returns valid results for getObject, so try a direct call that doesn't exist.
	// Actually the mock handles getObject. Let's test with QueryEvents which returns empty but valid,
	// and then test with a server that returns errors.

	// Test network error.
	badRPC := iotabackend.NewRPCClient("http://localhost:1") // no server on port 1
	_, err = badRPC.GetReferenceGasPrice(ctx)
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestRPCClient_GetReferenceGasPrice(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	rpc := iotabackend.NewRPCClient(server.URL)
	ctx := context.Background()

	price, err := rpc.GetReferenceGasPrice(ctx)
	if err != nil {
		t.Fatalf("GetReferenceGasPrice: %v", err)
	}
	if price != "1000" {
		t.Errorf("price = %q, want %q", price, "1000")
	}
}

func TestRPCClient_GetCoins(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	rpc := iotabackend.NewRPCClient(server.URL)
	ctx := context.Background()

	coins, err := rpc.GetCoins(ctx, "0xowner")
	if err != nil {
		t.Fatalf("GetCoins: %v", err)
	}
	if len(coins) != 1 {
		t.Fatalf("expected 1 coin, got %d", len(coins))
	}
	if coins[0].CoinObjectID != "0xcoin1" {
		t.Errorf("CoinObjectID = %q, want %q", coins[0].CoinObjectID, "0xcoin1")
	}
	if coins[0].Balance != "1000000000" {
		t.Errorf("Balance = %q, want %q", coins[0].Balance, "1000000000")
	}
}

func TestRPCClient_GetTransactionBlock(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	rpc := iotabackend.NewRPCClient(server.URL)
	ctx := context.Background()

	resp, err := rpc.GetTransactionBlock(ctx, fakeTxDigest)
	if err != nil {
		t.Fatalf("GetTransactionBlock: %v", err)
	}
	if resp.Digest != fakeTxDigest {
		t.Errorf("Digest = %q, want %q", resp.Digest, fakeTxDigest)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(resp.Events))
	}
}

// --- Anchor backend tests ---

func TestAnchorBackend_Name(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewAnchorBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewAnchorBackend: %v", err)
	}
	if backend.Name() != "iota" {
		t.Errorf("Name() = %q, want %q", backend.Name(), "iota")
	}
}

func TestAnchorBackend_Anchor(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewAnchorBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewAnchorBackend: %v", err)
	}

	merkleRoot := make([]byte, 32)
	for i := range merkleRoot {
		merkleRoot[i] = byte(i)
	}

	proof := anchor.AnchorProof{
		MerkleRoot:  merkleRoot,
		Description: "test anchor",
	}

	receipt, err := backend.Anchor(context.Background(), proof)
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}

	if receipt.Backend != "iota" {
		t.Errorf("Backend = %q, want %q", receipt.Backend, "iota")
	}
	if receipt.TransactionID != fakeTxDigest {
		t.Errorf("TransactionID = %q, want %q", receipt.TransactionID, fakeTxDigest)
	}
	if !bytes.Equal(receipt.MerkleRoot, merkleRoot) {
		t.Error("MerkleRoot mismatch in receipt")
	}
	if receipt.BlockRef != fakeCheckpoint {
		t.Errorf("BlockRef = %q, want %q", receipt.BlockRef, fakeCheckpoint)
	}
	if len(receipt.RawReceipt) == 0 {
		t.Error("RawReceipt should not be empty")
	}
	if receipt.AnchoredAt.IsZero() {
		t.Error("AnchoredAt should not be zero")
	}
}

func TestAnchorBackend_Verify(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewAnchorBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewAnchorBackend: %v", err)
	}

	// The mock returns merkle_root "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	expectedRoot, _ := hex.DecodeString("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

	receipt := anchor.AnchorReceipt{
		Backend:       "iota",
		TransactionID: fakeTxDigest,
		MerkleRoot:    expectedRoot,
	}

	result, err := backend.Verify(context.Background(), receipt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Valid {
		t.Error("expected Valid = true")
	}
	if !result.MerkleRootMatch {
		t.Error("expected MerkleRootMatch = true")
	}
	if result.Method != "iota" {
		t.Errorf("Method = %q, want %q", result.Method, "iota")
	}
}

func TestAnchorBackend_Verify_MismatchedRoot(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewAnchorBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewAnchorBackend: %v", err)
	}

	// Different root from what the mock returns.
	wrongRoot := make([]byte, 32)
	receipt := anchor.AnchorReceipt{
		Backend:       "iota",
		TransactionID: fakeTxDigest,
		MerkleRoot:    wrongRoot,
	}

	result, err := backend.Verify(context.Background(), receipt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Valid {
		t.Error("expected Valid = false for mismatched root")
	}
	if result.MerkleRootMatch {
		t.Error("expected MerkleRootMatch = false")
	}
}

func TestAnchorBackend_Status(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewAnchorBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewAnchorBackend: %v", err)
	}

	status, err := backend.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Connected {
		t.Error("expected Connected = true")
	}
}

func TestAnchorBackend_Status_Unhealthy(t *testing.T) {
	// Point at a non-existent server.
	_, priv := generateTestKey(t)
	cfg := iotabackend.Config{
		RPCURL:          "http://localhost:1",
		AnchorPackageID: "0xpkg",
	}
	_ = cfg.Validate()

	backend, err := iotabackend.NewAnchorBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewAnchorBackend: %v", err)
	}

	status, err := backend.Status(context.Background())
	if err != nil {
		t.Fatalf("Status should not return error: %v", err)
	}
	if status.Connected {
		t.Error("expected Connected = false for unreachable server")
	}
	if status.ErrorMessage == "" {
		t.Error("expected ErrorMessage to be set")
	}
}

func TestAnchorBackend_SupportsOfflineVerification(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewAnchorBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewAnchorBackend: %v", err)
	}
	if !backend.SupportsOfflineVerification() {
		t.Error("expected SupportsOfflineVerification = true")
	}
}

// --- DID backend tests ---

func TestDIDBackend_Name(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewDIDBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewDIDBackend: %v", err)
	}
	if backend.Name() != "iota" {
		t.Errorf("Name() = %q, want %q", backend.Name(), "iota")
	}
}

func TestDIDBackend_Method(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewDIDBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewDIDBackend: %v", err)
	}
	if backend.Method() != "did:iota" {
		t.Errorf("Method() = %q, want %q", backend.Method(), "did:iota")
	}
}

func TestDIDBackend_RequiresNetwork(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewDIDBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewDIDBackend: %v", err)
	}
	if !backend.RequiresNetwork() {
		t.Error("expected RequiresNetwork = true")
	}
}

func TestDIDBackend_Create(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	pub, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewDIDBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewDIDBackend: %v", err)
	}

	doc, err := backend.Create(context.Background(), pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Check DID format: did:iota:<network>:<objectID>
	if !strings.HasPrefix(doc.ID, "did:iota:testnet:") {
		t.Errorf("DID = %q, want prefix did:iota:testnet:", doc.ID)
	}

	// Check W3C compliance.
	if len(doc.Context) != 2 {
		t.Fatalf("expected 2 contexts, got %d", len(doc.Context))
	}
	if doc.Context[0] != "https://www.w3.org/ns/did/v1" {
		t.Errorf("context[0] = %q", doc.Context[0])
	}

	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("expected 1 verification method, got %d", len(doc.VerificationMethod))
	}
	vm := doc.VerificationMethod[0]
	if vm.Type != "Ed25519VerificationKey2020" {
		t.Errorf("type = %q", vm.Type)
	}
	if !strings.HasSuffix(vm.ID, "#keys-1") {
		t.Errorf("key ID = %q, want suffix #keys-1", vm.ID)
	}

	// Verify the multibase encodes the correct public key.
	decodedPub, err := anchor.PublicKeyFromMultibase(vm.PublicKeyMultibase)
	if err != nil {
		t.Fatalf("decode multibase: %v", err)
	}
	if !bytes.Equal(decodedPub, pub) {
		t.Error("public key in DID document does not match input")
	}

	if len(doc.Authentication) != 1 {
		t.Errorf("authentication refs = %v", doc.Authentication)
	}
	if doc.Created == "" {
		t.Error("Created timestamp should be set")
	}
}

func TestDIDBackend_Create_WithServices(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	pub, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewDIDBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewDIDBackend: %v", err)
	}

	opts := anchor.DIDOptions{
		Services: []anchor.DIDService{
			{
				ID:              "#node",
				Type:            "OpenNucleusNode",
				ServiceEndpoint: "nucleus://node-01",
			},
		},
	}

	doc, err := backend.Create(context.Background(), pub, opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if len(doc.Service) != 1 {
		t.Fatalf("expected 1 service, got %d", len(doc.Service))
	}
	if doc.Service[0].Type != "OpenNucleusNode" {
		t.Errorf("service type = %q", doc.Service[0].Type)
	}
}

func TestDIDBackend_Resolve(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewDIDBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewDIDBackend: %v", err)
	}

	did := "did:iota:testnet:" + fakeObjectID
	doc, err := backend.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if doc.ID != did {
		t.Errorf("ID = %q, want %q", doc.ID, did)
	}
	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("expected 1 verification method, got %d", len(doc.VerificationMethod))
	}
	if doc.VerificationMethod[0].PublicKeyMultibase == "" {
		t.Error("publicKeyMultibase should not be empty")
	}
}

func TestDIDBackend_Resolve_InvalidDID(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewDIDBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewDIDBackend: %v", err)
	}

	tests := []struct {
		name string
		did  string
	}{
		{"empty", ""},
		{"wrong method", "did:key:z6Mk123"},
		{"missing object ID", "did:iota:testnet"},
		{"no prefix", "iota:testnet:0x123"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := backend.Resolve(context.Background(), tc.did)
			if err == nil {
				t.Errorf("Resolve(%q) should have returned error", tc.did)
			}
		})
	}
}

// --- Integration pattern test ---

func TestIOTA_WithIdentityEngine(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	pub, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	iotaDID, err := iotabackend.NewDIDBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewDIDBackend: %v", err)
	}

	keyBackend := didkey.New()

	// Create an IdentityEngine with both backends.
	engine := anchor.NewIdentityEngine(keyBackend, iotaDID)

	// Create a did:key (offline).
	keyDoc, err := engine.CreateDID(context.Background(), "key", pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatalf("CreateDID key: %v", err)
	}
	if !strings.HasPrefix(keyDoc.ID, "did:key:") {
		t.Errorf("did:key ID = %q", keyDoc.ID)
	}

	// Create a did:iota (network).
	iotaDoc, err := engine.CreateDID(context.Background(), "iota", pub, anchor.DIDOptions{})
	if err != nil {
		t.Fatalf("CreateDID iota: %v", err)
	}
	if !strings.HasPrefix(iotaDoc.ID, "did:iota:") {
		t.Errorf("did:iota ID = %q", iotaDoc.ID)
	}

	// Resolve the did:iota — should come from cache.
	resolved, err := engine.ResolveDID(context.Background(), iotaDoc.ID)
	if err != nil {
		t.Fatalf("ResolveDID (cached): %v", err)
	}
	if resolved.ID != iotaDoc.ID {
		t.Errorf("resolved ID = %q, want %q", resolved.ID, iotaDoc.ID)
	}

	// Clear cache and resolve again — should hit the network backend.
	engine.ClearCache(iotaDoc.ID)
	resolved2, err := engine.ResolveDID(context.Background(), iotaDoc.ID)
	if err != nil {
		t.Fatalf("ResolveDID (network): %v", err)
	}
	if resolved2.ID != iotaDoc.ID {
		t.Errorf("resolved2 ID = %q, want %q", resolved2.ID, iotaDoc.ID)
	}
}

// --- Constructor validation tests ---

func TestNewAnchorBackend_InvalidKey(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	cfg := newMockConfig(server.URL)
	_, err := iotabackend.NewAnchorBackend(cfg, []byte("short"))
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestNewDIDBackend_InvalidKey(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	cfg := newMockConfig(server.URL)
	_, err := iotabackend.NewDIDBackend(cfg, []byte("short"))
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestNewAnchorBackend_InvalidConfig(t *testing.T) {
	_, priv := generateTestKey(t)
	_, err := iotabackend.NewAnchorBackend(iotabackend.Config{}, priv)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestNewDIDBackend_InvalidConfig(t *testing.T) {
	_, priv := generateTestKey(t)
	_, err := iotabackend.NewDIDBackend(iotabackend.Config{}, priv)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

// --- ParseObjectRef test ---

func TestParseObjectRef(t *testing.T) {
	resp := &iotabackend.ObjectResponse{
		Data: iotabackend.ObjectData{
			ObjectID: "0xobj123",
			Version:  "5",
			Digest:   "digest456",
			Content:  json.RawMessage(`{}`),
		},
	}

	ref := iotabackend.ParseObjectRef(resp)
	if ref.ID != "0xobj123" {
		t.Errorf("ID = %q, want %q", ref.ID, "0xobj123")
	}
	if ref.Version != "5" {
		t.Errorf("Version = %q, want %q", ref.Version, "5")
	}
	if ref.Digest != "digest456" {
		t.Errorf("Digest = %q, want %q", ref.Digest, "digest456")
	}
}

// --- Interface compliance tests ---

func TestAnchorBackend_ImplementsInterface(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewAnchorBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewAnchorBackend: %v", err)
	}

	// Compile-time interface check.
	var _ anchor.AnchorBackend = backend
}

func TestDIDBackend_ImplementsInterface(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	_, priv := generateTestKey(t)
	cfg := newMockConfig(server.URL)

	backend, err := iotabackend.NewDIDBackend(cfg, priv)
	if err != nil {
		t.Fatalf("NewDIDBackend: %v", err)
	}

	// Compile-time interface check.
	var _ anchor.DIDBackend = backend
}
