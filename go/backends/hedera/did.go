package hedera

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	anchor "github.com/Open-Nucleus/open-anchor/go"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

// DIDMessage is the JSON payload submitted to HCS for DID operations.
type DIDMessage struct {
	Operation string          `json:"operation"` // "create", "update", "deactivate"
	DID       string          `json:"did,omitempty"`
	Document  json.RawMessage `json:"document,omitempty"`
	RefSeq    int64           `json:"refSeq,omitempty"` // reference to original create sequence
	Timestamp string          `json:"timestamp"`
}

// DIDBackend implements anchor.DIDBackend for the did:hedera method via HCS.
type DIDBackend struct {
	config     Config
	client     *hiero.Client
	mirror     *MirrorClient
	didTopicID hiero.TopicID
}

// NewDIDBackend creates a new did:hedera backend.
// The submitterKey is used to pay for HCS transactions and may differ
// from the DID subject's key.
func NewDIDBackend(config Config, submitterKey ed25519.PrivateKey) (*DIDBackend, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if len(submitterKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("hedera: invalid Ed25519 private key length: %d", len(submitterKey))
	}

	client, err := newClient(config, submitterKey)
	if err != nil {
		return nil, fmt.Errorf("hedera did: create client: %w", err)
	}

	didTopicID, err := hiero.TopicIDFromString(config.DIDTopicID)
	if err != nil {
		return nil, fmt.Errorf("hedera did: parse DID topic ID %q: %w", config.DIDTopicID, err)
	}

	return &DIDBackend{
		config:     config,
		client:     client,
		mirror:     NewMirrorClient(config.MirrorURL),
		didTopicID: didTopicID,
	}, nil
}

// Name returns the DID method name.
func (b *DIDBackend) Name() string { return "hedera" }

// Method returns the full DID method prefix.
func (b *DIDBackend) Method() string { return "did:hedera" }

// RequiresNetwork returns true — did:hedera requires the Hedera network.
func (b *DIDBackend) RequiresNetwork() bool { return true }

// Create generates a new did:hedera DID by submitting the document to HCS.
func (b *DIDBackend) Create(ctx context.Context, publicKey ed25519.PublicKey, opts anchor.DIDOptions) (*anchor.DIDDocument, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("hedera did: invalid Ed25519 public key length: %d", len(publicKey))
	}

	network := b.config.Network
	if network == "" {
		network = "testnet"
	}

	// Build a W3C-compliant DID Document.
	multibase := anchor.PublicKeyToMultibase(publicKey)
	placeholderDID := fmt.Sprintf("did:hedera:%s:%s", network, b.config.DIDTopicID)
	keyID := placeholderDID + "#keys-1"

	controller := placeholderDID
	if opts.Controller != "" {
		controller = opts.Controller
	}

	doc := &anchor.DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: placeholderDID,
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
		Created:         time.Now().UTC().Format(time.RFC3339),
	}

	if opts.Controller != "" {
		doc.Controller = []string{opts.Controller}
	}
	if len(opts.Services) > 0 {
		doc.Service = opts.Services
	}

	// Serialize and submit to HCS.
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("hedera did create: marshal doc: %w", err)
	}

	didMsg := DIDMessage{
		Operation: "create",
		Document:  docBytes,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	msgBytes, err := json.Marshal(didMsg)
	if err != nil {
		return nil, fmt.Errorf("hedera did create: marshal message: %w", err)
	}

	tx, err := hiero.NewTopicMessageSubmitTransaction().
		SetTopicID(b.didTopicID).
		SetMessage(msgBytes).
		Execute(b.client)
	if err != nil {
		return nil, fmt.Errorf("hedera did create: submit: %w", err)
	}

	receipt, err := tx.GetReceipt(b.client)
	if err != nil {
		return nil, fmt.Errorf("hedera did create: receipt: %w", err)
	}

	seqNum := receipt.TopicSequenceNumber

	// Build the final DID string with the actual sequence number.
	did := fmt.Sprintf("did:hedera:%s:%s_%d", network, b.config.DIDTopicID, seqNum)

	// Update the document with the real DID.
	keyID = did + "#keys-1"
	doc.ID = did
	doc.VerificationMethod[0].ID = keyID
	if opts.Controller == "" {
		doc.VerificationMethod[0].Controller = did
	}
	doc.Authentication = []string{keyID}
	doc.AssertionMethod = []string{keyID}

	return doc, nil
}

// Resolve fetches a did:hedera DID Document from the Mirror Node.
func (b *DIDBackend) Resolve(ctx context.Context, did string) (*anchor.DIDDocument, error) {
	topicID, seqNum, err := parseDIDComponents(did)
	if err != nil {
		return nil, err
	}

	// Query the mirror node for the HCS message.
	msg, err := b.mirror.GetTopicMessage(ctx, topicID, seqNum)
	if err != nil {
		return nil, fmt.Errorf("hedera did resolve: get message: %w", err)
	}

	// Decode the message content.
	content, err := base64.StdEncoding.DecodeString(msg.Message)
	if err != nil {
		return nil, fmt.Errorf("hedera did resolve: decode message: %w", err)
	}

	// Check for any subsequent updates by scanning for update messages
	// that reference this sequence number.
	latestContent := content
	updates, err := b.mirror.GetTopicMessages(ctx, topicID, seqNum, 100)
	if err == nil {
		for _, u := range updates.Messages {
			uContent, err := base64.StdEncoding.DecodeString(u.Message)
			if err != nil {
				continue
			}
			var didMsg DIDMessage
			if err := json.Unmarshal(uContent, &didMsg); err != nil {
				continue
			}
			if didMsg.RefSeq == seqNum {
				if didMsg.Operation == "deactivate" {
					return &anchor.DIDDocument{
						ID:          did,
						Deactivated: true,
					}, nil
				}
				if didMsg.Operation == "update" && didMsg.Document != nil {
					latestContent = uContent
				}
			}
		}
	}

	// Parse the DID message.
	var didMsg DIDMessage
	if err := json.Unmarshal(latestContent, &didMsg); err != nil {
		return nil, fmt.Errorf("hedera did resolve: parse message: %w", err)
	}

	// Parse the DID Document from the message.
	var doc anchor.DIDDocument
	if err := json.Unmarshal(didMsg.Document, &doc); err != nil {
		return nil, fmt.Errorf("hedera did resolve: parse document: %w", err)
	}

	// Ensure the DID matches.
	doc.ID = did

	return &doc, nil
}

// Update modifies an existing did:hedera DID Document by submitting a new HCS message.
func (b *DIDBackend) Update(ctx context.Context, did string, updates anchor.DIDUpdate, signingKey ed25519.PrivateKey) (*anchor.DIDDocument, error) {
	_, seqNum, err := parseDIDComponents(did)
	if err != nil {
		return nil, err
	}

	// First resolve the current document.
	currentDoc, err := b.Resolve(ctx, did)
	if err != nil {
		return nil, fmt.Errorf("hedera did update: resolve current: %w", err)
	}
	if currentDoc.Deactivated {
		return nil, fmt.Errorf("hedera did update: DID is deactivated")
	}

	// Apply updates to the document.
	if len(updates.AddServices) > 0 {
		currentDoc.Service = append(currentDoc.Service, updates.AddServices...)
	}
	if len(updates.RemoveServices) > 0 {
		filtered := make([]anchor.DIDService, 0, len(currentDoc.Service))
		removeSet := make(map[string]bool)
		for _, id := range updates.RemoveServices {
			removeSet[id] = true
		}
		for _, svc := range currentDoc.Service {
			if !removeSet[svc.ID] {
				filtered = append(filtered, svc)
			}
		}
		currentDoc.Service = filtered
	}
	currentDoc.Updated = time.Now().UTC().Format(time.RFC3339)

	docBytes, err := json.Marshal(currentDoc)
	if err != nil {
		return nil, fmt.Errorf("hedera did update: marshal doc: %w", err)
	}

	didMsg := DIDMessage{
		Operation: "update",
		DID:       did,
		Document:  docBytes,
		RefSeq:    seqNum,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	msgBytes, err := json.Marshal(didMsg)
	if err != nil {
		return nil, fmt.Errorf("hedera did update: marshal message: %w", err)
	}

	_, err = hiero.NewTopicMessageSubmitTransaction().
		SetTopicID(b.didTopicID).
		SetMessage(msgBytes).
		Execute(b.client)
	if err != nil {
		return nil, fmt.Errorf("hedera did update: submit: %w", err)
	}

	return currentDoc, nil
}

// Deactivate marks a did:hedera DID as deactivated by submitting a deactivation message.
func (b *DIDBackend) Deactivate(ctx context.Context, did string, signingKey ed25519.PrivateKey) error {
	_, seqNum, err := parseDIDComponents(did)
	if err != nil {
		return err
	}

	didMsg := DIDMessage{
		Operation: "deactivate",
		DID:       did,
		RefSeq:    seqNum,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	msgBytes, err := json.Marshal(didMsg)
	if err != nil {
		return fmt.Errorf("hedera did deactivate: marshal: %w", err)
	}

	_, err = hiero.NewTopicMessageSubmitTransaction().
		SetTopicID(b.didTopicID).
		SetMessage(msgBytes).
		Execute(b.client)
	if err != nil {
		return fmt.Errorf("hedera did deactivate: submit: %w", err)
	}
	return nil
}

// --- Helpers ---

// parseDIDComponents extracts the topic ID and sequence number from a did:hedera string.
// Format: did:hedera:<network>:<topicId>_<sequenceNumber>
func parseDIDComponents(did string) (topicID string, seqNum int64, err error) {
	if !strings.HasPrefix(did, "did:hedera:") {
		return "", 0, fmt.Errorf("invalid did:hedera format: %q", did)
	}

	parts := strings.SplitN(did, ":", 4)
	if len(parts) != 4 {
		return "", 0, fmt.Errorf("invalid did:hedera format (expected did:hedera:<network>:<topicId>_<seq>): %q", did)
	}

	topicSeq := parts[3]
	idx := strings.LastIndex(topicSeq, "_")
	if idx < 0 {
		return "", 0, fmt.Errorf("invalid did:hedera format (missing _<seq>): %q", did)
	}

	topicID = topicSeq[:idx]
	seqStr := topicSeq[idx+1:]

	seqNum, err = strconv.ParseInt(seqStr, 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("invalid sequence number in did:hedera: %q", did)
	}

	return topicID, seqNum, nil
}
