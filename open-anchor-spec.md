# open-anchor

**A blockchain-agnostic library for data integrity anchoring, decentralised identity, and verifiable credentials.**

**Repo:** github.com/Open-Nucleus/open-anchor  
**Licence:** Apache 2.0  
**Author:** Dr Akanimoh Osutuk — FibrinLab  
**Version:** 0.1.0 (Draft Specification)  
**Date:** March 2026

---

## 1. The Problem

### 1.1 What Exists Today

**Blockchain-specific SDKs** — IOTA Identity, Hedera SDK, ethers.js. Each provides anchoring and identity for its own chain. If you pick one, you're locked in. Migrating means rewriting your integration layer.

**W3C DID Core and Verifiable Credentials** — excellent specifications that define *what* a DID and a VC look like. But they are specifications, not libraries. Every implementation reimplements the same DID Document construction, credential signing, and verification logic against a specific DID method.

**Hyperledger Aries / Indy** — comprehensive decentralised identity frameworks, but heavyweight. They assume persistent network connectivity, specific ledgers (Indy, Fabric), and are designed for enterprise deployments, not resource-constrained or offline environments.

### 1.2 The Gap

No existing open-source project provides a **lightweight, blockchain-agnostic, offline-capable library** that:

1. **Anchors data hashes to any supported blockchain** through a pluggable backend interface — write once, deploy to IOTA, Hedera, Ethereum, or any future chain.

2. **Creates and resolves Decentralised Identifiers (DIDs)** through a pluggable DID method interface — `did:key` for offline, `did:iota` or `did:hedera` when connectivity is available.

3. **Issues and verifies W3C Verifiable Credentials** — using the same Ed25519 keys, regardless of the underlying DID method or blockchain.

4. **Works offline** — anchoring and credential operations queue locally and execute when connectivity is available. Verification works fully offline using cached proofs and `did:key`.

5. **Runs on constrained hardware** — Raspberry Pi, Android devices, field tablets. No heavy dependencies, no JVM, no Docker required.

open-anchor provides the common layer that any distributed system can import to get tamper-evident data and portable identity, without choosing a blockchain at architecture time.

---

## 2. Architecture

### 2.1 Two Pluggable Interfaces

```
┌─────────────────────────────────────────────────────┐
│                    open-anchor                        │
│                                                       │
│  ┌─────────────────┐     ┌─────────────────────────┐ │
│  │  Anchor Engine   │     │     Identity Engine      │ │
│  │                  │     │                          │ │
│  │  Merkle Tree     │     │  DID Create / Resolve    │ │
│  │  Proof Generation│     │  VC Issue / Verify       │ │
│  │  Offline Queue   │     │  Credential Storage      │ │
│  │  Receipt Storage │     │  Presentation Builder    │ │
│  └────────┬─────────┘     └────────────┬─────────────┘ │
│           │                            │               │
│  ┌────────▼────────────────────────────▼─────────────┐ │
│  │              Backend Interface Layer               │ │
│  └────────┬──────────┬──────────┬──────────┬─────────┘ │
│           │          │          │          │           │
│  ┌────────▼───┐ ┌────▼───┐ ┌───▼────┐ ┌──▼────────┐  │
│  │   IOTA     │ │ Hedera │ │did:key │ │ did:web   │  │
│  │  Tangle +  │ │ HCS +  │ │(offline│ │ (HTTPS    │  │
│  │  Identity  │ │ DID    │ │  only) │ │  resolve) │  │
│  └────────────┘ └────────┘ └────────┘ └───────────┘  │
└─────────────────────────────────────────────────────┘
```

### 2.2 Core Principle: Offline-First, Anchor-Later

```
Event occurs (data created/modified)
    │
    ├─ 1. Compute Merkle root from local data (instant, offline)
    ├─ 2. Store proof locally (Git commit)
    ├─ 3. Queue anchor operation (local queue)
    │
    └─ When connectivity available:
        ├─ 4. Submit to configured blockchain backend
        ├─ 5. Receive receipt (transaction hash, block, timestamp)
        └─ 6. Store receipt locally, sync to peers
```

Data integrity is never blocked by network availability. The local Merkle proof is valid immediately. The blockchain anchor adds external, tamper-evident timestamping when possible.

---

## 3. Anchor Engine

### 3.1 AnchorBackend Interface

```go
package anchor

import (
    "context"
    "crypto/ed25519"
    "time"
)

// AnchorBackend is the interface every blockchain integration must implement.
type AnchorBackend interface {
    // Name returns the backend identifier (e.g. "iota", "hedera", "ethereum")
    Name() string
    
    // Anchor submits a proof to the external ledger.
    // Returns a receipt containing the transaction reference.
    Anchor(ctx context.Context, proof AnchorProof) (AnchorReceipt, error)
    
    // Verify checks an existing receipt against the external ledger.
    // Returns true if the anchored data matches.
    Verify(ctx context.Context, receipt AnchorReceipt) (VerificationResult, error)
    
    // Status returns the current backend connectivity and health.
    Status(ctx context.Context) (BackendStatus, error)
    
    // SupportsOfflineVerification returns true if the backend provides
    // enough data in the receipt to verify without network access.
    SupportsOfflineVerification() bool
}
```

### 3.2 Core Types

```go
// AnchorProof represents data to be anchored.
type AnchorProof struct {
    // The Merkle root hash of the data being anchored
    MerkleRoot []byte  // 32 bytes (SHA-256)
    
    // Human-readable description of what's being anchored
    Description string
    
    // The source identifier (e.g. node ID)
    SourceID string
    
    // When the proof was computed locally
    ComputedAt time.Time
    
    // Optional: the full Merkle tree for offline verification
    MerkleTree *MerkleTree
    
    // Optional: signing key for the proof
    SigningKey ed25519.PrivateKey
}

// AnchorReceipt is the proof-of-anchoring returned by a backend.
type AnchorReceipt struct {
    // Which backend produced this receipt
    Backend string
    
    // The Merkle root that was anchored
    MerkleRoot []byte
    
    // Backend-specific transaction reference
    TransactionID string
    
    // When the anchor was confirmed by the backend
    AnchoredAt time.Time
    
    // Backend-specific proof data (for offline verification)
    Proof []byte
    
    // The block/milestone/round number (backend-specific)
    BlockRef string
    
    // Full receipt as backend-specific JSON (for deep verification)
    RawReceipt []byte
    
    // Signature over the receipt by the anchoring node
    Signature []byte
}

// VerificationResult contains the outcome of a verification check.
type VerificationResult struct {
    Valid           bool
    Method          string    // "ledger_query", "cached_proof", "offline"
    VerifiedAt      time.Time
    MerkleRootMatch bool
    TimestampMatch  bool
    Details         string
}

// BackendStatus reports the health of a backend connection.
type BackendStatus struct {
    Connected    bool
    LastAnchor   time.Time
    LastVerify   time.Time
    QueueDepth   int
    ErrorMessage string
}
```

### 3.3 Merkle Tree

The library provides a built-in Merkle tree implementation for computing roots from arbitrary data sets:

```go
package anchor

// MerkleTree computes and stores a binary hash tree.
type MerkleTree struct {
    Root   []byte
    Leaves []MerkleLeaf
    Nodes  [][]byte  // All intermediate nodes for proof generation
}

type MerkleLeaf struct {
    Path string  // Identifier (e.g. Git file path)
    Hash []byte  // SHA-256 of the leaf data
}

// NewMerkleTree builds a tree from a set of leaves.
func NewMerkleTree(leaves []MerkleLeaf) *MerkleTree

// Root returns the 32-byte Merkle root.
func (t *MerkleTree) Root() []byte

// GenerateProof returns the inclusion proof for a specific leaf.
// This allows verifying that a single record is part of the anchored set
// without having access to all other records.
func (t *MerkleTree) GenerateProof(leafIndex int) (MerkleProof, error)

// VerifyProof checks that a leaf is included in a tree with the given root.
func VerifyProof(leaf MerkleLeaf, proof MerkleProof, root []byte) bool

// MerkleProof contains the sibling hashes needed to reconstruct the root.
type MerkleProof struct {
    LeafHash []byte
    Siblings []ProofStep
}

type ProofStep struct {
    Hash     []byte
    Position string  // "left" or "right"
}
```

### 3.4 Offline Queue

Anchor operations are queued locally when the backend is unavailable:

```go
package anchor

// Queue manages pending anchor operations with retry logic.
type Queue struct {
    db          *sql.DB  // SQLite backing store
    backend     AnchorBackend
    retryPolicy RetryPolicy
}

type RetryPolicy struct {
    MaxRetries     int           // Default: 10
    InitialBackoff time.Duration // Default: 1 minute
    MaxBackoff     time.Duration // Default: 24 hours
    BackoffFactor  float64       // Default: 2.0
}

type QueuedAnchor struct {
    ID         string
    Proof      AnchorProof
    QueuedAt   time.Time
    Attempts   int
    NextRetry  time.Time
    LastError  string
    Status     string  // "pending", "submitted", "confirmed", "failed"
}

// Enqueue adds a proof to the anchor queue.
// Returns immediately — the proof will be submitted asynchronously.
func (q *Queue) Enqueue(proof AnchorProof) (string, error)

// Process attempts to submit all pending proofs.
// Called periodically or when connectivity is detected.
func (q *Queue) Process(ctx context.Context) (int, error)

// Status returns the current queue state.
func (q *Queue) Status() QueueStatus
```

**Queue SQLite schema:**

```sql
CREATE TABLE anchor_queue (
    id TEXT PRIMARY KEY,
    merkle_root BLOB NOT NULL,
    description TEXT,
    source_id TEXT,
    computed_at TEXT NOT NULL,
    proof_data BLOB,               -- Serialised AnchorProof
    queued_at TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    next_retry TEXT,
    last_error TEXT,
    status TEXT DEFAULT 'pending',  -- pending, submitted, confirmed, failed
    receipt_data BLOB              -- Serialised AnchorReceipt (after confirmation)
);

CREATE INDEX idx_queue_status ON anchor_queue(status);
CREATE INDEX idx_queue_retry ON anchor_queue(next_retry);
```

---

## 4. Identity Engine

### 4.1 DIDBackend Interface

```go
package anchor

// DIDBackend is the interface for decentralised identity operations.
type DIDBackend interface {
    // Name returns the DID method name (e.g. "key", "iota", "hedera")
    Name() string
    
    // Method returns the full DID method prefix (e.g. "did:key", "did:iota")
    Method() string
    
    // Create generates a new DID from an Ed25519 public key.
    Create(ctx context.Context, publicKey ed25519.PublicKey, opts DIDOptions) (*DIDDocument, error)
    
    // Resolve fetches and returns the DID Document for a given DID string.
    Resolve(ctx context.Context, did string) (*DIDDocument, error)
    
    // Update modifies an existing DID Document (e.g. add/rotate keys).
    Update(ctx context.Context, did string, updates DIDUpdate, signingKey ed25519.PrivateKey) (*DIDDocument, error)
    
    // Deactivate marks a DID as deactivated (revocation).
    Deactivate(ctx context.Context, did string, signingKey ed25519.PrivateKey) error
    
    // RequiresNetwork returns true if this method needs connectivity for create/resolve.
    RequiresNetwork() bool
}

type DIDOptions struct {
    // Controller DID (if different from the subject)
    Controller string
    
    // Service endpoints to include in the DID Document
    Services []DIDService
    
    // Additional verification methods
    AdditionalKeys []ed25519.PublicKey
}
```

### 4.2 DID Document (W3C DID Core Compliant)

```go
// DIDDocument follows the W3C DID Core specification.
type DIDDocument struct {
    Context            []string              `json:"@context"`
    ID                 string                `json:"id"`
    Controller         []string              `json:"controller,omitempty"`
    VerificationMethod []VerificationMethod  `json:"verificationMethod"`
    Authentication     []string              `json:"authentication"`
    AssertionMethod    []string              `json:"assertionMethod,omitempty"`
    KeyAgreement       []string              `json:"keyAgreement,omitempty"`
    Service            []DIDService          `json:"service,omitempty"`
    Created            string                `json:"created,omitempty"`
    Updated            string                `json:"updated,omitempty"`
    Deactivated        bool                  `json:"deactivated,omitempty"`
}

type VerificationMethod struct {
    ID                 string `json:"id"`
    Type               string `json:"type"`                 // "Ed25519VerificationKey2020"
    Controller         string `json:"controller"`
    PublicKeyMultibase string `json:"publicKeyMultibase"`   // Multibase-encoded Ed25519 public key
}

type DIDService struct {
    ID              string `json:"id"`
    Type            string `json:"type"`
    ServiceEndpoint string `json:"serviceEndpoint"`
}
```

**Example DID Document for an Open Nucleus device:**

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
  "verificationMethod": [{
    "id": "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
    "publicKeyMultibase": "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
  }],
  "authentication": [
    "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP#keys-1"
  ],
  "assertionMethod": [
    "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP#keys-1"
  ],
  "service": [{
    "id": "#open-nucleus-node",
    "type": "OpenNucleusNode",
    "serviceEndpoint": "nucleus://node-sheffield-01"
  }]
}
```

### 4.3 DID Method Implementations

**`did:key` (V1 — offline-first, zero network dependency)**

The public key is encoded directly in the DID string. No ledger, no resolution network. Perfect for offline-first systems.

```go
package didkey

// Create generates a did:key from an Ed25519 public key.
// The DID string contains the full public key — resolution is instant
// and requires no network access.
func (b *Backend) Create(ctx context.Context, pub ed25519.PublicKey, opts DIDOptions) (*DIDDocument, error) {
    // 1. Multicodec prefix for Ed25519: 0xed01
    // 2. Multibase encode (base58btc, prefix 'z')
    // 3. DID string: "did:key:z6Mk..."
    // 4. Build DID Document with derived verification methods
}

// Resolve parses the public key from the DID string.
// No network call needed — the key IS the identifier.
func (b *Backend) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
    // 1. Strip "did:key:" prefix
    // 2. Multibase decode
    // 3. Extract Ed25519 public key
    // 4. Build DID Document
}

func (b *Backend) RequiresNetwork() bool { return false }
```

**`did:iota` (V2 — IOTA Tangle-backed)**

```go
package didiota

// Create publishes a DID Document to the IOTA Tangle via the Identity framework.
func (b *Backend) Create(ctx context.Context, pub ed25519.PublicKey, opts DIDOptions) (*DIDDocument, error) {
    // 1. Build DID Document
    // 2. Publish to IOTA via iota-identity SDK
    // 3. Return DID with Tangle message reference
}

// Resolve fetches the DID Document from the IOTA Tangle.
func (b *Backend) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
    // 1. Parse message ID from DID
    // 2. Query IOTA node for DID Document
    // 3. Verify chain of custody
}

func (b *Backend) RequiresNetwork() bool { return true }
```

**`did:hedera` (V2 — Hedera Consensus Service-backed)**

```go
package didhedera

// Create publishes a DID Document to a Hedera HCS topic.
func (b *Backend) Create(ctx context.Context, pub ed25519.PublicKey, opts DIDOptions) (*DIDDocument, error) {
    // 1. Build DID Document
    // 2. Submit to HCS topic
    // 3. Return DID with topic ID and sequence number
}

// Resolve reads the DID Document from Hedera mirror node.
func (b *Backend) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
    // 1. Parse topic ID and sequence from DID
    // 2. Query Hedera mirror node
    // 3. Reconstruct latest DID Document state from message history
}

func (b *Backend) RequiresNetwork() bool { return true }
```

### 4.4 DID Resolution Strategy

When resolving a DID, the library tries methods in order:

```go
func (e *IdentityEngine) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
    method := extractMethod(did)  // "key", "iota", "hedera"
    
    // 1. Try local cache first
    if doc, ok := e.cache.Get(did); ok {
        return doc, nil
    }
    
    // 2. If did:key, resolve offline (always works)
    if method == "key" {
        return e.didKeyBackend.Resolve(ctx, did)
    }
    
    // 3. Try the appropriate network backend
    backend, ok := e.backends[method]
    if !ok {
        return nil, fmt.Errorf("unsupported DID method: %s", method)
    }
    
    doc, err := backend.Resolve(ctx, did)
    if err != nil {
        // 4. Fall back to cached version if network unavailable
        if doc, ok := e.staleCache.Get(did); ok {
            return doc, nil  // Return stale with warning
        }
        return nil, err
    }
    
    // 5. Cache the result
    e.cache.Set(did, doc)
    return doc, nil
}
```

---

## 5. Verifiable Credentials

### 5.1 Credential Types

open-anchor supports issuing and verifying W3C Verifiable Credentials. The library provides the generic framework; consuming applications define the credential types.

```go
// CredentialClaims represents the claims in a Verifiable Credential.
type CredentialClaims struct {
    // Standard fields
    Context     []string          `json:"@context"`
    Type        []string          `json:"type"`
    Issuer      string            `json:"issuer"`         // DID of the issuer
    Subject     string            `json:"credentialSubject.id"`  // DID of the subject
    IssuanceDate string           `json:"issuanceDate"`
    ExpirationDate string         `json:"expirationDate,omitempty"`
    
    // Application-specific claims (passed through as JSON)
    Claims map[string]interface{} `json:"credentialSubject"`
}

// VerifiableCredential is a signed credential.
type VerifiableCredential struct {
    CredentialClaims
    Proof CredentialProof `json:"proof"`
}

type CredentialProof struct {
    Type               string `json:"type"`                // "Ed25519Signature2020"
    Created            string `json:"created"`
    VerificationMethod string `json:"verificationMethod"`  // DID#key-id
    ProofPurpose       string `json:"proofPurpose"`        // "assertionMethod"
    ProofValue         string `json:"proofValue"`          // Base64-encoded signature
}
```

### 5.2 Issue and Verify

```go
package anchor

// IssueCredential creates a signed Verifiable Credential.
func (e *IdentityEngine) IssueCredential(
    ctx context.Context,
    issuerDID string,
    issuerKey ed25519.PrivateKey,
    claims CredentialClaims,
) (*VerifiableCredential, error) {
    // 1. Set issuance date to now
    // 2. Construct the credential JSON (canonical form)
    // 3. Sign with Ed25519
    // 4. Attach proof block
    // 5. Return complete VC
}

// VerifyCredential checks the signature and validity of a VC.
func (e *IdentityEngine) VerifyCredential(
    ctx context.Context,
    vc *VerifiableCredential,
) (*CredentialVerification, error) {
    // 1. Resolve the issuer's DID to get their public key
    // 2. Verify the Ed25519 signature
    // 3. Check expiration date
    // 4. Check revocation status (if revocation list available)
    // 5. Return verification result
}

type CredentialVerification struct {
    Valid            bool
    SignatureValid   bool
    NotExpired       bool
    NotRevoked       bool
    IssuerResolved   bool
    ResolutionMethod string  // "offline" (did:key) or "network" (did:iota)
}
```

### 5.3 Healthcare Credential Templates

While open-anchor is domain-agnostic, it ships with credential type constants for healthcare use cases:

```go
const (
    // Practitioner credential types
    CredTypePractitionerLicense  = "PractitionerLicenseCredential"
    CredTypePractitionerRole     = "PractitionerRoleCredential"
    
    // Data integrity credential types
    CredTypeDataIntegrity        = "DataIntegrityCredential"
    CredTypeAuditTrail           = "AuditTrailCredential"
    
    // Organisational credential types
    CredTypeAuthorisedDeployment = "AuthorisedDeploymentCredential"
    CredTypeSiteAccreditation    = "SiteAccreditationCredential"
    
    // Patient credential types
    CredTypePatientConsent       = "PatientConsentCredential"
    CredTypeImmunisationRecord   = "ImmunisationRecordCredential"
)
```

**Example: Data Integrity Credential** (issued after successful anchoring):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://open-nucleus.dev/credentials/v1"
  ],
  "type": ["VerifiableCredential", "DataIntegrityCredential"],
  "issuer": "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
  "issuanceDate": "2026-03-01T12:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "type": "DataIntegrityProof",
    "merkleRoot": "a3f2b8c1d4e5f6...",
    "anchoredOn": "iota",
    "transactionId": "0x1234abcd...",
    "anchoredAt": "2026-03-01T12:00:05Z",
    "resourceCount": 1247,
    "nodeId": "node-sheffield-01",
    "siteId": "clinic-maiduguri-03"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-03-01T12:00:06Z",
    "verificationMethod": "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndTn..."
  }
}
```

**Example: Practitioner License Credential** (issued by a medical authority):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://open-nucleus.dev/credentials/v1"
  ],
  "type": ["VerifiableCredential", "PractitionerLicenseCredential"],
  "issuer": "did:iota:0xMedicalBoardNigeria...",
  "issuanceDate": "2026-01-15T00:00:00Z",
  "expirationDate": "2028-01-15T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkDrOsutuk...",
    "name": "Dr Akanimoh Osutuk",
    "license": "MDCN/2020/12345",
    "specialty": "Paediatrics",
    "jurisdiction": "Nigeria",
    "status": "active"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-01-15T09:00:00Z",
    "verificationMethod": "did:iota:0xMedicalBoardNigeria...#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3hJ7rGkPq..."
  }
}
```

---

## 6. Verifiable Presentations

When a practitioner needs to prove their identity to a new node or during sync:

```go
// VerifiablePresentation bundles one or more VCs with a proof from the holder.
type VerifiablePresentation struct {
    Context              []string               `json:"@context"`
    Type                 []string               `json:"type"`
    Holder               string                 `json:"holder"`     // Presenter's DID
    VerifiableCredential []VerifiableCredential  `json:"verifiableCredential"`
    Proof                CredentialProof         `json:"proof"`
}

// CreatePresentation bundles credentials into a signed presentation.
func (e *IdentityEngine) CreatePresentation(
    ctx context.Context,
    holderDID string,
    holderKey ed25519.PrivateKey,
    credentials []VerifiableCredential,
) (*VerifiablePresentation, error)

// VerifyPresentation checks the presentation signature AND each embedded credential.
func (e *IdentityEngine) VerifyPresentation(
    ctx context.Context,
    vp *VerifiablePresentation,
) (*PresentationVerification, error)
```

Use case: during the Sync Service handshake, Node A presents a VP containing:
1. Its node identity credential (proving it's an authorised deployment)
2. The operator's practitioner license credential (proving a licensed person manages it)

Node B verifies both offline (did:key) or online (did:iota/did:hedera) before accepting the sync.

---

## 7. Credential Revocation

### 7.1 Revocation List

open-anchor uses a simple, offline-compatible revocation model: a signed revocation list maintained by each issuer.

```go
type RevocationList struct {
    Issuer     string    `json:"issuer"`      // Issuer DID
    Revoked    []string  `json:"revoked"`     // List of revoked credential IDs
    UpdatedAt  string    `json:"updatedAt"`
    Proof      CredentialProof `json:"proof"` // Signed by issuer
}
```

Revocation lists are stored in Git at `.nucleus/credentials/revocations/` and propagate via the normal sync mechanism. Verification checks the local revocation list — no network call needed.

### 7.2 Revocation Check During Verification

```go
func (e *IdentityEngine) isRevoked(vc *VerifiableCredential) bool {
    list, ok := e.revocationLists[vc.Issuer]
    if !ok {
        return false  // No revocation list available — assume valid
    }
    for _, revokedID := range list.Revoked {
        if revokedID == vc.ID {
            return true
        }
    }
    return false
}
```

---

## 8. API Surface

### 8.1 Anchor Operations

```go
package anchor

// NewAnchorEngine creates an anchor engine with the specified backend.
func NewAnchorEngine(backend AnchorBackend, opts ...EngineOption) *AnchorEngine

// Anchor computes a Merkle root and submits it to the backend.
// If the backend is unavailable, the operation is queued.
func (e *AnchorEngine) Anchor(ctx context.Context, leaves []MerkleLeaf) (*AnchorResult, error)

// AnchorRoot submits a pre-computed Merkle root.
func (e *AnchorEngine) AnchorRoot(ctx context.Context, root []byte, description string) (*AnchorResult, error)

// Verify checks an anchor receipt against the backend.
func (e *AnchorEngine) Verify(ctx context.Context, receipt AnchorReceipt) (*VerificationResult, error)

// VerifyOffline checks an anchor receipt using only local data.
func (e *AnchorEngine) VerifyOffline(receipt AnchorReceipt) (*VerificationResult, error)

// ProcessQueue attempts to submit all pending anchor operations.
func (e *AnchorEngine) ProcessQueue(ctx context.Context) (int, error)

// QueueStatus returns the current state of the offline queue.
func (e *AnchorEngine) QueueStatus() QueueStatus

type AnchorResult struct {
    MerkleRoot []byte
    Queued     bool          // true if submitted to queue (backend unavailable)
    Receipt    *AnchorReceipt // non-nil if anchored immediately
    QueueID    string         // non-empty if queued
}
```

### 8.2 Identity Operations

```go
package anchor

// NewIdentityEngine creates an identity engine with the specified DID backends.
func NewIdentityEngine(backends ...DIDBackend) *IdentityEngine

// CreateDID generates a new DID using the specified method.
func (e *IdentityEngine) CreateDID(ctx context.Context, method string, publicKey ed25519.PublicKey, opts DIDOptions) (*DIDDocument, error)

// ResolveDID resolves any supported DID to its DID Document.
func (e *IdentityEngine) ResolveDID(ctx context.Context, did string) (*DIDDocument, error)

// IssueCredential creates a signed Verifiable Credential.
func (e *IdentityEngine) IssueCredential(ctx context.Context, issuerDID string, issuerKey ed25519.PrivateKey, claims CredentialClaims) (*VerifiableCredential, error)

// VerifyCredential checks signature, expiry, and revocation.
func (e *IdentityEngine) VerifyCredential(ctx context.Context, vc *VerifiableCredential) (*CredentialVerification, error)

// CreatePresentation bundles credentials into a signed VP.
func (e *IdentityEngine) CreatePresentation(ctx context.Context, holderDID string, holderKey ed25519.PrivateKey, credentials []VerifiableCredential) (*VerifiablePresentation, error)

// VerifyPresentation checks the VP and all embedded credentials.
func (e *IdentityEngine) VerifyPresentation(ctx context.Context, vp *VerifiablePresentation) (*PresentationVerification, error)
```

---

## 9. Backend Comparison

| Property | did:key | IOTA | Hedera | Ethereum |
|----------|---------|------|--------|----------|
| **Anchor cost** | N/A | Free | ~$0.001/msg | Gas fees |
| **DID cost** | Free | Free | ~$0.001 | Gas fees |
| **Anchor finality** | Instant (local) | ~10s | 3-5s | ~12s |
| **Offline create** | ✓ | ✗ | ✗ | ✗ |
| **Offline resolve** | ✓ (always) | ✗ (cache only) | ✗ (cache only) | ✗ (cache only) |
| **Offline verify VC** | ✓ | ✓ (if issuer cached) | ✓ (if issuer cached) | ✓ (if issuer cached) |
| **Data sovereignty** | Full (no ledger) | Data on Tangle | Data on HCS | Data on chain |
| **Go dependency** | None | iota.go SDK | hedera-sdk-go | go-ethereum |
| **Pi 4 compatible** | ✓ | ✓ (light node) | ✓ (mirror API) | ✓ (light client) |

**Recommended deployment pattern:**

- `did:key` as the base layer — works everywhere, always, offline
- One network-backed method (IOTA or Hedera) for anchoring and verifiable ledger registration when connectivity allows
- `did:key` DIDs can be optionally "upgraded" by registering the same public key on a ledger-backed method

---

## 10. Repository Structure

```
open-anchor/
├── README.md
├── LICENSE                           # Apache 2.0
├── CLAUDE.md                         # AI assistant context
├── CONTRIBUTING.md
├── CHANGELOG.md
├── go/
│   ├── go.mod
│   ├── anchor.go                     # AnchorBackend interface, AnchorEngine
│   ├── merkle.go                     # Merkle tree implementation
│   ├── queue.go                      # Offline anchor queue
│   ├── did.go                        # DIDBackend interface, IdentityEngine
│   ├── credential.go                 # VC issuance and verification
│   ├── presentation.go              # VP creation and verification
│   ├── revocation.go                # Revocation list management
│   ├── backends/
│   │   ├── didkey/
│   │   │   ├── didkey.go            # did:key implementation (anchor: N/A)
│   │   │   └── didkey_test.go
│   │   ├── iota/
│   │   │   ├── anchor.go            # IOTA Tangle anchoring
│   │   │   ├── did.go               # did:iota implementation
│   │   │   └── iota_test.go
│   │   └── hedera/
│   │       ├── anchor.go            # Hedera HCS anchoring
│   │       ├── did.go               # did:hedera implementation
│   │       └── hedera_test.go
│   ├── anchor_test.go
│   ├── merkle_test.go
│   ├── credential_test.go
│   └── presentation_test.go
├── dart/                             # Dart port (for Flutter VC verification)
├── python/                           # Python port (for Sentinel)
└── docs/
    └── index.html                    # GitHub Pages documentation site
```

---

## 11. Build Plan

### Phase 1: Core Interfaces + did:key + Merkle Tree (Week 1-2)

**Tasks:**
1. `AnchorBackend` and `DIDBackend` interface definitions
2. Merkle tree implementation (SHA-256, binary tree, proof generation/verification)
3. `did:key` backend (create, resolve — zero dependencies, fully offline)
4. DID Document construction (W3C DID Core compliant)
5. Unit tests: Merkle proof verification, did:key roundtrip, DID Document structure

**Deliverable:** Working `go get`-able library with `did:key` and local Merkle proofs.

### Phase 2: Verifiable Credentials + Offline Queue (Week 3-4)

**Tasks:**
1. VC issuance with Ed25519Signature2020
2. VC verification (signature + expiry + revocation check)
3. VP creation and verification
4. Offline anchor queue (SQLite-backed, retry with exponential backoff)
5. Healthcare credential type constants
6. Integration tests: issue VC → verify VC, issue VP with multiple VCs → verify

**Deliverable:** Full offline identity + credential system.

### Phase 3: IOTA Backend (Week 5-6)

**Tasks:**
1. IOTA Tangle anchor backend (submit Merkle root as tagged data)
2. IOTA anchor verification (query Tangle, compare root)
3. `did:iota` DID backend (create, resolve via IOTA Identity framework)
4. Integration tests with IOTA testnet
5. Queue integration: enqueue → process when IOTA available → confirm

**Deliverable:** Working IOTA integration behind the pluggable interface.

### Phase 4: Hedera Backend (Week 7-8)

**Tasks:**
1. Hedera HCS anchor backend (submit to HCS topic)
2. Hedera anchor verification (query mirror node)
3. `did:hedera` DID backend
4. Integration tests with Hedera testnet

**Deliverable:** Working Hedera integration, proving the pluggable interface works across chains.

### Phase 5: Dart/Python Ports + Documentation (Week 9-10)

**Tasks:**
1. Dart port (credential verification for Flutter frontend)
2. Python port (for Sentinel Agent if needed)
3. GitHub Pages documentation site
4. Community outreach

**Deliverable:** Multi-language library ready for adoption.

---

## 12. Testing Strategy

### 12.1 Unit Tests

| Area | Coverage | Focus |
|------|----------|-------|
| Merkle tree | 100% | Construction, proof generation, proof verification, edge cases (1 leaf, 2 leaves, odd count) |
| did:key | 100% | Create, resolve, roundtrip, invalid inputs |
| DID Document | 100% | W3C compliance, JSON serialisation, field validation |
| VC issuance | 95% | Signing, all credential types, expiration handling |
| VC verification | 95% | Valid signature, expired, revoked, unknown issuer |
| VP | 95% | Single VC, multiple VCs, nested verification |
| Offline queue | 90% | Enqueue, retry logic, backoff, status transitions |

### 12.2 Integration Tests

| Test | Description |
|------|-------------|
| Merkle → anchor → verify | Compute tree, anchor to mock backend, verify receipt |
| did:key full flow | Create DID → issue VC → create VP → verify VP — all offline |
| Queue drain | Enqueue 10 anchors, start mock backend, verify all submitted |
| Backend switch | Anchor with IOTA backend, verify with same receipt using Hedera-style verify |
| Revocation propagation | Issue VC, revoke it, verify fails |
| Stale cache resolution | Resolve DID, disconnect network, resolve again from cache |

### 12.3 Compliance Tests

| Test | Standard |
|------|----------|
| DID Document structure | W3C DID Core 1.0 |
| VC structure | W3C Verifiable Credentials Data Model 1.1 |
| Ed25519Signature2020 | W3C Ed25519 Signature Suite |
| did:key encoding | did:key Method Specification (w3c-ccg) |

---

## 13. Performance Targets

All targets on Raspberry Pi 4.

| Operation | Target | Notes |
|-----------|--------|-------|
| Merkle tree (1,000 leaves) | < 10ms | SHA-256 computation |
| Merkle tree (10,000 leaves) | < 100ms | |
| Merkle proof generation | < 1ms | Single leaf |
| Merkle proof verification | < 1ms | |
| did:key create | < 1ms | No I/O |
| did:key resolve | < 1ms | No I/O |
| VC issuance (Ed25519 sign) | < 5ms | |
| VC verification (Ed25519 verify) | < 5ms | Offline, no network |
| VP verification (3 VCs) | < 15ms | Offline, no network |
| Queue enqueue | < 5ms | SQLite insert |
| Memory footprint | < 20MB RSS | Core library, no backend active |

---

*open-anchor • FibrinLab*  
*Tamper-evident data. Portable identity. Any chain.*
