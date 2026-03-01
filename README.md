# open-anchor

**A blockchain-agnostic Go library for data integrity anchoring, decentralised identity (DIDs), and W3C Verifiable Credentials.**

Designed to be offline-first, lightweight, and run on constrained hardware (Raspberry Pi 4, Android, field tablets).

## Features

- **Merkle tree anchoring** — SHA-256 binary Merkle tree with proof generation and verification
- **Pluggable blockchain backends** — anchor data to any supported ledger through the `AnchorBackend` interface
- **Decentralised identity (DIDs)** — create and resolve DIDs through the pluggable `DIDBackend` interface
- **`did:key` (offline)** — Ed25519 keys encoded directly in the DID string; no network required
- **W3C Verifiable Credentials** — issue and verify VCs with Ed25519Signature2020
- **Verifiable Presentations** — bundle multiple VCs into a signed presentation
- **Credential revocation** — signed revocation lists, checked locally during verification
- **Offline anchor queue** — SQLite-backed queue with exponential backoff; anchors when connectivity returns
- **DID resolution strategy** — cache → `did:key` (instant) → network backend → stale cache fallback

## Install

```sh
go get github.com/Open-Nucleus/open-anchor/go
```

Requires Go 1.22+. The only external dependency is `modernc.org/sqlite` (pure-Go, no CGo) for the offline queue.

## Quick Start

### Create a DID and issue a credential (fully offline)

```go
package main

import (
    "context"
    "crypto/ed25519"
    "fmt"

    anchor "github.com/Open-Nucleus/open-anchor/go"
    "github.com/Open-Nucleus/open-anchor/go/backends/didkey"
)

func main() {
    ctx := context.Background()
    engine := anchor.NewIdentityEngine(didkey.New())

    // Generate keys and create DIDs.
    issuerPub, issuerPriv, _ := ed25519.GenerateKey(nil)
    holderPub, holderPriv, _ := ed25519.GenerateKey(nil)

    issuerDoc, _ := engine.CreateDID(ctx, "key", issuerPub, anchor.DIDOptions{})
    holderDoc, _ := engine.CreateDID(ctx, "key", holderPub, anchor.DIDOptions{})

    // Issue a credential.
    vc, _ := engine.IssueCredential(ctx, issuerDoc.ID, issuerPriv, anchor.CredentialClaims{
        Type: []string{"VerifiableCredential", anchor.CredTypePractitionerLicense},
        Subject: map[string]interface{}{
            "id":       holderDoc.ID,
            "name":     "Dr Jane Smith",
            "license":  "MDCN/2026/12345",
            "specialty": "Paediatrics",
        },
    })

    // Verify the credential.
    result, _ := engine.VerifyCredential(ctx, vc)
    fmt.Printf("Valid: %v (offline: %s)\n", result.Valid, result.ResolutionMethod)

    // Bundle into a presentation and verify.
    vp, _ := engine.CreatePresentation(ctx, holderDoc.ID, holderPriv, []anchor.VerifiableCredential{*vc})
    vpResult, _ := engine.VerifyPresentation(ctx, vp)
    fmt.Printf("Presentation valid: %v\n", vpResult.Valid)
}
```

### Anchor data with Merkle proofs

```go
package main

import (
    "context"
    "crypto/sha256"
    "fmt"

    anchor "github.com/Open-Nucleus/open-anchor/go"
)

func main() {
    // Build a Merkle tree from data hashes.
    leaves := make([]anchor.MerkleLeaf, 3)
    for i, data := range []string{"record-1", "record-2", "record-3"} {
        h := sha256.Sum256([]byte(data))
        leaves[i] = anchor.MerkleLeaf{Path: data, Hash: h[:]}
    }

    tree, _ := anchor.NewMerkleTree(leaves)
    fmt.Printf("Merkle root: %x\n", tree.GetRoot())

    // Generate and verify an inclusion proof for leaf 0.
    proof, _ := tree.GenerateProof(0)
    valid := anchor.VerifyProof(leaves[0], proof, tree.GetRoot())
    fmt.Printf("Proof valid: %v\n", valid)
}
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  open-anchor                     │
│                                                  │
│  ┌────────────────┐    ┌──────────────────────┐  │
│  │ Anchor Engine   │    │  Identity Engine      │  │
│  │                 │    │                       │  │
│  │ Merkle Tree     │    │ DID Create / Resolve  │  │
│  │ Proof Generation│    │ VC Issue / Verify     │  │
│  │ Offline Queue   │    │ VP Create / Verify    │  │
│  │ Receipt Storage │    │ Revocation Lists      │  │
│  └───────┬─────────┘    └───────────┬───────────┘  │
│          │                          │              │
│  ┌───────▼──────────────────────────▼────────────┐ │
│  │            Backend Interface Layer             │ │
│  └───────┬─────────┬─────────┬─────────┬─────────┘ │
│          │         │         │         │           │
│  ┌───────▼──┐ ┌────▼──┐ ┌───▼───┐ ┌───▼────────┐  │
│  │  IOTA    │ │Hedera │ │did:key│ │ Future     │  │
│  │ (Phase 3)│ │(Phs 4)│ │  ✓    │ │ backends   │  │
│  └──────────┘ └───────┘ └───────┘ └────────────┘  │
└─────────────────────────────────────────────────┘
```

Two core engines sit behind pluggable backend interfaces:

- **AnchorEngine** — Merkle tree construction, proof generation, offline queue, receipt storage
- **IdentityEngine** — DID create/resolve, VC issue/verify, VP create/verify, revocation lists

## Key Interfaces

### AnchorBackend

Every blockchain integration implements this interface:

```go
type AnchorBackend interface {
    Name() string
    Anchor(ctx context.Context, proof AnchorProof) (AnchorReceipt, error)
    Verify(ctx context.Context, receipt AnchorReceipt) (VerificationResult, error)
    Status(ctx context.Context) (BackendStatus, error)
    SupportsOfflineVerification() bool
}
```

### DIDBackend

Every DID method implements this interface:

```go
type DIDBackend interface {
    Name() string
    Method() string
    Create(ctx context.Context, publicKey ed25519.PublicKey, opts DIDOptions) (*DIDDocument, error)
    Resolve(ctx context.Context, did string) (*DIDDocument, error)
    Update(ctx context.Context, did string, updates DIDUpdate, signingKey ed25519.PrivateKey) (*DIDDocument, error)
    Deactivate(ctx context.Context, did string, signingKey ed25519.PrivateKey) error
    RequiresNetwork() bool
}
```

## Project Structure

```
go/
├── anchor.go                    # AnchorBackend interface, AnchorEngine
├── merkle.go                    # SHA-256 binary Merkle tree
├── did.go                       # DIDBackend interface, IdentityEngine
├── credential.go                # W3C VC issuance and verification
├── presentation.go              # W3C VP creation and verification
├── revocation.go                # Signed revocation list management
├── queue.go                     # SQLite-backed offline anchor queue
├── backends/
│   └── didkey/
│       └── didkey.go            # did:key implementation (offline-only)
└── internal/
    └── base58/
        └── base58.go            # Base58btc encode/decode (vendored)
```

## Design Constraints

- **Offline-first** — all operations work without network; anchoring queues locally and executes when connectivity returns
- **Ed25519 only** — all signing uses Ed25519 with multibase (base58btc, `z` prefix) and multicodec prefix `0xed01`
- **W3C compliant** — DID Documents follow W3C DID Core 1.0; credentials follow W3C VC Data Model 1.1
- **Lightweight** — no JVM, no Docker, no CGo; must compile and run on Raspberry Pi 4 with < 20MB RSS

## Testing

```sh
cd go/
go test ./...           # run all tests (74 tests)
go test -race ./...     # race detector
go test -bench=. ./...  # benchmarks
go vet ./...            # static analysis
```

### Performance (Apple M4 Pro)

| Operation | Result |
|-----------|--------|
| Merkle tree (1,000 leaves) | 0.16ms |
| Merkle tree (10,000 leaves) | 1.58ms |

## Credential Types

Built-in type constants for healthcare and data integrity use cases:

| Constant | Type |
|----------|------|
| `CredTypePractitionerLicense` | `PractitionerLicenseCredential` |
| `CredTypePractitionerRole` | `PractitionerRoleCredential` |
| `CredTypeDataIntegrity` | `DataIntegrityCredential` |
| `CredTypeAuditTrail` | `AuditTrailCredential` |
| `CredTypeAuthorisedDeployment` | `AuthorisedDeploymentCredential` |
| `CredTypeSiteAccreditation` | `SiteAccreditationCredential` |
| `CredTypePatientConsent` | `PatientConsentCredential` |
| `CredTypeImmunisationRecord` | `ImmunisationRecordCredential` |

## Roadmap

- [x] Phase 1: Core interfaces + `did:key` + Merkle tree
- [x] Phase 2: Verifiable Credentials + offline queue
- [ ] Phase 3: IOTA backend (`did:iota` + Tangle anchoring)
- [ ] Phase 4: Hedera backend (`did:hedera` + HCS anchoring)
- [ ] Phase 5: Dart/Python ports + documentation

## Licence

Apache 2.0
