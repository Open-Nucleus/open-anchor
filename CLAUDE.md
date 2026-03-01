# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

open-anchor is a blockchain-agnostic Go library for data integrity anchoring, decentralised identity (DIDs), and W3C Verifiable Credentials. It is designed to be offline-first, lightweight, and run on constrained hardware (Raspberry Pi 4, Android, field tablets).

**Repo:** github.com/Open-Nucleus/open-anchor
**Licence:** Apache 2.0
**Spec:** `open-anchor-spec.md` is the authoritative design document.

## Build Commands

All Go source lives under `go/`. From that directory:

```sh
cd go/
go build ./...          # build everything
go test ./...           # run all tests
go test -run TestName   # run a single test
go vet ./...            # static analysis
go test -race ./...     # race detector
go test -bench=. ./...  # benchmarks (performance targets in spec §13)
```

The project has no JVM, Docker, or heavy build-system dependencies. SQLite (via CGo) is the only non-pure-Go dependency (used for the offline anchor queue).

## Architecture

Two core engines sit behind pluggable backend interfaces:

- **AnchorEngine** (`anchor.go`) — Merkle tree construction, proof generation, offline queue, receipt storage. Uses the `AnchorBackend` interface.
- **IdentityEngine** (`did.go`) — DID create/resolve, VC issue/verify, VP create/verify, revocation lists. Uses the `DIDBackend` interface.

### Key Interfaces

`AnchorBackend` — every blockchain integration implements this (Anchor, Verify, Status, SupportsOfflineVerification). Defined in `anchor.go`.

`DIDBackend` — every DID method implements this (Create, Resolve, Update, Deactivate, RequiresNetwork). Defined in `did.go`.

### Backend Implementations

All backends live in `go/backends/<name>/`:

| Backend | DID Method | Anchoring | Network Required |
|---------|-----------|-----------|-----------------|
| `didkey/` | `did:key` | N/A | No (offline-only) |
| `iota/` | `did:iota` | IOTA Tangle | Yes |
| `hedera/` | `did:hedera` | Hedera HCS | Yes |

### Core Source Files (go/)

| File | Responsibility |
|------|---------------|
| `anchor.go` | AnchorBackend interface, AnchorEngine, core types |
| `merkle.go` | SHA-256 binary Merkle tree, proof generation/verification |
| `queue.go` | SQLite-backed offline anchor queue with exponential backoff |
| `did.go` | DIDBackend interface, IdentityEngine, DID resolution with cache/fallback |
| `credential.go` | W3C VC issuance and verification (Ed25519Signature2020) |
| `presentation.go` | W3C VP creation and verification |
| `revocation.go` | Signed revocation list management |

## Design Constraints

- **Offline-first:** All operations must work without network. Anchoring queues locally and executes when connectivity returns. Verification works fully offline using `did:key` and cached proofs.
- **No heavy dependencies:** No JVM, no Docker. Must compile and run on Raspberry Pi 4 with < 20MB RSS.
- **Ed25519 only:** All signing uses Ed25519. Keys are encoded as multibase (base58btc, prefix 'z') with multicodec prefix 0xed01.
- **W3C compliant:** DID Documents follow W3C DID Core 1.0. Credentials follow W3C VC Data Model 1.1. Signatures use Ed25519Signature2020 suite.

## DID Resolution Strategy

Resolution follows a priority chain: local cache → `did:key` (instant offline) → network backend → stale cache fallback. See spec §4.4.

## Offline Queue Schema

The anchor queue uses SQLite with the schema in spec §3.4. Status values: `pending`, `submitted`, `confirmed`, `failed`. Retry uses exponential backoff (default: 2x, 1min initial, 24h max, 10 retries).

## Multi-Language Ports

Dart (`dart/`) and Python (`python/`) ports are planned for later phases. The Go implementation is the reference.

## Implementation Phases

1. Core interfaces + `did:key` + Merkle tree
2. Verifiable Credentials + offline queue
3. IOTA backend
4. Hedera backend
5. Dart/Python ports + documentation
