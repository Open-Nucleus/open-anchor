// Package iota implements the IOTA Rebased (Move-based L1) backend for
// data-integrity anchoring and did:iota DID operations.
//
// Interaction with the IOTA network uses JSON-RPC 2.0. Anchoring is performed
// via a Move smart contract, and DID operations use the IOTA Identity modules.
// Transaction signing follows the IOTA/Sui convention: Ed25519 over a
// Blake2b-256 hash of the intent-prefixed transaction bytes.
package iota

import "fmt"

const (
	// DefaultGasBudget is the default gas budget in nanos (10M ≈ 0.01 IOTA).
	DefaultGasBudget uint64 = 10_000_000

	// DefaultClockObjectID is the well-known shared Clock object on IOTA/Sui.
	DefaultClockObjectID = "0x6"

	// Network endpoint constants.
	MainnetRPCURL = "https://api.mainnet.iota.cafe"
	TestnetRPCURL = "https://api.testnet.iota.cafe"
	DevnetRPCURL  = "https://api.devnet.iota.cafe"
)

// Config holds configuration for the IOTA backend.
type Config struct {
	// RPCURL is the JSON-RPC endpoint (e.g. "https://api.testnet.iota.cafe").
	RPCURL string

	// NetworkID identifies the network: "mainnet", "testnet", or "devnet".
	NetworkID string

	// AnchorPackageID is the published Move package ID for the anchoring module.
	AnchorPackageID string

	// IdentityPackageID is the IOTA Identity Move package ID (for did:iota).
	IdentityPackageID string

	// ClockObjectID is the system shared Clock object ID (default: "0x6").
	ClockObjectID string

	// GasBudget is the default gas budget in nanos (default: 10_000_000).
	GasBudget uint64
}

// Validate checks that required fields are set and applies defaults.
func (c *Config) Validate() error {
	if c.RPCURL == "" {
		return fmt.Errorf("iota: RPCURL is required")
	}
	if c.AnchorPackageID == "" && c.IdentityPackageID == "" {
		return fmt.Errorf("iota: at least one of AnchorPackageID or IdentityPackageID is required")
	}
	if c.ClockObjectID == "" {
		c.ClockObjectID = DefaultClockObjectID
	}
	if c.GasBudget == 0 {
		c.GasBudget = DefaultGasBudget
	}
	return nil
}
