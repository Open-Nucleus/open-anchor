// Package hedera implements the Hedera Hashgraph backend for data-integrity
// anchoring via the Hedera Consensus Service (HCS) and did:hedera DID operations.
//
// Anchoring submits Merkle roots as HCS topic messages. Verification queries the
// Hedera Mirror Node REST API. Transaction signing and submission use the official
// Hedera Go SDK.
package hedera

import "fmt"

const (
	// Default Mirror Node endpoints.
	TestnetMirrorURL  = "https://testnet.mirrornode.hedera.com"
	MainnetMirrorURL  = "https://mainnet-public.mirrornode.hedera.com"
	PreviewMirrorURL  = "https://previewnet.mirrornode.hedera.com"

	// DefaultNetwork is the network used when none is specified.
	DefaultNetwork = "testnet"
)

// Config holds configuration for the Hedera backend.
type Config struct {
	// Network identifies the Hedera network: "mainnet", "testnet", or "previewnet".
	Network string

	// OperatorID is the Hedera account ID that pays for transactions (e.g. "0.0.12345").
	OperatorID string

	// OperatorKey is the hex-encoded Ed25519 private key for the operator account.
	OperatorKey string

	// TopicID is the HCS topic used for Merkle root anchoring (e.g. "0.0.67890").
	TopicID string

	// DIDTopicID is the HCS topic used for DID document operations.
	// If empty, TopicID is used for both anchoring and DIDs.
	DIDTopicID string

	// MirrorURL is the Mirror Node REST API base URL.
	// Defaults to the testnet mirror if empty.
	MirrorURL string
}

// Validate checks required fields and applies defaults.
func (c *Config) Validate() error {
	if c.OperatorID == "" {
		return fmt.Errorf("hedera: OperatorID is required")
	}
	if c.OperatorKey == "" {
		return fmt.Errorf("hedera: OperatorKey is required")
	}
	if c.TopicID == "" {
		return fmt.Errorf("hedera: TopicID is required")
	}
	if c.Network == "" {
		c.Network = DefaultNetwork
	}
	if c.DIDTopicID == "" {
		c.DIDTopicID = c.TopicID
	}
	if c.MirrorURL == "" {
		switch c.Network {
		case "mainnet":
			c.MirrorURL = MainnetMirrorURL
		case "previewnet":
			c.MirrorURL = PreviewMirrorURL
		default:
			c.MirrorURL = TestnetMirrorURL
		}
	}
	return nil
}
