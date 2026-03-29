/**
 * Open Anchor — IOTA Identity Bridge
 *
 * Lightweight Express server wrapping @iota/identity-wasm for DID operations
 * on IOTA Rebased testnet. Called by the Go backend via HTTP.
 *
 * Usage:
 *   IOTA_NETWORK=testnet node index.js
 *
 * Endpoints:
 *   POST /did/create   — create a new did:iota DID
 *   GET  /did/resolve/:did — resolve a DID to its Document
 *   GET  /health       — health check
 */

const express = require('express');
const {
  IotaDocument,
  IotaDID,
  IdentityClient,
  IdentityClientReadOnly,
  MethodScope,
  VerificationMethod,
  IotaDocumentMetadata,
  CoreDocument,
} = require('@iota/identity-wasm/node');
const { getFullnodeUrl, IotaClient } = require('@iota/iota-sdk/client');
const { Ed25519Keypair } = require('@iota/iota-sdk/keypairs/ed25519');
const { Transaction } = require('@iota/iota-sdk/transactions');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3001;
const NETWORK = process.env.IOTA_NETWORK || 'testnet';

// Use global to prevent WASM garbage collection
global.__iotaClient = null;
global.__identityClient = null;

// Initialize IOTA client on startup
async function init() {
  try {
    const rpcUrl = getFullnodeUrl(NETWORK);
    console.log(`[identity-bridge] Connecting to IOTA ${NETWORK}: ${rpcUrl}`);
    global.__iotaClient = new IotaClient({ url: rpcUrl });
    global.__identityClient = await IdentityClientReadOnly.create(global.__iotaClient);
    console.log(`[identity-bridge] IOTA Identity client ready`);
  } catch (err) {
    console.error(`[identity-bridge] Failed to initialize:`, err.message);
  }
}

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    network: NETWORK,
    identity_client: global.__identityClient !== null,
  });
});

// Resolve a DID
app.get('/did/resolve/:did', async (req, res) => {
  try {
    const didStr = decodeURIComponent(req.params.did);
    console.log(`[identity-bridge] Resolving: ${didStr}`);

    if (!global.__identityClient) {
      return res.status(503).json({ error: 'Identity client not initialized' });
    }

    const did = IotaDID.parse(didStr);
    const doc = await global.__identityClient.resolveDid(did);

    res.json({
      status: 'success',
      data: doc.toJSON(),
    });
  } catch (err) {
    console.error(`[identity-bridge] Resolve error:`, err.message);
    res.status(400).json({ error: err.message });
  }
});

// Create a DID (informational — shows what the SDK can do)
app.post('/did/create', async (req, res) => {
  try {
    const { publicKeyBase64, practitionerId, role, siteId } = req.body;

    console.log(`[identity-bridge] Creating DID for practitioner: ${practitionerId}`);

    if (global.__identityClient === null) {
      return res.status(503).json({ error: 'Identity client not initialized' });
    }

    // For demo: create a DID document structure
    // Full on-chain creation requires a funded keypair and transaction signing
    const doc = new IotaDocument(NETWORK);

    // Add a verification method
    // Note: actual on-chain publish requires IdentityClient (write mode) with funded account

    res.json({
      status: 'success',
      data: {
        did: doc.id().toString(),
        document: doc.toJSON(),
        network: NETWORK,
        note: 'DID document created locally. On-chain publish requires funded IOTA account.',
      },
    });
  } catch (err) {
    console.error(`[identity-bridge] Create error:`, err.message);
    res.status(400).json({ error: err.message });
  }
});

// List supported operations
app.get('/did/info', (req, res) => {
  res.json({
    service: 'Open Anchor Identity Bridge',
    version: '0.1.0',
    network: NETWORK,
    did_method: 'did:iota',
    operations: ['create', 'resolve'],
    sdk: '@iota/identity-wasm',
    standards: ['W3C DID Core 1.0', 'W3C Verifiable Credentials 1.1'],
  });
});

// Start server
init().then(() => {
  console.log('[identity-bridge] After init, global.__identityClient:', global.__identityClient !== null);
  app.listen(PORT, () => {
    console.log(`[identity-bridge] Running on http://localhost:${PORT}`);
    console.log(`[identity-bridge] Network: ${NETWORK}`);
    console.log(`[identity-bridge] Endpoints:`);
    console.log(`  GET  /health`);
    console.log(`  GET  /did/info`);
    console.log(`  GET  /did/resolve/:did`);
    console.log(`  POST /did/create`);
  });
});
