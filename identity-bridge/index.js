/**
 * Open Anchor — IOTA Identity Bridge
 *
 * Lightweight Express server wrapping @iota/identity-wasm for DID operations,
 * Verifiable Credential issuance/verification, and data notarization on IOTA
 * Rebased testnet. Called by the Go backend via HTTP.
 *
 * Usage:
 *   IOTA_NETWORK=testnet node index.js
 *
 * Endpoints:
 *   POST /did/create        — create a new did:iota DID (with local keypair)
 *   GET  /did/resolve/:did  — resolve a DID to its Document
 *   GET  /did/info          — list supported operations
 *   GET  /health            — health check
 *   POST /vc/issue          — issue a Verifiable Credential (JWT)
 *   POST /vc/verify         — verify a Verifiable Credential (JWT)
 *   POST /notarize          — notarize a data hash on IOTA
 *   GET  /notarize          — list all notarization records
 *   GET  /notarize/:id      — retrieve a notarization record
 */

const crypto = require('crypto');
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
  // VC-related imports
  Credential,
  Jwt,
  JwsAlgorithm,
  JwsSignatureOptions,
  JwtCredentialValidator,
  JwtCredentialValidationOptions,
  EdDSAJwsVerifier,
  FailFast,
  Timestamp,
  JwkMemStore,
  KeyIdMemStore,
  Storage,
  DecodedJwtCredential,
} = require('@iota/identity-wasm/node');
const { getFullnodeUrl, IotaClient } = require('@iota/iota-sdk/client');
const { Ed25519Keypair } = require('@iota/iota-sdk/keypairs/ed25519');
const { Transaction } = require('@iota/iota-sdk/transactions');

const app = express();
app.use(express.json({ limit: '2mb' }));

const PORT = process.env.PORT || 3001;
const NETWORK = process.env.IOTA_NETWORK || 'testnet';

// Use global to prevent WASM garbage collection
global.__iotaClient = null;
global.__identityClient = null;

// ──────────────────────────────────────────────────────────────────────────────
// In-memory DID Document + Storage cache
//
// Locally-created IotaDocuments all share the same zero-address DID because the
// real on-chain object ID is only assigned at publish time.  To support multiple
// local issuers we key the registry by a unique *alias* derived from the public
// key of the generated verification method.  The alias has the form:
//   did:iota:testnet:local:<sha256-of-public-key-x-coordinate>
//
// This alias is returned by POST /did/create and must be passed as issuerDid to
// POST /vc/issue.  The actual on-chain DID (all zeros) is used inside the VC
// itself — the alias is only for local registry lookup.
// ──────────────────────────────────────────────────────────────────────────────
const didRegistry = new Map(); // alias -> { doc, storage, fragment, alias }

// ──────────────────────────────────────────────────────────────────────────────
// In-memory notarization ledger (local fallback when no funded account)
// ──────────────────────────────────────────────────────────────────────────────
const notarizationLedger = new Map(); // notarization ID -> record

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Derive a deterministic local alias from an IotaDocument's first verification
 * method public key.  Format: did:iota:<network>:local:<hex-fingerprint>
 */
function deriveLocalAlias(doc) {
  const methods = doc.methods();
  if (!methods || methods.length === 0) {
    throw new Error('Document has no verification methods');
  }
  // Extract the public key JWK via toJSON() — the WASM method is tryPublicKeyJwk()
  const methodJson = methods[0].toJSON();
  const jwk = methodJson.publicKeyJwk;
  if (!jwk) {
    throw new Error('Verification method has no publicKeyJwk');
  }
  // The JWK 'x' parameter (base64url-encoded public key) is unique per key
  const fingerprint = crypto
    .createHash('sha256')
    .update(JSON.stringify(jwk))
    .digest('hex')
    .substring(0, 40); // 20-byte fingerprint is plenty
  return `did:iota:${NETWORK}:local:${fingerprint}`;
}

/**
 * Look up a DID entry in the registry.  Accepts either a local alias
 * (did:iota:...:local:...) or the canonical on-chain DID.  For the latter we
 * return the first matching entry (useful when there is only one issuer).
 */
function findRegistryEntry(didStr) {
  // Direct alias match
  if (didRegistry.has(didStr)) {
    return didRegistry.get(didStr);
  }
  // Fallback: search by on-chain DID
  for (const entry of didRegistry.values()) {
    if (entry.doc.id().toString() === didStr) {
      return entry;
    }
  }
  return null;
}

// ──────────────────────────────────────────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────────────────────────────────────────
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

// ──────────────────────────────────────────────────────────────────────────────
// GET /health
// ──────────────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    network: NETWORK,
    identity_client: global.__identityClient !== null,
    did_registry_size: didRegistry.size,
    notarization_ledger_size: notarizationLedger.size,
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /did/resolve/:did
// ──────────────────────────────────────────────────────────────────────────────
app.get('/did/resolve/:did', async (req, res) => {
  try {
    const didStr = decodeURIComponent(req.params.did);
    console.log(`[identity-bridge] Resolving: ${didStr}`);

    // Check local registry first (handles both aliases and on-chain DIDs)
    const local = findRegistryEntry(didStr);
    if (local) {
      return res.json({
        status: 'success',
        data: local.doc.toJSON(),
        source: 'local',
        alias: local.alias,
      });
    }

    if (!global.__identityClient) {
      return res.status(503).json({ error: 'Identity client not initialized' });
    }

    const did = IotaDID.parse(didStr);
    const doc = await global.__identityClient.resolveDid(did);

    res.json({
      status: 'success',
      data: doc.toJSON(),
      source: 'on-chain',
    });
  } catch (err) {
    console.error(`[identity-bridge] Resolve error:`, err.message);
    res.status(400).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /did/create
// ──────────────────────────────────────────────────────────────────────────────
app.post('/did/create', async (req, res) => {
  try {
    const { publicKeyBase64, practitionerId, role, siteId } = req.body;

    console.log(`[identity-bridge] Creating DID for practitioner: ${practitionerId}`);

    if (global.__identityClient === null) {
      return res.status(503).json({ error: 'Identity client not initialized' });
    }

    // Create a DID document with a verification method backed by an in-memory key
    const doc = new IotaDocument(NETWORK);
    const jwkStore = new JwkMemStore();
    const keyIdStore = new KeyIdMemStore();
    const storage = new Storage(jwkStore, keyIdStore);

    const fragment = await doc.generateMethod(
      storage,
      JwkMemStore.ed25519KeyType(),
      JwsAlgorithm.EdDSA,
      '#key-1',
      MethodScope.VerificationMethod(),
    );

    // Derive a unique local alias from the public key
    const alias = deriveLocalAlias(doc);
    const onChainDid = doc.id().toString();

    // Cache the document + storage for later VC operations
    didRegistry.set(alias, { doc, storage, fragment, alias });

    console.log(`[identity-bridge] Created DID: ${alias} (on-chain: ${onChainDid})`);

    res.json({
      status: 'success',
      data: {
        did: alias,
        onChainDid,
        document: doc.toJSON(),
        fragment,
        network: NETWORK,
        note: 'DID document created locally with Ed25519 verification method. Use the "did" field as the issuerDid for VC operations. On-chain publish requires funded IOTA account.',
      },
    });
  } catch (err) {
    console.error(`[identity-bridge] Create error:`, err.message);
    res.status(400).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /did/info
// ──────────────────────────────────────────────────────────────────────────────
app.get('/did/info', (req, res) => {
  res.json({
    service: 'Open Anchor Identity Bridge',
    version: '0.2.0',
    network: NETWORK,
    did_method: 'did:iota',
    operations: ['create', 'resolve', 'vc/issue', 'vc/verify', 'notarize'],
    sdk: '@iota/identity-wasm',
    standards: ['W3C DID Core 1.0', 'W3C Verifiable Credentials 1.1'],
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /vc/issue — Issue a Verifiable Credential (signed JWT)
//
// Body: {
//   issuerDid:      "did:iota:...:local:..." — local alias from /did/create
//   subjectDid:     "did:iota:..."           — DID of the credential subject
//   credentialType: "PractitionerLicense",
//   claims:         { name, role, ... }       — arbitrary claims about the subject
//   expirationDate: "2027-01-01T00:00:00Z"    (optional)
// }
// ──────────────────────────────────────────────────────────────────────────────
app.post('/vc/issue', async (req, res) => {
  try {
    const { issuerDid, subjectDid, credentialType, claims, expirationDate } = req.body;

    // Validate required fields
    if (!issuerDid) {
      return res.status(400).json({ error: 'issuerDid is required' });
    }
    if (!subjectDid) {
      return res.status(400).json({ error: 'subjectDid is required' });
    }
    if (!credentialType) {
      return res.status(400).json({ error: 'credentialType is required' });
    }
    if (!claims || typeof claims !== 'object') {
      return res.status(400).json({ error: 'claims must be a non-empty object' });
    }

    // Look up the issuer in our local registry
    const issuerEntry = findRegistryEntry(issuerDid);
    if (!issuerEntry) {
      return res.status(404).json({
        error: 'Issuer DID not found in local registry. Create it first via POST /did/create.',
        hint: 'Use the "did" value returned by /did/create as the issuerDid.',
      });
    }

    const { doc: issuerDoc, storage, fragment } = issuerEntry;
    const onChainDid = issuerDoc.id().toString();

    console.log(`[identity-bridge] Issuing VC: type=${credentialType}, issuer=${issuerDid}`);

    // Build the W3C Verifiable Credential
    // The VC uses the on-chain DID as the issuer (W3C spec compliance)
    const credentialData = {
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: [credentialType],
      issuer: onChainDid,
      credentialSubject: {
        id: subjectDid,
        ...claims,
      },
      issuanceDate: Timestamp.nowUTC(),
    };

    if (expirationDate) {
      credentialData.expirationDate = Timestamp.parse(expirationDate);
    }

    const credential = new Credential(credentialData);

    // Sign the credential as a JWT using the issuer's key
    const jwt = await issuerDoc.createCredentialJwt(
      storage,
      fragment,
      credential,
      new JwsSignatureOptions(),
    );

    const jwtString = jwt.toString();

    console.log(`[identity-bridge] VC issued: ${credentialData.id} (JWT ${jwtString.length} bytes)`);

    res.json({
      status: 'success',
      data: {
        credential: credential.toJSON(),
        jwt: jwtString,
        credentialId: credentialData.id,
        issuer: issuerDid,
        issuerOnChainDid: onChainDid,
        subject: subjectDid,
        type: credentialType,
        issuedAt: new Date().toISOString(),
      },
    });
  } catch (err) {
    console.error(`[identity-bridge] VC issue error:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /vc/verify — Verify a Verifiable Credential (JWT)
//
// Body: {
//   credential: "eyJhbGci..."  — the JWT string, OR
//   credential: { ... }        — object with a .jwt field
//   jwt: "eyJhbGci..."         — alternative top-level JWT field
// }
//
// The issuer's DID document is resolved from the local registry or on-chain.
// ──────────────────────────────────────────────────────────────────────────────
app.post('/vc/verify', async (req, res) => {
  try {
    let jwtString = null;

    // Accept JWT as a string directly, or as an object with a .jwt field
    if (typeof req.body.credential === 'string') {
      jwtString = req.body.credential;
    } else if (req.body.credential && typeof req.body.credential === 'object') {
      jwtString = req.body.credential.jwt || req.body.jwt;
    } else if (typeof req.body.jwt === 'string') {
      jwtString = req.body.jwt;
    }

    if (!jwtString) {
      return res.status(400).json({
        error: 'credential (JWT string) is required. Pass as { "credential": "eyJ..." } or { "jwt": "eyJ..." }',
      });
    }

    console.log(`[identity-bridge] Verifying VC (JWT ${jwtString.length} bytes)`);

    const jwt = new Jwt(jwtString);

    // Decode the JWT header to extract the issuer's DID (kid field)
    const headerB64 = jwtString.split('.')[0];
    const headerJson = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
    const kid = headerJson.kid || '';
    // kid format: "did:iota:testnet:0x...#key-1" — extract the DID part
    const issuerDid = kid.split('#')[0];

    if (!issuerDid) {
      return res.status(400).json({ error: 'Could not extract issuer DID from JWT header' });
    }

    console.log(`[identity-bridge] VC issuer (from JWT): ${issuerDid}`);

    // Resolve the issuer's DID document — try local registry first, then on-chain
    let issuerDoc = null;
    let resolvedFrom = 'unknown';

    const localEntry = findRegistryEntry(issuerDid);
    if (localEntry) {
      issuerDoc = localEntry.doc;
      resolvedFrom = 'local';
      console.log(`[identity-bridge] Issuer resolved from local registry`);
    } else if (global.__identityClient) {
      try {
        const did = IotaDID.parse(issuerDid);
        issuerDoc = await global.__identityClient.resolveDid(did);
        resolvedFrom = 'on-chain';
        console.log(`[identity-bridge] Issuer resolved from on-chain`);
      } catch (resolveErr) {
        return res.status(404).json({
          error: `Could not resolve issuer DID: ${resolveErr.message}`,
          issuer: issuerDid,
        });
      }
    } else {
      return res.status(503).json({
        error: 'Cannot verify: issuer DID not in local registry and identity client not initialized',
      });
    }

    // Verify the JWT signature against the issuer's document
    const validator = new JwtCredentialValidator(new EdDSAJwsVerifier());
    const decoded = validator.validate(
      jwt,
      issuerDoc,
      new JwtCredentialValidationOptions(),
      FailFast.FirstError,
    );

    const decodedCredential = decoded.credential().toJSON();

    console.log(`[identity-bridge] VC verified successfully`);

    res.json({
      status: 'success',
      data: {
        valid: true,
        issuer: issuerDid,
        credential: decodedCredential,
        resolvedFrom,
        verifiedAt: new Date().toISOString(),
      },
    });
  } catch (err) {
    console.error(`[identity-bridge] VC verify error:`, err.message);

    // Distinguish between validation failures and server errors
    const msg = (err.message || '').toLowerCase();
    const isValidationError =
      msg.includes('signature') ||
      msg.includes('expired') ||
      msg.includes('invalid') ||
      msg.includes('verification') ||
      msg.includes('credential') ||
      msg.includes('jws') ||
      msg.includes('jwt') ||
      msg.includes('decode') ||
      msg.includes('deserializ');

    if (isValidationError) {
      return res.json({
        status: 'success',
        data: {
          valid: false,
          reason: err.message,
          verifiedAt: new Date().toISOString(),
        },
      });
    }

    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /notarize — Notarize a data hash on IOTA
//
// Body: {
//   dataHash:    "0xabcdef..." — hex-encoded hash of the data to notarize
//   description: "Patient record anchor" (optional)
//   metadata:    { ... }       (optional, arbitrary metadata)
// }
//
// Strategy:
//   1. If env vars ANCHOR_PACKAGE_ID and IOTA_SIGNER_KEY are set, submit an
//      on-chain Move transaction to the deployed anchor_root() function.
//   2. Otherwise, create a locally timestamped, SHA-256-chained notarization
//      record that can be verified offline and anchored on-chain later.
// ──────────────────────────────────────────────────────────────────────────────
app.post('/notarize', async (req, res) => {
  try {
    const { dataHash, description, metadata } = req.body;

    if (!dataHash || typeof dataHash !== 'string') {
      return res.status(400).json({ error: 'dataHash (hex string) is required' });
    }

    // Normalize: strip 0x prefix for internal use
    const cleanHash = dataHash.startsWith('0x') ? dataHash.slice(2) : dataHash;

    // Validate hex format
    if (!/^[0-9a-fA-F]+$/.test(cleanHash)) {
      return res.status(400).json({ error: 'dataHash must be a valid hex string' });
    }

    console.log(`[identity-bridge] Notarizing hash: 0x${cleanHash.substring(0, 16)}...`);

    const anchorPackageId = process.env.ANCHOR_PACKAGE_ID;
    const signerKey = process.env.IOTA_SIGNER_KEY;

    // ── On-chain notarization (when configured) ─────────────────────────
    if (anchorPackageId && signerKey && global.__iotaClient) {
      try {
        const keypair = Ed25519Keypair.fromSecretKey(Buffer.from(signerKey, 'hex'));

        // Pad or truncate to exactly 32 bytes (the Move contract requires 32)
        const merkleRootBytes = Buffer.from(cleanHash.padEnd(64, '0').substring(0, 64), 'hex');

        const tx = new Transaction();
        tx.moveCall({
          target: `${anchorPackageId}::anchoring::anchor_root`,
          arguments: [
            tx.pure('vector<u8>', Array.from(merkleRootBytes)),
            tx.pure('u64', '0'),
            tx.object('0x6'), // IOTA system Clock object
          ],
        });

        const result = await global.__iotaClient.signAndExecuteTransaction({
          signer: keypair,
          transaction: tx,
        });

        console.log(`[identity-bridge] On-chain notarization: ${result.digest}`);

        return res.json({
          status: 'success',
          data: {
            notarizationId: result.digest,
            timestamp: new Date().toISOString(),
            hash: `0x${cleanHash}`,
            description: description || null,
            metadata: metadata || null,
            network: NETWORK,
            method: 'on-chain',
            transactionDigest: result.digest,
          },
        });
      } catch (onChainErr) {
        console.warn(
          `[identity-bridge] On-chain notarization failed, falling back to local: ${onChainErr.message}`,
        );
        // Fall through to local notarization
      }
    }

    // ── Local notarization (offline-capable fallback) ───────────────────
    const notarizationId = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    // Build a deterministic record hash: SHA-256(dataHash + timestamp + description)
    const recordPayload = `${cleanHash}:${timestamp}:${description || ''}`;
    const recordHash = crypto.createHash('sha256').update(recordPayload).digest('hex');

    // Chain to previous notarization for tamper evidence (hash chain)
    const entries = Array.from(notarizationLedger.values());
    const previousRecordHash =
      entries.length > 0 ? entries[entries.length - 1].recordHash : null;
    const previousHashHex = previousRecordHash || '0'.repeat(64);
    const chainHash = crypto
      .createHash('sha256')
      .update(`${previousHashHex}:${recordHash}`)
      .digest('hex');

    const record = {
      notarizationId,
      timestamp,
      hash: `0x${cleanHash}`,
      recordHash,
      chainHash,
      previousHash: previousHashHex,
      description: description || null,
      metadata: metadata || null,
      network: NETWORK,
      method: 'local',
      sequenceNumber: notarizationLedger.size + 1,
    };

    notarizationLedger.set(notarizationId, record);

    console.log(
      `[identity-bridge] Local notarization: ${notarizationId} (seq #${record.sequenceNumber})`,
    );

    res.json({
      status: 'success',
      data: record,
    });
  } catch (err) {
    console.error(`[identity-bridge] Notarize error:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /notarize/:id — Retrieve a notarization record
// ──────────────────────────────────────────────────────────────────────────────
app.get('/notarize/:id', (req, res) => {
  const record = notarizationLedger.get(req.params.id);
  if (!record) {
    return res.status(404).json({ error: 'Notarization record not found' });
  }
  res.json({ status: 'success', data: record });
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /notarize — List all notarization records
// ──────────────────────────────────────────────────────────────────────────────
app.get('/notarize', (req, res) => {
  const records = Array.from(notarizationLedger.values());
  res.json({
    status: 'success',
    data: {
      count: records.length,
      records,
    },
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Start server
// ──────────────────────────────────────────────────────────────────────────────
init().then(() => {
  console.log(
    '[identity-bridge] After init, global.__identityClient:',
    global.__identityClient !== null,
  );
  app.listen(PORT, () => {
    console.log(`[identity-bridge] Running on http://localhost:${PORT}`);
    console.log(`[identity-bridge] Network: ${NETWORK}`);
    console.log(`[identity-bridge] Endpoints:`);
    console.log(`  GET  /health`);
    console.log(`  GET  /did/info`);
    console.log(`  GET  /did/resolve/:did`);
    console.log(`  POST /did/create`);
    console.log(`  POST /vc/issue`);
    console.log(`  POST /vc/verify`);
    console.log(`  POST /notarize`);
    console.log(`  GET  /notarize`);
    console.log(`  GET  /notarize/:id`);
  });
});
