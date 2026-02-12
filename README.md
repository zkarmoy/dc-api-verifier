# DC API Verifier Playground

A lightweight playground for Digital Credentials API + OpenID4VP (unsigned) and ISO 18013-7 over DC API. It focuses on ISO/IEC 18013-5 mdoc parsing and extraction for testing wallets and requests.

This is a demo and not production-ready.

**Supported Protocols**
1. OpenID4VP (unsigned) over DC API (`response_mode=dc_api.jwt`)
2. ISO 18013-7 DeviceRequest over DC API (`protocol=org-iso-mdoc`)

**Supported Credentials (mdoc)**
1. PID `eu.europa.ec.eudi.pid.1`
2. Age Verification `eu.europa.ec.av.1`

## Features

**OpenID4VP (Unsigned) via DC API**
- Generates dynamic DCQL requests
- Supports live wallet interaction
- Editable request JSON before sending

**ISO 18013-7 (DeviceRequest over DC API)**
- Generates an ISO 18013-5 DeviceRequest (CBOR, base64url)
- Invokes the wallet through DC API with `protocol: "org-iso-mdoc"`

**Credential Attribute Selection**
- PID and AV attribute selectors

**Verification and Display**
- Parses DeviceResponse and IssuerSigned items
- Verifies IssuerAuth signature
- Verifies valueDigests (when present)
- Displays extracted attributes and issuer certificate

**Developer Tools**
- Raw JSON viewer (sanitized)
- Editable request JSON
- CBOR debug section
- Server logs streamed into UI console
- Annex C / HPKE debug logs (ISO 18013-7)

## Architecture

```
Browser (UI)
  -> Node.js Express Backend
  -> Wallet (DC API / OpenID4VP)
```

**Backend**
- Express server
- CBOR parsing
- ISO 18013-5 mdoc parsing
- IssuerAuth verification
- valueDigest verification
- DeviceAuth parsing (full verification requires SessionTranscript)

**Frontend**
- Static HTML / CSS / JS
- DCQL request builder
- Step-based flow UI

## Protocols Overview

This playground supports two different transport protocols that ultimately yield an mdoc `DeviceResponse`. They are similar at the cryptographic object level (ISO 18013-5) but differ in how the request is built and transported.

### Digital Credentials API (DC API)

DC API is the browser-facing transport used to communicate with a wallet. It provides an invocation interface from a web app and carries a request and response payload. In this project, DC API is the transport for both:

- **OpenID4VP (unsigned)** using `response_mode=dc_api.jwt`.
- **ISO 18013-7** using `protocol=org-iso-mdoc`.

DC API does **not** define how credentials are structured; it is a transport mechanism. The credential format depends on the chosen protocol and format (here, `mso_mdoc`).

### ISO 18013-5 (mdoc)

ISO/IEC 18013-5 defines the mdoc data model and cryptographic structures:

- `DeviceResponse` contains `documents`, each with `docType`, `issuerSigned`, and optionally `deviceSigned`.
- `issuerSigned` includes:
  - `issuerAuth` (COSE_Sign1 over the MSO)
  - `nameSpaces` (arrays of `IssuerSignedItemBytes`)
- `valueDigests` in the MSO allow per-item integrity verification.

This verifier parses and extracts attributes from `IssuerSignedItemBytes` and verifies the issuer signature and value digests when present.

### ISO 18013-7 (DeviceRequest over DC API)

ISO 18013-7 describes how a verifier sends an **ISO 18013-5 DeviceRequest** via DC API and receives an encrypted response. The response is **not** a raw `DeviceResponse` but an encrypted envelope that must be decrypted before parsing the mdoc.

In the Annex C DC API transport profile:

- Request contains:
  - `deviceRequest` (CBOR, base64url)
  - `encryptionInfo` (CBOR, base64url) with nonce and verifier public key
- Response contains:
  - `EncryptedResponse = ["dcapi", { enc: bstr, cipherText: bstr }]`

The response is encrypted using **HPKE single-shot** (RFC 9180) with:

- **KEM**: DHKEM(P-256)
- **KDF**: HKDF-SHA256
- **AEAD**: AES-128-GCM

The HPKE `info` is the CBOR-encoded `SessionTranscript` (see below) and `aad` is empty.

### OpenID4VP (Unsigned) over DC API

OpenID4VP is an OAuth-style protocol for requesting verifiable credentials from a wallet. In this playground:

- The request is **unsigned** (dev mode), with a DCQL query describing requested claims.
- The wallet responds using `response_mode=dc_api.jwt`.
- The response can be:
  - a JWE (encrypted) JWT, or
  - a nested response containing `vp_token` entries.

For mdoc, the `vp_token` value is a base64url-encoded CBOR `DeviceResponse` (or `Document`), which the verifier parses directly.

### SessionTranscript (Annex C)

The SessionTranscript binds the request and origin to the cryptographic session. In Annex C, it is:

```
SessionTranscript = [
  null,
  null,
  ["dcapi", dcapiInfoHash]
]

dcapiInfo = [Base64EncryptionInfo, SerializedOrigin]

SerializedOrigin = tstr

dcapiInfoHash = SHA-256(CBOR(dcapiInfo))
```

- `Base64EncryptionInfo` is the base64url CBOR of `encryptionInfo`.
- `SerializedOrigin` is the ASCII serialization of the origin.

The **SessionTranscript** is the HPKE `info` input for ISO 18013-7 encryption/decryption.

## OpenID4VP vs ISO 18013-7 (Key Differences)

1. **Request Shape**
- **OID4VP**: OAuth-style request with DCQL claims.
- **ISO 18013-7**: `deviceRequest` (CBOR) + `encryptionInfo`.

2. **Response Transport**
- **OID4VP**: JWT container (`dc_api.jwt`), may be encrypted or nested.
- **ISO 18013-7**: `EncryptedResponse` with HPKE ciphertext.

3. **Crypto**
- **OID4VP**: relies on the JWT container and credential format.
- **ISO 18013-7**: always uses HPKE single-shot with AES-128-GCM.

4. **Decryption**
- **OID4VP**: decode JWT -> extract `vp_token` -> parse CBOR.
- **ISO 18013-7**: HPKE decrypt -> obtain `DeviceResponse` -> parse CBOR.

## Getting Started

1. Install dependencies

```bash
npm install
```

2. Start the server

```bash
node server.js
```

Open:

```
http://localhost:3000
```

Some Digital Credential APIs require a secure context (https). Run behind a local HTTPS proxy if needed.

## Using the App

**Step 1: Build Request**
- Pick protocol: OpenID4VP or ISO 18013-7
- Pick credential type and attributes

**Step 2: Send Request**
- Use "Send to Wallet" to invoke the Digital Credentials API

**Step 3: Receive Response**
- Paste the wallet response JSON

**Step 4: Verify**
- IssuerAuth and valueDigest verification are shown

**Step 5: Attributes**
- Extracted attributes and portrait are displayed

## ISO 18013-5 Notes

**Value Digests**
Each disclosed attribute is verified against:

```
MSO.valueDigests[namespace][digestID]
```

Digest is computed over:

```
IssuerSignedItemBytes = Tag(24, embedded CBOR)
```

**DeviceAuth**
Device signature verification requires the correct SessionTranscript. This demo parses DeviceAuth but does not fully verify it unless transcript bytes are provided.

## Debugging (ISO 18013-7 / Annex C)

The UI console mirrors backend logs. For ISO 18013-7 (DC API / `org-iso-mdoc`), the server emits detailed Annex C debugging output when the debug env vars are enabled, including:

- `enc` (ephemeral public key) hex
- `cipherText` hex
- `dcapiInfo` CBOR hex
- `dcapiInfoHash` hex
- `SessionTranscript` (info) CBOR hex
- `aad` (empty) hex
- Origin and encryptionInfo (b64url)
- HPKE intermediate secrets when available:
  - `sharedSecret`
  - `aeadKey`
  - `baseNonce`

These logs appear in the UI console as `[iso-mdoc][annexC] ...` lines.

**Enable debug logs**

```bash
# Standard debug (server + UI console)
DEBUG=1 node server.js

# Enable Annex C / HPKE logs
DEBUG=1 DEBUG_ANNEXC=1 node server.js

# Include intermediate secrets (sharedSecret, aeadKey, baseNonce) if available
DEBUG=1 DEBUG_ANNEXC=1 DEBUG_ANNEXC_SECRETS=1 node server.js
```

Note: Some HPKE internals may not be exposed by the library. In those cases, the server logs indicate the value is unavailable.

## Project Structure

```
.
├── server.js
├── public/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── package.json
└── README.md
```

## Customization

**Add PID Attributes**
- Type attribute name and click +
- Apply edits to request JSON if needed

**Edit Request JSON**
- Modify the JSON in the editor
- Click "Apply edits"

## Known Limitations

- No production-grade security hardening
- DeviceAuth full verification requires SessionTranscript
- No certificate trust chain validation
- HTTPS not enforced by default
