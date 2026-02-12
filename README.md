# DC API Verifier Playground

A lightweight playground for Digital Credentials API + OpenID4VP (unsigned) and ISO 18013-7 over DC API. It focuses on ISO/IEC 18013-5 mdoc parsing and extraction for testing wallets and requests.

This is a demo and not production-ready.

**Supported Protocols**
1. OpenID4VP (unsigned) over DC API (`response_mode=dc_api.jwt`)
2. ISO 18013-7 DeviceRequest over DC API (`protocol=org-iso-mdoc`)

**Supported Credentials (mdoc)**
1. PID `eu.europa.ec.eudi.pid.1`
2. Age Verification `eu.europa.ec.av.1`
3. Custom mdoc doctypes via issuer metadata import (mso_mdoc only)

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
- Custom mdoc claim sets imported from issuer metadata

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
- Optional: paste issuer metadata to load supported mdoc credentials

**Step 2: Send Request**
- Use "Send to Wallet" to invoke the Digital Credentials API

**Step 3: Receive Response**
- Paste or upload the wallet response JSON

**Step 4: Verify**
- IssuerAuth and valueDigest verification are shown

**Step 5: Attributes**
- Extracted attributes and portrait are displayed

## Testing With Issuer Metadata

1. Paste issuer metadata JSON in the Supported Credentials section.
2. Click **Import metadata**.
3. Select a credential card and click **Use for request**.
4. Create a request to get a fresh `request_id`, then send to wallet.

Notes:
- Only `mso_mdoc` credential configurations are imported.
- Non‑PID/AV doctypes are applied directly to the request JSON.

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

The UI console mirrors backend logs. For ISO 18013-7 (DC API / `org-iso-mdoc`), the server emits detailed Annex C debugging output, including:

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
