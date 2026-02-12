# 🪪 EUDI Wallet Playground – DC API Verifier Demo

A lightweight **Digital Credentials API (DC API)** + **OpenID4VP (unsigned)** verifier playground for testing **ISO/IEC 18013-5 mdoc credentials**, including:

- 🇪🇺 PID — `eu.europa.ec.eudi.pid.1`
- 🔞 Age Verification — `eu.europa.ec.av.1`

This project is designed for experimentation, interoperability testing, and understanding how mdoc-based credentials work in a web verifier context.

> ⚠️ This is a demo / playground. It is **not production-ready** and does not implement full security hardening.

---

## ✨ Features

### 🔐 OpenID4VP (Unsigned) via DC API
- Generates dynamic DCQL requests
- Supports live wallet interaction
- Editable request JSON before sending

### 🪪 PID Support (`eu.europa.ec.eudi.pid.1`)
- Attribute selector (checkboxes)
- Manual attribute addition via text input
- Displays:
  - Given name / family name
  - Birth date (ISO-safe formatting, no timezone shift)
  - Birth place
  - Issuing country / authority
  - Expiry date
- Strict filtering: only requested attributes are displayed

### 🔞 Age Verification Support (`eu.europa.ec.av.1`)
Displays:
- `age_over_18`
- `age_over_21`
- `issuing_country`
- `expiry_date`

### 🌐 ISO 18013-7 (DeviceRequest over DC API)
- Alternate presentation format selectable in the UI
- Generates an ISO 18013-5 DeviceRequest (CBOR, base64url)
- Invokes the wallet through DC API with `protocol: "org-iso-mdoc"`

### 🏛 Certificate Viewer
Displays issuer certificate details:
- Subject (CN, O, OU, C)
- Issuer
- Validity period
- Public key information
- Raw subject / issuer (collapsible)

### 🧪 Developer Tools
- Raw JSON viewer (sanitized to avoid large binary overflow)
- Scrollable debug area
- Editable request JSON
- Manual attribute injection
- Strict CBOR + valueDigest verification

---

## 🏗 Architecture

```
Browser (UI)
   ↓
Node.js Express Backend
   ↓
Wallet (DC API / OpenID4VP)
```

### Backend
- Express server
- CBOR parsing
- ISO 18013-5 mdoc parsing
- IssuerAuth verification
- valueDigest verification
- DeviceAuth parsing (verification requires transcript)

### Frontend
- Static HTML / CSS / JS
- No framework
- Clean identity-card rendering
- Dynamic DCQL builder

---

## 🚀 Getting Started

### 1️⃣ Install dependencies

```bash
npm install
```

### 2️⃣ Start the server

```bash
node server.js
```

Open:

```
http://localhost:3000
```

> Some Digital Credential APIs require a secure context (`https`).  
> If needed, run behind a local HTTPS proxy.

---

## 🧭 How It Works

### 1️⃣ Create Request
- Choose credential type (PID or AV)
- Select attributes (PID)
- Optionally edit JSON manually
- Click “Send to Wallet”

### ISO 18013-7 (DeviceRequest via DC API)
1. Switch to **Age Verification**
2. Select **Presentation format → ISO 18013-7**
3. Click **Create request**
4. Use **Send to Wallet**
5. Paste the response and submit

### 2️⃣ Wallet Interaction
- Wallet displays requested attributes
- User consents
- Credential is returned via DC API

### 3️⃣ Verification & Display
The backend:

- Parses DeviceResponse
- Extracts IssuerSigned items
- Verifies:
  - IssuerAuth signature
  - ValueDigests
- Displays structured credential view

---

## 🔍 ISO 18013-5 Notes

### Value Digests
Each disclosed attribute is verified against:

```
MSO.valueDigests[namespace][digestID]
```

Digest is computed over:

```
IssuerSignedItemBytes = Tag(24, embedded CBOR)
```

### DeviceAuth
Device signature verification requires the correct SessionTranscript.  
This demo parses DeviceAuth but does not fully verify it unless transcript bytes are provided.

---

## 📁 Project Structure

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

---

## ⚙️ Customization

### Add a New Attribute
In PID view:
- Type attribute name
- Click ➕
- It is automatically added to DCQL

### Edit Request JSON
- Modify request directly in the editor
- Click “Apply edits”
- Launch wallet with modified request

---

## 🧪 Known Limitations

- No production-grade security
- DeviceAuth full verification requires transcript
- No certificate trust chain validation
- No HTTPS enforcement built-in
- Designed for experimentation and interoperability

---

## ✅ Testing Notes

### OID4VP (DC API)
- Requires a browser with Digital Credentials API support
- Some setups need HTTPS (use a local HTTPS proxy if required)
- Chrome: enable `chrome://flags/#enable-digital-credentials` (if needed)

### ISO 18013-7
- Uses the same UI but different request/response endpoints
- Requires Digital Credentials API support
- Wallet support varies; expect differences across vendors

---

## 📚 References

- ISO/IEC 18013-5: Mobile Driving Licence (mdoc)
- OpenID4VP Draft
- EUDI Wallet Architecture & ARF
- Digital Credentials API (W3C)

---

## 🤝 Contributing

This project is a technical playground for experimentation.  
Pull requests and improvements are welcome.

---

## 📄 License

MIT License

Copyright 2026 - @me

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## 👤 Author

Built for experimentation with EUDI Wallet and DC API flows.
