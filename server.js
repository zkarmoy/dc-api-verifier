// server.js (CommonJS) — Local DC API + OpenID4VP (unsigned) + DCQL (PID/AV mdoc) + extraction + verification (partial)
// NOTE: This performs parsing/extraction ONLY. It does NOT fully verify mdoc; deviceAuth needs SessionTranscript bytes.

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const cbor = require("cbor");

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static("public"));

const DEBUG = String(process.env.DEBUG || "").toLowerCase() === "true" || process.env.DEBUG === "1";
const log = (...args) => {
  if (DEBUG) console.log(...args);
};

/**
 * In-memory state store (dev only).
 * Map<request_id, { createdAt, request_id, nonce, state, credential_type, private_key_jwk, public_key_jwk, doctype, pidNamespace, credential_id, credType, credId, requestedAttrs }>
 */
const stateStore = new Map();
const portraitStore = new Map(); // request_id -> { bytes, mime }

// -------------------- helpers --------------------
function b64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function randomB64url(bytes = 32) {
  return b64url(crypto.randomBytes(bytes));
}

function normalizeB64Url(s) {
  if (typeof s !== "string") return s;
  let out = s.trim();
  out = out.replace(/\s+/g, "");
  if (
    (out.startsWith('"') && out.endsWith('"')) ||
    (out.startsWith("'") && out.endsWith("'"))
  ) {
    out = out.slice(1, -1);
  }
  if (out.startsWith("mdoc:")) out = out.slice(5);
  return out;
}

function b64urlToBuf(s) {
  const clean = normalizeB64Url(s);
  const pad = "=".repeat((4 - (clean.length % 4)) % 4);
  const b64 = (clean + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(b64, "base64");
}

function isBstr(v) {
  return Buffer.isBuffer(v) || v instanceof Uint8Array;
}

function toBuf(v) {
  return Buffer.isBuffer(v) ? v : Buffer.from(v);
}

function isTagged(v, tag) {
  return v instanceof cbor.Tagged && v.tag === tag;
}

function cborDecode(bytes) {
  return cbor.decodeFirstSync(bytes, {
    tags: {
      0: (v) => new cbor.Tagged(0, v),
      24: (v) => new cbor.Tagged(24, v)
    }
  });
}

function decodeMaybeEmbedded(bytes) {
  let v = cborDecode(bytes);
  if (isTagged(v, 24) && isBstr(v.value)) {
    v = cborDecode(toBuf(v.value));
  }
  return v;
}

function mapGet(m, k) {
  if (!m) return undefined;
  if (m instanceof Map) {
    if (m.has(k)) return m.get(k);
    if (typeof k === "string" && m.has(Number(k))) return m.get(Number(k));
    if (typeof k === "number" && m.has(String(k))) return m.get(String(k));
    return undefined;
  }
  if (Object.prototype.hasOwnProperty.call(m, k)) return m[k];
  if (Object.prototype.hasOwnProperty.call(m, String(k))) return m[String(k)];
  if (Object.prototype.hasOwnProperty.call(m, Number(k))) return m[Number(k)];
  return undefined;
}

function mapKeys(m) {
  if (!m) return [];
  if (m instanceof Map) return Array.from(m.keys());
  return Object.keys(m);
}

function tag0ToISOString(v) {
  if (v instanceof Date) return v.toISOString();
  if (typeof v === "string") return v;
  return v ? String(v) : undefined;
}

function sha256Hex(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/**
 * Generate an ephemeral P-256 keypair (JWK).
 */
function generateEphemeralP256Jwk() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });

  const pubJwk = publicKey.export({ format: "jwk" });
  const privJwk = privateKey.export({ format: "jwk" });

  return {
    publicJwk: {
      kty: pubJwk.kty,
      crv: pubJwk.crv,
      x: pubJwk.x,
      y: pubJwk.y
    },
    privateJwk: {
      kty: privJwk.kty,
      crv: privJwk.crv,
      x: privJwk.x,
      y: privJwk.y,
      d: privJwk.d
    }
  };
}

function cleanupOld(ttlMs) {
  const now = Date.now();
  for (const [id, st] of stateStore.entries()) {
    if (now - st.createdAt > ttlMs) {
      stateStore.delete(id);
      portraitStore.delete(id);
    }
  }
}
setInterval(() => cleanupOld(5 * 60 * 1000), 60_000);

// -------------------- mdoc parsing --------------------
function classifyTopLevel(top) {
  if (top && typeof top === "object") {
    const keys = mapKeys(top);
    if (keys.includes("version") && keys.includes("documents")) return "DeviceResponse";
    if (keys.includes("docType") && keys.includes("issuerSigned")) return "Document";
  }
  if (Array.isArray(top) && top.length === 4) return "COSE_Sign1";
  if (isTagged(top, 24)) return "TaggedEmbeddedCBOR";
  return "Unknown";
}

function getFirstDocumentFromAnyTop(top) {
  const kind = classifyTopLevel(top);
  if (kind === "DeviceResponse") {
    const docs = mapGet(top, "documents") || [];
    return docs[0];
  }
  if (kind === "Document") return top;
  throw new Error(`Unsupported top-level structure: ${kind}`);
}

function parseIssuerSignedItems(nameSpaces) {
  const disclosed = [];
  const nsEntries = nameSpaces instanceof Map ? Array.from(nameSpaces.entries()) : Object.entries(nameSpaces || {});

  for (const [ns, items] of nsEntries) {
    const arr = Array.isArray(items) ? items : [];
    for (const raw of arr) {
      let itemBytes = null;
      let decoded = raw;

      if (isTagged(raw, 24) && isBstr(raw.value)) {
        itemBytes = toBuf(raw.value);
        decoded = cborDecode(itemBytes);
      } else if (isBstr(raw)) {
        itemBytes = toBuf(raw);
        decoded = cborDecode(itemBytes);
      }

      if (decoded && decoded.elementIdentifier !== undefined) {
        disclosed.push({
          namespace: ns,
          digestID: decoded.digestID,
          elementIdentifier: decoded.elementIdentifier,
          elementValue: decoded.elementValue,
          issuerSignedItemBytes: itemBytes
        });
      }
    }
  }

  return disclosed;
}

function parseIssuerAuth(issuerAuthCoseSign1) {
  if (!Array.isArray(issuerAuthCoseSign1) || issuerAuthCoseSign1.length !== 4) {
    throw new Error("issuerAuth is not a COSE_Sign1 array");
  }
  const [protectedBstr, unprotected, payload] = issuerAuthCoseSign1;
  const x5chain = mapGet(unprotected, 33);

  let msoBytes = payload;
  if (isTagged(payload, 24) && isBstr(payload.value)) {
    msoBytes = toBuf(payload.value);
  } else if (isBstr(payload)) {
    msoBytes = toBuf(payload);
  } else {
    throw new Error("issuerAuth payload is not bytes / Tag(24)");
  }

  const mso = cborDecode(msoBytes);
  return { protectedBstr, unprotected, x5chain, mso, msoBytes };
}

function parseDeviceKey(coseKey) {
  const kty = mapGet(coseKey, 1);
  const crv = mapGet(coseKey, -1);
  const x = mapGet(coseKey, -2);
  const y = mapGet(coseKey, -3);
  return { kty, crv, x: x ? toBuf(x) : null, y: y ? toBuf(y) : null };
}

function coseSigToDer(sig) {
  if (!Buffer.isBuffer(sig)) sig = Buffer.from(sig);
  if (sig.length !== 64) throw new Error("COSE signature must be 64 bytes (r||s)");
  let r = sig.slice(0, 32);
  let s = sig.slice(32);
  if (r[0] & 0x80) r = Buffer.concat([Buffer.from([0x00]), r]);
  if (s[0] & 0x80) s = Buffer.concat([Buffer.from([0x00]), s]);
  const totalLen = 2 + r.length + 2 + s.length;
  return Buffer.concat([
    Buffer.from([0x30, totalLen, 0x02, r.length]),
    r,
    Buffer.from([0x02, s.length]),
    s
  ]);
}

function verifyCoseSign1(cose, publicKey, externalAad = Buffer.alloc(0)) {
  const [protectedBstr, unprotected, payload, signature] = cose;
  const sigStructure = ["Signature1", protectedBstr, externalAad, payload];
  const toBeSigned = cbor.encode(sigStructure);
  const derSig = coseSigToDer(signature);
  const ok = crypto.verify("sha256", toBeSigned, publicKey, derSig);
  return { ok, unprotected };
}

function verifyIssuerAuthSignature(issuerAuthCoseSign1, x5chain) {
  if (!x5chain) return { ok: false, reason: "x5chain missing" };
  const certDer = Array.isArray(x5chain) ? toBuf(x5chain[0]) : toBuf(x5chain);
  const cert = new crypto.X509Certificate(certDer);
  const pubKey = cert.publicKey;
  const res = verifyCoseSign1(issuerAuthCoseSign1, pubKey);
  return { ok: res.ok, cert };
}

function verifyValueDigests(disclosed, valueDigests) {
  let allOk = true;
  const perItem = [];
  let debugPrinted = false;

  for (const item of disclosed) {
    const nsMap = mapGet(valueDigests, item.namespace);
    const expected = nsMap ? mapGet(nsMap, item.digestID) : null;

    let ok = false;
    let computedHex;
    let expectedHex;
    if (item.issuerSignedItemBytes) {
      // IMPORTANT: hash exact embedded CBOR bytes from Tag(24)
      const computed = crypto.createHash("sha256").update(item.issuerSignedItemBytes).digest();
      computedHex = computed.toString("hex");
      if (expected) {
        expectedHex = toBuf(expected).toString("hex");
        ok = Buffer.compare(computed, toBuf(expected)) === 0;
      }
    }
    if (!ok) allOk = false;

    perItem.push({
      namespace: item.namespace,
      digestID: item.digestID,
      elementIdentifier: item.elementIdentifier,
      ok
    });

    if (!ok && !debugPrinted && DEBUG) {
      console.log("[valueDigest debug]");
      console.log("namespace:", item.namespace);
      console.log("digestID:", item.digestID);
      console.log("issuerSignedItemBytes.length:", item.issuerSignedItemBytes ? item.issuerSignedItemBytes.length : 0);
      console.log("computedDigestHex:", computedHex);
      console.log("expectedDigestHex:", expectedHex);
      console.log("match:", ok);
      debugPrinted = true;
    }
  }

  return { allOk, perItem };
}

function parseDn(dn) {
  const out = {};
  if (!dn) return out;
  const parts = dn.split(/[\n,]/).map((p) => p.trim()).filter(Boolean);
  for (const p of parts) {
    const [k, ...rest] = p.split("=");
    if (!k || rest.length === 0) continue;
    const key = k.trim();
    const val = rest.join("=").trim();
    if (out[key]) {
      if (Array.isArray(out[key])) out[key].push(val);
      else out[key] = [out[key], val];
    } else {
      out[key] = val;
    }
  }
  return out;
}

function certInfo(cert) {
  if (!cert) return undefined;
  const subject = cert.subject || "";
  const issuer = cert.issuer || "";
  const s = parseDn(subject);
  const i = parseDn(issuer);
  const pick = (o, key) => {
    const v = o[key] ?? o[key.toUpperCase()] ?? o[key.toLowerCase()];
    return Array.isArray(v) ? v.join("; ") : v;
  };
  const alg = cert.publicKey?.asymmetricKeyType || "unknown";
  const curve = cert.publicKey?.asymmetricKeyDetails?.namedCurve || undefined;
  return {
    subject,
    issuer,
    subjectCN: pick(s, "CN"),
    subjectO: pick(s, "O"),
    subjectOU: pick(s, "OU"),
    subjectC: pick(s, "C"),
    serialNumber: pick(s, "serialNumber") || cert.serialNumber,
    issuerCN: pick(i, "CN"),
    issuerO: pick(i, "O"),
    issuerOU: pick(i, "OU"),
    issuerC: pick(i, "C"),
    notBefore: cert.validFrom,
    notAfter: cert.validTo,
    publicKeyAlg: alg,
    publicKeyCurve: curve
  };
}

function guessPortraitMime(bytes) {
  if (!bytes || bytes.length < 3) return "application/octet-stream";
  const jp2Magic = Buffer.from([0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a]);
  const jpgMagic = Buffer.from([0xff, 0xd8, 0xff]);
  const pngMagic = Buffer.from([0x89, 0x50, 0x4e, 0x47]);
  const jp2Brand = Buffer.from("ftypjp2");

  const scanLen = Math.min(bytes.length, 64);
  const nearStart = bytes.slice(0, scanLen);

  if (bytes.slice(0, 12).equals(jp2Magic) || nearStart.indexOf(jp2Brand) !== -1) return "image/jp2";
  if (bytes.slice(0, 3).equals(jpgMagic)) return "image/jpeg";
  if (bytes.slice(0, 4).equals(pngMagic)) return "image/png";
  return "application/octet-stream";
}

function extractPortrait(disclosed) {
  const cand = disclosed.find((d) => d.elementIdentifier === "portrait");
  if (!cand) return { present: false, byteLength: 0, mimeGuess: "application/octet-stream" };

  let bytes = null;
  const v = cand.elementValue;
  if (isBstr(v)) bytes = toBuf(v);
  else if (isTagged(v, 24) && isBstr(v.value)) bytes = toBuf(v.value);
  else if (v && typeof v === "object") {
    if (isBstr(v.value)) bytes = toBuf(v.value);
    else if (Array.isArray(v.data)) bytes = Buffer.from(v.data);
  }

  const mimeGuess = bytes ? guessPortraitMime(bytes) : "application/octet-stream";
  return {
    present: true,
    byteLength: bytes ? bytes.length : 0,
    mimeGuess,
    bytes
  };
}

/**
 * Parse vp_token.<credId>[0] (base64url) into:
 * - summary (docType, validityInfo, disclosed attributes, device key)
 * - verification (issuerAuth sig + valueDigests)
 */
function parseMdocAndVerify(deviceResponseOrDocumentB64Url) {
  const bytes = b64urlToBuf(deviceResponseOrDocumentB64Url);
  const top = decodeMaybeEmbedded(bytes);

  const kind = classifyTopLevel(top);
  const document = getFirstDocumentFromAnyTop(top);

  const docType = mapGet(document, "docType");
  const issuerSigned = mapGet(document, "issuerSigned") || {};
  const issuerAuth = mapGet(issuerSigned, "issuerAuth");
  const nameSpaces = mapGet(issuerSigned, "nameSpaces") || new Map();

  const disclosed = parseIssuerSignedItems(nameSpaces);

  const issuerAuthParsed = issuerAuth ? parseIssuerAuth(issuerAuth) : null;
  const mso = issuerAuthParsed?.mso;

  const validityInfo = mso ? mapGet(mso, "validityInfo") : null;
  const deviceKeyInfo = mso ? mapGet(mso, "deviceKeyInfo") : null;
  const deviceKey = deviceKeyInfo ? parseDeviceKey(mapGet(deviceKeyInfo, "deviceKey")) : null;

  const issuerSig = issuerAuth
    ? verifyIssuerAuthSignature(issuerAuth, issuerAuthParsed?.x5chain)
    : { ok: false, reason: "issuerAuth missing" };

  const digests = mso
    ? verifyValueDigests(disclosed, mapGet(mso, "valueDigests"))
    : { allOk: false, perItem: [], reason: "MSO missing" };

  const cert = issuerSig.cert;
  const certDetails = certInfo(cert);

  const summary = {
    topLevelKind: kind,
    docType,
    validityInfo: validityInfo
      ? {
          signed: tag0ToISOString(mapGet(validityInfo, "signed")),
          validFrom: tag0ToISOString(mapGet(validityInfo, "validFrom")),
          validUntil: tag0ToISOString(mapGet(validityInfo, "validUntil")),
          expectedUpdate: tag0ToISOString(mapGet(validityInfo, "expectedUpdate"))
        }
      : undefined,
    disclosedAttributes: disclosed.map((d) => ({
      namespace: d.namespace,
      digestID: d.digestID,
      elementIdentifier: d.elementIdentifier,
      elementValue: d.elementValue
    })),
    devicePublicKey: deviceKey
      ? {
          kty: deviceKey.kty,
          crv: deviceKey.crv,
          x: deviceKey.x?.toString("hex"),
          y: deviceKey.y?.toString("hex")
        }
      : undefined,
    issuerCertificate: certDetails
  };

  const debug = {
    byteLength: bytes.length,
    sha256: sha256Hex(bytes),
    first16: bytes.slice(0, 16).toString("hex"),
    last16: bytes.slice(-16).toString("hex"),
    topLevelKind: kind
  };

  const results = {
    issuerAuthSignatureValid: issuerSig.ok,
    valueDigestsValid: digests,
    deviceSignatureValid: { ok: null, reason: "NOT VERIFIED (missing session transcript)" }
  };

  return { summary, debug, results, disclosed };
}

// -------------------- routes --------------------

/**
 * GET /verifier/oid4vp/request?cred=pid|av
 */
app.get("/verifier/oid4vp/request", (req, res) => {
  if (DEBUG) {
    console.log("[request] query:", req.query);
  }
  const request_id = randomB64url(16);
  const nonce = randomB64url(32);
  const state = randomB64url(16);

  const { publicJwk, privateJwk } = generateEphemeralP256Jwk();

  const cred = String(req.query.cred || "pid").toLowerCase();
  const isAv = cred === "av";
  if (DEBUG) {
    console.log("[request] cred selected:", cred);
  }

  const doctype = isAv ? "eu.europa.ec.av.1" : "eu.europa.ec.eudi.pid.1";
  const namespace = doctype;

  const credId = isAv ? "av1" : "pid1";
  const defaultPidAttrs = ["family_name", "given_name", "birth_date"];
  const attrsParam = String(req.query.attrs || "").trim();
  const requestedAttrs = !isAv
    ? (attrsParam ? attrsParam.split(",").map((s) => s.trim()).filter(Boolean) : defaultPidAttrs)
    : [];

  const claims = isAv
    ? [
        { path: [namespace, "age_over_18"] },
        { path: [namespace, "age_over_21"] },
        { path: [namespace, "issuing_country"] },
        { path: [namespace, "expiry_date"] }
      ]
    : requestedAttrs.map((a) => ({ path: [namespace, a] }));

  const request = {
    response_type: "vp_token",
    response_mode: "dc_api",
    nonce,
    state,
    client_metadata: {
      vp_formats_supported: {
        mso_mdoc: {
          deviceauth_alg_values: [-7],
          issuerauth_alg_values: [-7]
        }
      }
    },
    dcql_query: {
      credentials: [
        {
          id: credId,
          format: "mso_mdoc",
          meta: { doctype_value: doctype },
          claims
        }
      ]
    }
  };

  stateStore.set(request_id, {
    createdAt: Date.now(),
    request_id,
    credential_type: "mso_mdoc",
    doctype,
    pidNamespace: namespace,
    credential_id: credId,
    credType: isAv ? "av" : "pid",
    credId,
    requestedAttrs,
    nonce,
    state,
    private_key_jwk: privateJwk,
    public_key_jwk: publicJwk
  });

  res.json({
    protocol: "openid4vp-v1-unsigned",
    request_id,
    request,
    state_hint: { nonce, state, public_key_jwk: publicJwk }
  });
});

/**
 * GET /portrait/:request_id
 */
app.get("/portrait/:request_id", (req, res) => {
  const entry = portraitStore.get(req.params.request_id);
  if (!entry) return res.status(404).send("Not found");
  res.setHeader("Content-Type", entry.mime || "application/octet-stream");
  res.send(entry.bytes);
});

/**
 * POST /verifier/oid4vp/response
 */
app.post("/verifier/oid4vp/response", (req, res) => {
  const { request_id, dcResponse } = req.body || {};

  if (!request_id || !stateStore.has(request_id)) {
    return res.status(400).json({
      ok: false,
      error: "Unknown or missing request_id. Cannot match response to stored verifier state."
    });
  }

  if (!dcResponse || typeof dcResponse !== "object") {
    return res.status(400).json({ ok: false, error: "Missing dcResponse in POST body." });
  }

  const vpToken = dcResponse?.data?.vp_token;
  const stored = stateStore.get(request_id);
  const credId = stored?.credId || stored?.credential_id || "pid1";
  const pidArr = vpToken?.[credId];

  if (!Array.isArray(pidArr) || typeof pidArr[0] !== "string") {
    return res.status(400).json({
      ok: false,
      error: `vp_token.${credId} missing or not in expected format.`
    });
  }

  const payloadB64Url = pidArr[0];
  const normalized = normalizeB64Url(payloadB64Url);

  log("\n=== DC API response received ===");
  log("request_id:", request_id);
  log(`vp_token.${credId}[0] length:`, payloadB64Url.length);
  log("prefix:", payloadB64Url.slice(0, 48));
  log("suffix:", payloadB64Url.slice(-48));
  log("b64url regex ok:", /^[A-Za-z0-9_-]+$/.test(normalized));

  let parsed;
  try {
    parsed = parseMdocAndVerify(payloadB64Url);
  } catch (e) {
    console.error("Parsing failed:", e?.message);
    return res.status(400).json({
      ok: false,
      error: `Failed to decode CBOR mdoc payload from vp_token.${credId}[0].`,
      message: e?.message
    });
  }

  // portrait extraction (if any)
  const portrait = extractPortrait(parsed.disclosed);
  let portraitDataUrl = null;
  let portraitDownloadUrl = null;
  if (portrait.present && portrait.bytes) {
    const inlineable = portrait.mimeGuess === "image/jpeg" || portrait.mimeGuess === "image/png";
    if (inlineable && portrait.bytes.length <= 500 * 1024) {
      portraitDataUrl = `data:${portrait.mimeGuess};base64,${portrait.bytes.toString("base64")}`;
    } else {
      portraitDownloadUrl = `/portrait/${request_id}`;
    }
    portraitStore.set(request_id, { bytes: portrait.bytes, mime: portrait.mimeGuess });
  }

  return res.json({
    ok: true,
    matched_request_id: request_id,
    received: {
      protocol: dcResponse?.protocol,
      vp_token_keys: vpToken ? Object.keys(vpToken) : []
    },
    extracted: {
      ...parsed.summary,
      credType: stored?.credType,
      credId,
      requestedAttrs: stored?.requestedAttrs || [],
      portrait: {
        present: portrait.present,
        byteLength: portrait.byteLength,
        mimeGuess: portrait.mimeGuess,
        dataUrl: portraitDataUrl,
        downloadUrl: portraitDownloadUrl
      }
    },
    verification: parsed.results,
    cbor_debug: parsed.debug
  });
});

app.listen(3000, () => {
  console.log("Open http://localhost:3000");
});
