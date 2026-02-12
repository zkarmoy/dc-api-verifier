// server.js (CommonJS) — Local DC API + OpenID4VP (unsigned) + DCQL (PID/AV mdoc) + extraction + verification (partial)
// NOTE: This performs parsing/extraction ONLY. It does NOT fully verify mdoc; deviceAuth needs SessionTranscript bytes.

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const cbor = require("cbor");
const cborx = require("cbor-x");
let jose = null;
try {
  jose = require("jose");
} catch {
  jose = null;
}
let hpkeCore = null;

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static("public"));

const DEBUG = String(process.env.DEBUG || "").toLowerCase() === "true" || process.env.DEBUG === "1";
const log = (...args) => {
  if (!DEBUG) return;
  const normalized = args.map((arg) => (arg && typeof arg === "object" ? normalizeForLog(arg) : arg));
  console.log(...normalized);
};

// -------------------- server log streaming (dev) --------------------
const logSubscribers = new Set();
const logBuffer = [];
const MAX_LOGS = 200;

function pushLog(level, args) {
  const msg = args
    .map((a) => {
      if (typeof a === "string") return a;
      try {
        return JSON.stringify(a);
      } catch {
        return String(a);
      }
    })
    .join(" ");
  const entry = { ts: Date.now(), level, msg };
  logBuffer.push(entry);
  if (logBuffer.length > MAX_LOGS) logBuffer.shift();
  const payload = `data: ${JSON.stringify(entry)}\n\n`;
  for (const res of logSubscribers) {
    try {
      res.write(payload);
    } catch {
      // ignore broken connections
    }
  }
}

const origLog = console.log.bind(console);
const origWarn = console.warn.bind(console);
const origError = console.error.bind(console);
console.log = (...args) => {
  origLog(...args);
  pushLog("info", args);
};
console.warn = (...args) => {
  origWarn(...args);
  pushLog("warn", args);
};
console.error = (...args) => {
  origError(...args);
  pushLog("error", args);
};

let hpkeCorePromise = null;

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
  return Buffer.from(clean, "base64url");
}

function bufToB64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function first16Hex(buf) {
  return Buffer.from(buf).slice(0, 16).toString("hex");
}

function decodeAndCompare(referenceB64Url, generatedB64Url, label) {
  if (!referenceB64Url) return;
  try {
    const refBytes = b64urlToBuf(referenceB64Url);
    const genBytes = b64urlToBuf(generatedB64Url);
    const refDecoded = cborx.decode(refBytes);
    const genDecoded = cborx.decode(genBytes);
    log(`[iso-mdoc] ${label} ref first16:`, first16Hex(refBytes));
    log(`[iso-mdoc] ${label} gen first16:`, first16Hex(genBytes));
    log(`[iso-mdoc] ${label} ref decoded:`, refDecoded);
    log(`[iso-mdoc] ${label} gen decoded:`, genDecoded);
  } catch (e) {
    log(`[iso-mdoc] ${label} decodeAndCompare failed:`, e?.message);
  }
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

function unwrapCborBstr(bytes) {
  try {
    const v = cborDecode(bytes);
    if (isTagged(v, 24) && isBstr(v.value)) return toBuf(v.value);
    if (isBstr(v)) return toBuf(v);
  } catch {
    return null;
  }
  return null;
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

function normalizeForLog(value, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return `0x${Buffer.from(value).toString("hex")}`;
  }
  if (value && typeof value === "object" && value.type === "Buffer" && Array.isArray(value.data)) {
    return `0x${Buffer.from(value.data).toString("hex")}`;
  }
  if (value instanceof Map) {
    const out = {};
    for (const [k, v] of value.entries()) {
      out[k] = normalizeForLog(v, seen);
    }
    return out;
  }
  if (Array.isArray(value)) {
    return value.map((v) => normalizeForLog(v, seen));
  }
  if (typeof value === "object") {
    if (seen.has(value)) return "[Circular]";
    seen.add(value);
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = normalizeForLog(v, seen);
    }
    return out;
  }
  return value;
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

function isJwtLike(s) {
  if (typeof s !== "string") return false;
  const parts = s.split(".");
  return parts.length === 3 || parts.length === 5;
}

async function decodeDcApiJwt(jwt, stored) {
  if (!jose) {
    throw new Error("JOSE library not installed (npm i jose) for dc_api.jwt handling");
  }
  const parts = jwt.split(".");
  if (parts.length === 5) {
    const privateKey = await jose.importJWK(stored?.enc_private_jwk, "ECDH-ES");
    const { plaintext, protectedHeader } = await jose.compactDecrypt(jwt, privateKey);
    return { plaintext, protectedHeader, type: "jwe" };
  }
  if (parts.length === 3) {
    const protectedHeader = jose.decodeProtectedHeader(jwt);
    const payload = jose.decodeJwt(jwt); // decode without verify (no sig key)
    return { payload, protectedHeader, type: "jws" };
  }
  throw new Error("Unsupported JWT format");
}

function encodeLenPrefixed(buf) {
  const b = buf ? Buffer.from(buf) : Buffer.alloc(0);
  const out = Buffer.concat([Buffer.alloc(4), b]);
  out.writeUInt32BE(b.length, 0);
  return out;
}

function concatKdf(z, alg, keyLenBytes, partyUInfo, partyVInfo, algIdOverride) {
  const algStr = algIdOverride || alg;
  const algBuf = Buffer.from(algStr, "utf8");
  const algId = encodeLenPrefixed(algBuf);
  const partyU = encodeLenPrefixed(partyUInfo);
  const partyV = encodeLenPrefixed(partyVInfo);
  const suppPubInfo = Buffer.alloc(4);
  suppPubInfo.writeUInt32BE(keyLenBytes * 8, 0);
  const suppPrivInfo = Buffer.alloc(0);

  const hashLen = 32; // SHA-256
  const reps = Math.ceil(keyLenBytes / hashLen);
  const buffers = [];
  for (let i = 1; i <= reps; i++) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(i, 0);
    const input = Buffer.concat([counter, z, algId, partyU, partyV, suppPubInfo, suppPrivInfo]);
    buffers.push(crypto.createHash("sha256").update(input).digest());
  }
  return Buffer.concat(buffers).slice(0, keyLenBytes);
}

function coseAlgToJose(alg) {
  if (alg === 1) return "A128GCM";
  if (alg === 2) return "A192GCM";
  if (alg === 3) return "A256GCM";
  return null;
}

async function getHpkeSuite() {
  if (!hpkeCorePromise) {
    hpkeCorePromise = import("@hpke/core");
  }
  const { CipherSuite, Aes128Gcm, DhkemP256HkdfSha256, HkdfSha256 } = await hpkeCorePromise;
  return new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm()
  });
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
    if (DEBUG) {
      const t = items instanceof Map ? "Map" : Array.isArray(items) ? "Array" : typeof items;
      const keys = items && typeof items === "object" ? mapKeys(items) : [];
      console.log("[iso-mdoc] ns", ns, "items type:", t, "keys:", keys.slice(0, 10));
      const first = Array.isArray(items) ? items[0] : (items instanceof Map ? items.values().next().value : Object.values(items || {})[0]);
      if (first !== undefined) {
        const firstType = isBstr(first) ? "bstr" : (first && typeof first === "object" ? first.constructor?.name || "object" : typeof first);
        console.log("[iso-mdoc] ns", ns, "first item type:", firstType, "len:", isBstr(first) ? toBuf(first).length : undefined);
        try {
          const decodedFirst = isBstr(first) ? cborDecode(toBuf(first)) : first;
          if (decodedFirst && typeof decodedFirst === "object") {
            console.log("[iso-mdoc] ns", ns, "first decoded keys:", mapKeys(decodedFirst));
          }
        } catch (e) {
          console.log("[iso-mdoc] ns", ns, "first decode failed:", e?.message);
        }
      }
    }
    const arr = Array.isArray(items)
      ? items
      : (items instanceof Map ? Array.from(items.values()) : (items && typeof items === "object" ? Object.values(items) : []));
    for (const raw of arr) {
      let itemBytes = null;
      let itemBytesTagged = null;
      let itemBytesInner = null;
      let decoded = raw;

      const isTaggedObj = raw && typeof raw === "object" && raw.tag === 24 && raw.value !== undefined;

      if ((isTagged(raw, 24) || isTaggedObj) && isBstr((raw || {}).value)) {
        itemBytesInner = toBuf(raw.value);
        itemBytesTagged = cbor.encodeCanonical(new cbor.Tagged(24, itemBytesInner));
        itemBytes = itemBytesTagged;
        decoded = cborDecode(itemBytesInner);
      } else if ((isTagged(raw, 24) || isTaggedObj) && raw.value && typeof raw.value === "object" && isBstr(raw.value.value)) {
        itemBytesInner = toBuf(raw.value.value);
        itemBytesTagged = cbor.encodeCanonical(new cbor.Tagged(24, itemBytesInner));
        itemBytes = itemBytesTagged;
        decoded = cborDecode(itemBytesInner);
      } else if (isBstr(raw)) {
        itemBytesInner = toBuf(raw);
        itemBytesTagged = cbor.encodeCanonical(new cbor.Tagged(24, itemBytesInner));
        itemBytes = itemBytesTagged;
        decoded = cborDecode(itemBytesInner);
      }

      if (decoded && decoded.elementIdentifier !== undefined) {
        disclosed.push({
          namespace: ns,
          digestID: decoded.digestID,
          elementIdentifier: decoded.elementIdentifier,
          elementValue: decoded.elementValue,
          issuerSignedItemBytes: itemBytes,
          issuerSignedItemBytesTagged: itemBytesTagged,
          issuerSignedItemBytesInner: itemBytesInner
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
  const hasValueDigests = valueDigests && mapKeys(valueDigests).length > 0;
  if (!hasValueDigests) {
    return {
      allOk: null,
      perItem: disclosed.map((d) => ({
        namespace: d.namespace,
        digestID: d.digestID,
        elementIdentifier: d.elementIdentifier,
        ok: null
      })),
      reason: "valueDigests missing or empty"
    };
  }

  let allOk = true;
  const perItem = [];
  const debugPerItem = [];
  let debugPrinted = false;

  const findNamespaceMap = (vd, ns) => {
    if (!vd) return null;
    const direct = mapGet(vd, ns);
    if (direct) return direct;
    if (vd instanceof Map) {
      const nsBuf = Buffer.from(ns, "utf8");
      for (const [k, v] of vd.entries()) {
        if (typeof k === "string" && k === ns) return v;
        if (isBstr(k) && Buffer.compare(toBuf(k), nsBuf) === 0) return v;
      }
    } else if (typeof vd === "object") {
      const keys = Object.keys(vd);
      for (const k of keys) {
        if (k === ns) return vd[k];
      }
    }
    return null;
  };

  for (const item of disclosed) {
    const nsMap = findNamespaceMap(valueDigests, item.namespace);
    const expected = nsMap ? mapGet(nsMap, item.digestID) : null;

    let ok = false;
    let computedHex;
    let expectedHex;
    const expectedBuf = expected ? toBuf(expected) : null;
    const tryBytes = (bytes) => {
      if (!bytes || !expectedBuf) return false;
      const computed = crypto.createHash("sha256").update(bytes).digest();
      computedHex = computed.toString("hex");
      expectedHex = expectedBuf.toString("hex");
      return Buffer.compare(computed, expectedBuf) === 0;
    };
    // Prefer tagged bytes (Tag 24 wrapper). Fallback to inner bytes if needed.
    const taggedBytes = item.issuerSignedItemBytesTagged || item.issuerSignedItemBytes;
    ok = tryBytes(taggedBytes);
    if (!ok) {
      ok = tryBytes(item.issuerSignedItemBytesInner);
    }
    if (!ok) allOk = false;

    perItem.push({
      namespace: item.namespace,
      digestID: item.digestID,
      elementIdentifier: item.elementIdentifier,
      ok
    });

    if (DEBUG) {
      const taggedHex = taggedBytes
        ? crypto.createHash("sha256").update(taggedBytes).digest("hex")
        : null;
      const innerHex = item.issuerSignedItemBytesInner
        ? crypto.createHash("sha256").update(item.issuerSignedItemBytesInner).digest("hex")
        : null;
      debugPerItem.push({
        namespace: item.namespace,
        digestID: item.digestID,
        elementIdentifier: item.elementIdentifier,
        expectedHex: expectedBuf ? expectedBuf.toString("hex") : null,
        taggedHex,
        innerHex,
        matched: ok ? (taggedHex === expectedHex ? "tagged" : innerHex === expectedHex ? "inner" : "unknown") : null
      });
    }

    if (!ok && !debugPrinted && DEBUG) {
      console.log("[valueDigest debug]");
      console.log("valueDigests keys:", mapKeys(valueDigests));
      if (nsMap) console.log("nsMap keys:", mapKeys(nsMap));
      console.log("namespace:", item.namespace);
      console.log("digestID:", item.digestID);
      console.log("issuerSignedItemBytes.length:", item.issuerSignedItemBytes ? item.issuerSignedItemBytes.length : 0);
      console.log("computedDigestHex:", computedHex);
      console.log("expectedDigestHex:", expectedHex);
      console.log("match:", ok);
      debugPrinted = true;
    }
  }

  return { allOk, perItem, debugPerItem };
}

// -------------------- HPKE (RFC 9180) Helpers --------------------
const HPKE_SUITE_ID = Buffer.from("HPKE\x00\x10\x00\x01\x00\x01", "binary"); // P-256, HKDF-SHA256, AES-128-GCM

function hkdfExtract(salt, ikm) {
  // RFC 5869: PRK = HMAC-Hash(salt, IKM)
  // If salt is not provided, it is set to a string of HashLen zeros.
  const saltBuf = (salt && salt.length > 0) ? salt : Buffer.alloc(32, 0);
  return crypto.createHmac("sha256", saltBuf).update(ikm).digest();
}

function hkdfExpand(prk, info, length) {
  // RFC 5869: OKM = HKDF-Expand(PRK, info, L)
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  const okmBuffers = [];
  let t = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const hmac = crypto.createHmac("sha256", prk);
    hmac.update(t);
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    t = hmac.digest();
    okmBuffers.push(t);
  }
  return Buffer.concat(okmBuffers).slice(0, length);
}

function labeledExtract(salt, label, ikm) {
  // RFC 9180: labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
  const protocolLabel = Buffer.from("HPKE-v1", "utf8");
  const labelBytes = Buffer.from(label, "utf8");
  const labeledIkm = Buffer.concat([protocolLabel, HPKE_SUITE_ID, labelBytes, ikm]);
  return hkdfExtract(salt, labeledIkm);
}

function labeledExpand(prk, label, info, length) {
  // RFC 9180: labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
  const protocolLabel = Buffer.from("HPKE-v1", "utf8");
  const labelBytes = Buffer.from(label, "utf8");
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(length);
  const labeledInfo = Buffer.concat([lenBuf, protocolLabel, HPKE_SUITE_ID, labelBytes, info]);
  return hkdfExpand(prk, labeledInfo, length);
}

function jwkToRawP256(jwk) {
  if (!jwk || !jwk.x || !jwk.y) throw new Error("Invalid JWK");
  const x = b64urlToBuf(jwk.x);
  const y = b64urlToBuf(jwk.y);
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

function coseKeyToRawP256(map) {
  const x = map.get(-2);
  const y = map.get(-3);
  if (!x || !y) throw new Error("Invalid COSE Key");
  return Buffer.concat([Buffer.from([0x04]), toBuf(x), toBuf(y)]);
}

/**
 * HELPER: Derive Session Key for ISO mDoc (DCAPI/Google Profile)
 * Uses HKDF to derive 44 bytes (32 for AES Key, 12 for IV).
 */
function deriveSessionKey(verifierPrivJwk, walletPub, nonceBuffer) {
  // 1. Reconstruct Wallet Public Key from raw bytes or Map
  let xBuf, yBuf;

  if (isTagged(walletPub, 24)) walletPub = walletPub.value;

  if (walletPub instanceof Map) {
    xBuf = walletPub.get(-2) ? toBuf(walletPub.get(-2)) : null;
    yBuf = walletPub.get(-3) ? toBuf(walletPub.get(-3)) : null;
  } else if (Buffer.isBuffer(walletPub)) {
    if (walletPub.length === 65 && walletPub[0] === 0x04) {
      xBuf = walletPub.slice(1, 33);
      yBuf = walletPub.slice(33, 65);
    } else {
      try {
        const decoded = cbor.decodeFirstSync(walletPub);
        if (decoded instanceof Map) {
          xBuf = toBuf(decoded.get(-2));
          yBuf = toBuf(decoded.get(-3));
        }
      } catch (e) {
        if (walletPub.length === 64) {
          xBuf = walletPub.slice(0, 32);
          yBuf = walletPub.slice(32, 64);
        }
      }
    }
  }

  if (!xBuf || !yBuf) throw new Error("Could not extract Wallet Public Key from 'cenc'");

  const walletPubJwk = {
    kty: "EC", crv: "P-256",
    x: bufToB64url(xBuf),
    y: bufToB64url(yBuf)
  };

  // 2. Compute Shared Secret (ECDH)
  const verifierKey = crypto.createPrivateKey({ key: verifierPrivJwk, format: "jwk" });
  const walletKeyObj = crypto.createPublicKey({ key: walletPubJwk, format: "jwk" });
  const sharedSecret = crypto.diffieHellman({ privateKey: verifierKey, publicKey: walletKeyObj });

  // 3. HKDF-SHA256
  // Info="SKDevice", Salt=nonce. Output 44 bytes (32 Key + 12 IV)
  const info = Buffer.from("SKDevice", "utf8");
  const keyMaterial = crypto.hkdfSync("sha256", sharedSecret, nonceBuffer, info, 44);

  return {
    aesKey: keyMaterial.slice(0, 32),
    iv: keyMaterial.slice(32, 44)
  };
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

  if (DEBUG) {
    const nsType = nameSpaces instanceof Map ? "Map" : Array.isArray(nameSpaces) ? "Array" : typeof nameSpaces;
    console.log("[iso-mdoc] issuerSigned keys:", mapKeys(issuerSigned));
    console.log("[iso-mdoc] nameSpaces type:", nsType);
    if (nameSpaces && typeof nameSpaces === "object") {
      console.log("[iso-mdoc] nameSpaces keys:", mapKeys(nameSpaces));
    }
  }

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
    console.log("[oid4vp] request query:", req.query);
  }
  const request_id = randomB64url(16);
  const sessionId = crypto.randomUUID();
  const nonce = sessionId;
  const state = randomB64url(16);

  const { publicJwk, privateJwk } = generateEphemeralP256Jwk();
  const { publicJwk: encPublicJwk, privateJwk: encPrivateJwk } = generateEphemeralP256Jwk();

  const cred = String(req.query.cred || "pid").toLowerCase();
  const isAv = cred === "av";
  if (DEBUG) {
    console.log("[oid4vp] cred selected:", cred);
  }

  const doctype = isAv ? "eu.europa.ec.av.1" : "eu.europa.ec.eudi.pid.1";
  const namespace = doctype;

  const credId = isAv ? "av1" : "pid1";
  const defaultPidAttrs = ["family_name", "given_name", "birth_date"];
  const defaultAvAttrs = ["age_over_18", "age_over_21", "issuing_country", "expiry_date"];
  const attrsParam = String(req.query.attrs || "").trim();
  const requestedAttrs = isAv
    ? (attrsParam ? attrsParam.split(",").map((s) => s.trim()).filter(Boolean) : defaultAvAttrs)
    : (attrsParam ? attrsParam.split(",").map((s) => s.trim()).filter(Boolean) : defaultPidAttrs);

  const claims = requestedAttrs.map((a) => ({ path: [namespace, a] }));

  const originHeader = req.headers["origin"];
  const forwardedProto = (req.headers["x-forwarded-proto"] || "").toString();
  const forwardedHost = (req.headers["x-forwarded-host"] || "").toString();
  const host = forwardedHost || req.headers.host || "localhost:3000";
  const scheme = forwardedProto || (originHeader ? originHeader.split("://")[0] : "http");
  const origin = originHeader || `${scheme}://${host}`;
  const clientId = `web-origin:${origin}`;
  if (DEBUG) {
    console.log("[oid4vp] origin:", origin);
    console.log("[oid4vp] client_id:", clientId);
    console.log("[oid4vp] doctype:", doctype);
    console.log("[oid4vp] credId:", credId);
    console.log("[oid4vp] requestedAttrs:", requestedAttrs);
    console.log("[oid4vp] claims count:", claims.length);
  }
  const requestData = {
    response_type: "vp_token",
    response_mode: "dc_api.jwt",
    nonce,
    client_id: clientId,
    expected_origins: [origin],
    client_metadata: {
      jwks: {
        keys: [
          {
            kty: encPublicJwk.kty,
            use: "enc",
            crv: encPublicJwk.crv,
            kid: "key-1",
            x: encPublicJwk.x,
            y: encPublicJwk.y,
            alg: "ECDH-ES"
          }
        ]
      },
      encrypted_response_enc_values_supported: ["A256GCM", "A128GCM"],
      vp_formats_supported: {
        mso_mdoc: {
          deviceauth_alg_values: [-7, -9],
          issuerauth_alg_values: [-7, -9]
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
      ],
      credential_sets: [
        {
          options: [[credId]],
          purpose: isAv ? "Verify age" : "Verify user identity"
        }
      ]
    }
  };

  const request = {
    protocol: "openid4vp-v1-unsigned",
    data: requestData
  };
  if (DEBUG) {
    console.log("[oid4vp] request_id:", request_id);
    console.log("[oid4vp] request payload:", request);
  }

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
    origin,
    private_key_jwk: privateJwk,
    public_key_jwk: publicJwk,
    sessionId,
    enc_private_jwk: encPrivateJwk,
    enc_public_jwk: encPublicJwk
  });

  res.json({
    sessionId,
    request,
    request_id,
    state_hint: { nonce, state, public_key_jwk: publicJwk }
  });
});

/**
 * GET /verifier/iso-mdoc/request?cred=pid|av
 */
app.get("/verifier/iso-mdoc/request", (req, res) => {
  if (DEBUG) {
    console.log("[iso-mdoc request] query:", req.query);
  }
  const request_id = randomB64url(16);
  const sessionId = crypto.randomUUID();

  const cred = String(req.query.cred || "av").toLowerCase();
  const isAv = cred === "av";
  if (DEBUG) {
    console.log("[iso-mdoc request] cred selected:", cred);
  }
  const doctype = isAv ? "eu.europa.ec.av.1" : "eu.europa.ec.eudi.pid.1";
  const originHeader = req.headers["origin"];
  const forwardedProto = (req.headers["x-forwarded-proto"] || "").toString();
  const forwardedHost = (req.headers["x-forwarded-host"] || "").toString();
  const host = forwardedHost || req.headers.host || "localhost:3000";
  const scheme = forwardedProto || (originHeader ? originHeader.split("://")[0] : "http");
  const origin = originHeader || `${scheme}://${host}`;
  const attrsParam = String(req.query.attrs || "").trim();
  const defaultPidAttrs = ["family_name", "given_name", "birth_date"];
  const defaultAvAttrs = ["age_over_18", "age_over_21", "issuing_country", "expiry_date"];
  const requestedAttrs = isAv
    ? (attrsParam ? attrsParam.split(",").map((s) => s.trim()).filter(Boolean) : defaultAvAttrs)
    : (attrsParam ? attrsParam.split(",").map((s) => s.trim()).filter(Boolean) : defaultPidAttrs);

  const embeddedItems = {
    docType: doctype,
    nameSpaces: {
      [doctype]: {}
    }
  };
  requestedAttrs.forEach((a) => { embeddedItems.nameSpaces[doctype][a] = false; });
  const embeddedBytes = cbor.encodeCanonical(embeddedItems);
  const taggedItemsRequest = new cbor.Tagged(24, embeddedBytes);

  const deviceRequest = {
    version: "1.0",
    docRequests: [
      {
        itemsRequest: taggedItemsRequest
      }
    ]
  };

  const deviceRequestBytes = cbor.encodeCanonical(deviceRequest);
  const deviceRequestB64Url = bufToB64url(deviceRequestBytes);

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pubJwk = publicKey.export({ format: "jwk" });
  const privJwk = privateKey.export({ format: "jwk" });
  const coseKey = new Map([
    [1, 2],
    [-1, 1],
    [-2, Buffer.from(pubJwk.x, "base64url")],
    [-3, Buffer.from(pubJwk.y, "base64url")]
  ]);
  const encryptionInfoNonce = crypto.randomBytes(16);
  const encryptionInfo = [
    "dcapi",
    {
      nonce: encryptionInfoNonce,
      recipientPublicKey: coseKey
    }
  ];
  const encryptionInfoBytes = cbor.encodeCanonical(encryptionInfo);
  const encryptionInfoB64Url = bufToB64url(encryptionInfoBytes);

  const decodedDeviceRequest = cborDecode(deviceRequestBytes);
  const docReq = decodedDeviceRequest?.docRequests?.[0];
  const itemsIsTagged = docReq?.itemsRequest instanceof cbor.Tagged && docReq.itemsRequest.tag === 24;
  const taggedValue = itemsIsTagged ? docReq.itemsRequest.value : null;
  const decodedItemsRequest = taggedValue && isBstr(taggedValue) ? cborDecode(toBuf(taggedValue)) : null;
  const decodedEncryptionInfo = cborDecode(encryptionInfoBytes);
  const topKeys = decodedDeviceRequest && typeof decodedDeviceRequest === "object" ? Object.keys(decodedDeviceRequest) : [];
  const docReqKeys = docReq && typeof docReq === "object" ? Object.keys(docReq) : [];
  const itemsKeys = decodedItemsRequest && typeof decodedItemsRequest === "object" ? Object.keys(decodedItemsRequest) : [];
  const encIsArray = Array.isArray(decodedEncryptionInfo);
  const encOk = encIsArray && decodedEncryptionInfo.length === 2 && decodedEncryptionInfo[0] === "dcapi";
  log("[iso-mdoc] DeviceRequest top-level keys:", topKeys);
  log("[iso-mdoc] docRequest keys:", docReqKeys);
  log("[iso-mdoc] itemsRequest is Tag(24):", itemsIsTagged);
  log("[iso-mdoc] itemsRequest keys:", itemsKeys);
  log("[iso-mdoc] encryptionInfo array ok:", encOk);
  log("[iso-mdoc] deviceRequest first16:", first16Hex(deviceRequestBytes));
  log("[iso-mdoc] encryptionInfo first16:", first16Hex(encryptionInfoBytes));
  log("[iso-mdoc] DeviceRequest decoded:", normalizeForLog(decodedDeviceRequest));
  log("[iso-mdoc] ItemsRequest decoded:", normalizeForLog(decodedItemsRequest));
  log("[iso-mdoc] encryptionInfo decoded:", normalizeForLog(decodedEncryptionInfo));
  decodeAndCompare(process.env.REF_DEVICE_REQUEST_B64URL, deviceRequestB64Url, "deviceRequest");
  decodeAndCompare(process.env.REF_ENCRYPTION_INFO_B64URL, encryptionInfoB64Url, "encryptionInfo");

  stateStore.set(request_id, {
    createdAt: Date.now(),
    request_id,
    credential_type: "mso_mdoc",
    doctype,
    pidNamespace: doctype,
    credential_id: isAv ? "av1" : "pid1",
    credType: isAv ? "av" : "pid",
    credId: isAv ? "av1" : "pid1",
    requestedAttrs,
    origin,
    protocol: "org-iso-mdoc",
    encryption_nonce: encryptionInfoNonce,
    encryption_info_bytes: encryptionInfoBytes,
    device_request_bytes: deviceRequestBytes,
    private_key_jwk: privJwk,
    public_key_jwk: pubJwk
  });

  console.log("DEV private_key_jwk", request_id, privJwk);
  console.log("DEV encryption_nonce", request_id, encryptionInfoNonce.toString("hex"));

  res.json({
    sessionId,
    request: {
      protocol: "org-iso-mdoc",
      data: {
        deviceRequest: deviceRequestB64Url,
        encryptionInfo: encryptionInfoB64Url
      }
    },
    request_id
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
 * GET /logs/stream (Server-sent events)
 */
app.get("/logs/stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const recent = logBuffer.slice(-50);
  recent.forEach((entry) => {
    res.write(`data: ${JSON.stringify(entry)}\n\n`);
  });

  logSubscribers.add(res);
  req.on("close", () => {
    logSubscribers.delete(res);
  });
});

/**
 * POST /verifier/oid4vp/response
 */
app.post("/verifier/oid4vp/response", async (req, res) => {
  const { request_id, dcResponse } = req.body || {};

  if (DEBUG) {
    console.log("[oid4vp] response request_id:", request_id);
    console.log("[oid4vp] response keys:", dcResponse && typeof dcResponse === "object" ? Object.keys(dcResponse) : []);
    if (dcResponse?.protocol) console.log("[oid4vp] response protocol:", dcResponse.protocol);
    if (dcResponse?.data && typeof dcResponse.data === "object") {
      console.log("[oid4vp] response data keys:", Object.keys(dcResponse.data));
    }
  }

  if (!request_id || !stateStore.has(request_id)) {
    return res.status(400).json({
      ok: false,
      error: "Unknown or missing request_id. Cannot match response to stored verifier state."
    });
  }

  if (!dcResponse || typeof dcResponse !== "object") {
    return res.status(400).json({ ok: false, error: "Missing dcResponse in POST body." });
  }

  const stored = stateStore.get(request_id);
  const credId = stored?.credId || stored?.credential_id || "pid1";
  let vpToken = dcResponse?.data?.vp_token;
  let pidArr = vpToken?.[credId];

  // dc_api.jwt handling (JWE/JWS)
  const jwtCandidate = typeof dcResponse?.data === "string"
    ? dcResponse.data
    : (typeof dcResponse?.data?.response === "string" ? dcResponse.data.response : null);
  if (DEBUG) {
    console.log("[oid4vp] jwtCandidate present:", !!jwtCandidate);
    if (jwtCandidate) {
      console.log("[oid4vp] jwtCandidate length:", jwtCandidate.length);
      console.log("[oid4vp] jwtCandidate prefix:", jwtCandidate.slice(0, 48));
      console.log("[oid4vp] jwtCandidate suffix:", jwtCandidate.slice(-48));
      console.log("[oid4vp] jwtCandidate isJwtLike:", isJwtLike(jwtCandidate));
    }
  }
  if ((!pidArr || !Array.isArray(pidArr)) && jwtCandidate && isJwtLike(jwtCandidate)) {
    try {
      const decoded = await decodeDcApiJwt(jwtCandidate, stored);
      let payloadObj = null;
      if (decoded.type === "jwe") {
        if (DEBUG) {
          console.log("[oid4vp] jwe header:", decoded.protectedHeader);
        }
        const text = Buffer.from(decoded.plaintext).toString("utf8");
        if (DEBUG) {
          console.log("[oid4vp] jwe plaintext length:", text.length);
          console.log("[oid4vp] jwe plaintext prefix:", text.slice(0, 120));
        }
        try {
          payloadObj = JSON.parse(text);
        } catch {
          if (isJwtLike(text) && jose?.decodeJwt) {
            if (DEBUG) console.log("[oid4vp] JWE plaintext is JWT; decoding without verify");
            payloadObj = jose.decodeJwt(text);
          } else {
            throw new Error("JWE plaintext is not valid JSON or JWT");
          }
        }
      } else if (decoded.type === "jws") {
        if (DEBUG) {
          console.log("[oid4vp] jws header:", decoded.protectedHeader);
        }
        payloadObj = decoded.payload;
      }
      if (DEBUG) {
        console.log("[oid4vp] decoded jwt type:", decoded.type);
        console.log("[oid4vp] payload keys:", payloadObj && typeof payloadObj === "object" ? Object.keys(payloadObj) : []);
      }
      vpToken = payloadObj?.vp_token || payloadObj?.data?.vp_token || payloadObj?.response?.vp_token;
      if (!vpToken && payloadObj?.response && isJwtLike(payloadObj.response) && jose?.decodeJwt) {
        if (DEBUG) console.log("[oid4vp] nested response JWT; decoding without verify");
        const nested = jose.decodeJwt(payloadObj.response);
        vpToken = nested?.vp_token || nested?.data?.vp_token;
      }
      if (DEBUG && vpToken && typeof vpToken === "object") {
        console.log("[oid4vp] vp_token keys:", Object.keys(vpToken));
      }
      pidArr = vpToken?.[credId];
      if (typeof pidArr === "string") pidArr = [pidArr];
      if (DEBUG) {
        console.log("[oid4vp] credId:", credId);
        console.log("[oid4vp] vp_token[credId] type:", Array.isArray(pidArr) ? "array" : typeof pidArr);
        console.log("[oid4vp] vp_token[credId] length:", Array.isArray(pidArr) ? pidArr.length : 0);
      }
    } catch (e) {
      let jweHeader = null;
      try {
        jweHeader = jose?.decodeProtectedHeader ? jose.decodeProtectedHeader(jwtCandidate) : null;
      } catch {
        jweHeader = null;
      }
      return res.status(400).json({
        ok: false,
        error: "Failed to decode dc_api.jwt response",
        message: e?.message,
        jweHeader,
        hasEncPrivateKey: !!stored?.enc_private_jwk
      });
    }
  }

  if (!Array.isArray(pidArr) || typeof pidArr[0] !== "string") {
    return res.status(400).json({
      ok: false,
      error: `vp_token.${credId} missing or not in expected format.`
    });
  }

  const payloadB64Url = pidArr[0];
  const normalized = normalizeB64Url(payloadB64Url);

  log("\n=== OID4VP response received ===");
  log("request_id:", request_id);
  log("credId:", credId);
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

/**
 * POST /verifier/iso-mdoc/response
 */
app.post("/verifier/iso-mdoc/response", async (req, res) => {
  const { request_id, dcResponse } = req.body || {};

  if (!request_id || !stateStore.has(request_id)) {
    return res.status(400).json({ ok: false, error: "Unknown request_id" });
  }

  const stored = stateStore.get(request_id);

  // 1. Get raw payload
  const payloadB64Url = typeof dcResponse === "string" ? dcResponse :
    (dcResponse?.data?.response || dcResponse?.response);

  if (!payloadB64Url) return res.status(400).json({ ok: false, error: "Missing response payload" });

  try {
    const responseBytes = b64urlToBuf(payloadB64Url);
    const decodedTop = cborx.decode(responseBytes);

    // 2. Parse 'dcapi' / 'edcapi' envelope
    if (!Array.isArray(decodedTop) || decodedTop.length < 2) {
      throw new Error("Invalid response structure");
    }
    const proto = decodedTop[0];
    if (proto !== "dcapi" && proto !== "edcapi") {
      throw new Error(`Unsupported envelope: ${proto}`);
    }

    const envelopeMap = decodedTop[1];
    const getBytes = (v) => {
      if (!v) return null;
      if (v instanceof Map) return coseKeyToRawP256(v);
      if (isBstr(v)) return toBuf(v);
      if (v && typeof v === "object" && v.tag !== undefined && isBstr(v.value)) return toBuf(v.value);
      return null;
    };
    const enc = getBytes(mapGet(envelopeMap, "enc") || mapGet(envelopeMap, "cenc"));
    const ct = getBytes(mapGet(envelopeMap, "cipherText") || mapGet(envelopeMap, "ciphertext"));

    if (!enc || !ct) throw new Error("Missing enc/cipherText");

    // 3. Build HPKE info = CBOR(SessionTranscript)
    const origin = stored?.origin || "http://localhost:3000";
    const encInfoB64Url = stored?.encryption_info_bytes
      ? bufToB64url(toBuf(stored.encryption_info_bytes))
      : null;
    if (!encInfoB64Url) throw new Error("Missing encryption_info_bytes");
    const dcapiInfo = [encInfoB64Url, origin];
    const dcapiInfoHash = crypto.createHash("sha256").update(cbor.encodeCanonical(dcapiInfo)).digest();
    const sessionTranscript = [null, null, ["dcapi", dcapiInfoHash]];
    const info = cbor.encodeCanonical(sessionTranscript);

    // 4. HPKE open (DHKEM_P256 + HKDF_SHA256 + AES_128_GCM), aad = empty
    const suite = await getHpkeSuite();
    const recipientKey = await suite.kem.importKey("jwk", stored.private_key_jwk, false);
    const encBuf = toBuf(enc);
    const ctBuf = toBuf(ct);
    const infoBuf = toBuf(info);
    const encArray = encBuf.buffer.slice(encBuf.byteOffset, encBuf.byteOffset + encBuf.byteLength);
    const ctArray = ctBuf.buffer.slice(ctBuf.byteOffset, ctBuf.byteOffset + ctBuf.byteLength);
    const infoArray = infoBuf.buffer.slice(infoBuf.byteOffset, infoBuf.byteOffset + infoBuf.byteLength);
    const aad = new Uint8Array();

    const annexCEnabled = true;
    const annexCSecrets = true;
    const toHex = (v) => (v ? Buffer.from(v).toString("hex") : "");
    const toU8 = (v) => {
      if (!v) return null;
      if (v instanceof Uint8Array) return v;
      if (Buffer.isBuffer(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
      if (v instanceof ArrayBuffer) return new Uint8Array(v);
      if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
      return null;
    };

    if (annexCEnabled) {
      const dcapiInfoCbor = cbor.encodeCanonical(dcapiInfo);
      console.log("[iso-mdoc][annexC] enc hex:", toHex(encBuf));
      console.log("[iso-mdoc][annexC] ct hex:", toHex(ctBuf));
      console.log("[iso-mdoc][annexC] dcapiInfo (CBOR) hex:", toHex(dcapiInfoCbor));
      console.log("[iso-mdoc][annexC] dcapiInfoHash hex:", toHex(dcapiInfoHash));
      console.log("[iso-mdoc][annexC] SessionTranscript (CBOR) hex:", toHex(infoBuf));
      console.log("[iso-mdoc][annexC] aad hex:", "");
      console.log("[iso-mdoc][annexC] origin:", origin);
      console.log("[iso-mdoc][annexC] encryptionInfo b64url:", encInfoB64Url);
    }

    // Use recipient context so we can introspect derived secrets (dev only)
    let plaintext;
    try {
      const recipientContext = await suite.createRecipientContext({
        recipientKey,
        enc: encArray,
        info: infoArray
      });

      if (annexCEnabled) {
        let sharedSecret = null;
        if (annexCSecrets && typeof suite?.kem?.decap === "function") {
          try {
            sharedSecret = await suite.kem.decap(recipientKey, encArray);
            console.log("[iso-mdoc][annexC] sharedSecret:", toHex(toU8(sharedSecret)));
          } catch (e) {
            console.log("[iso-mdoc][annexC] sharedSecret unavailable:", e?.message);
          }
        }

        const ctx = recipientContext?._ctx || recipientContext?.ctx || null;
        const baseNonce = ctx?._baseNonce || ctx?.baseNonce || ctx?._nonce || ctx?.nonce || null;
        const aeadCtx = ctx?._aeadCtx || ctx?._aead || ctx?.aead || null;
        const keyBytes =
          toU8(aeadCtx?._key) ||
          toU8(aeadCtx?.key) ||
          toU8(aeadCtx?._rawKey) ||
          toU8(aeadCtx?.rawKey);

        if (annexCSecrets && keyBytes) {
          console.log("[iso-mdoc][annexC] aeadKey:", toHex(keyBytes));
        } else if (annexCSecrets) {
          console.log("[iso-mdoc][annexC] aeadKey unavailable (library internal)");
        }
        if (baseNonce) {
          console.log("[iso-mdoc][annexC] baseNonce:", toHex(toU8(baseNonce)));
        }
      }

      plaintext = await recipientContext.open(ctArray, aad);
    } catch (e) {
      // Fallback to one-shot open if context creation fails
      if (annexCEnabled) console.log("[iso-mdoc][annexC] recipient context failed, fallback to suite.open:", e?.message);
      plaintext = await suite.open(
        { recipientKey, enc: encArray, info: infoArray },
        ctArray,
        aad
      );
    }

    // 5. Unwrap SessionData if present
    let deviceResponse = cborx.decode(toBuf(plaintext));
    if (Array.isArray(deviceResponse) && deviceResponse.length === 2 && typeof deviceResponse[0] === "number") {
      deviceResponse = deviceResponse[1];
      if (isBstr(deviceResponse)) deviceResponse = cborx.decode(toBuf(deviceResponse));
    }

    // 6. Reuse existing verification logic
    const deviceResponseB64Url = bufToB64url(cbor.encodeCanonical(deviceResponse));
    const parsed = parseMdocAndVerify(deviceResponseB64Url);
    const portrait = extractPortrait(parsed.disclosed);

    if (portrait.present && portrait.bytes) {
      portraitStore.set(request_id, { bytes: portrait.bytes, mime: portrait.mimeGuess });
    }

    return res.json({
      ok: true,
      extracted: {
        ...parsed.summary,
        portrait: {
          present: portrait.present,
          mimeGuess: portrait.mimeGuess,
          downloadUrl: portrait.present ? `/portrait/${request_id}` : null
        }
      },
      verification: parsed.results
    });

  } catch (e) {
    console.error("Decryption failed:", e);
    return res.status(400).json({ ok: false, error: "Decryption failed", message: e.message });
  }
});

app.listen(3000, () => {
  console.log("Open http://localhost:3000");
});
