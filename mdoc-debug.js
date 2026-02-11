#!/usr/bin/env node
/* Minimal mdoc decoder + classifier for DC API vp_token.pid1[0] */
const crypto = require("crypto");
const cbor = require("cbor");

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

function cborDecodeWithTags(bytes) {
  return cbor.decodeFirstSync(bytes, {
    tags: {
      0: (v) => new cbor.Tagged(0, v),
      24: (v) => new cbor.Tagged(24, v)
    }
  });
}

function isTagged(v, tag) {
  return v && typeof v === "object" && v.tag === tag && "value" in v;
}

function describeTopLevel(v) {
  if (isTagged(v, 24) && Buffer.isBuffer(v.value)) {
    return { kind: "Tagged(24)", details: "embedded CBOR bytes" };
  }
  if (Array.isArray(v)) {
    const elems = v.map((e) => {
      if (Buffer.isBuffer(e)) return "bstr";
      if (Array.isArray(e)) return "array";
      if (e && typeof e === "object") return "map";
      return typeof e;
    });
    return { kind: "Array", length: v.length, elements: elems };
  }
  if (v && typeof v === "object") {
    const keys = v instanceof Map ? Array.from(v.keys()) : Object.keys(v);
    return { kind: "Map/Object", keys };
  }
  return { kind: typeof v };
}

function classifyStructure(v) {
  if (isTagged(v, 24) && Buffer.isBuffer(v.value)) return "TaggedEmbeddedCBOR";
  if (Array.isArray(v) && v.length === 4) return "COSE_Sign1";
  const keys = v instanceof Map ? Array.from(v.keys()) : Object.keys(v || {});
  if (keys.includes("version") && keys.includes("documents")) return "DeviceResponse";
  if (keys.includes("docType") && keys.includes("issuerSigned")) return "Document";
  return "Unknown";
}

function parseIssuerSignedItems(nameSpaces) {
  const disclosed = [];
  for (const [ns, items] of Object.entries(nameSpaces || {})) {
    for (const item of items) {
      let itemBytes;
      let decoded;
      if (isTagged(item, 24) && Buffer.isBuffer(item.value)) {
        itemBytes = item.value;
        decoded = cborDecodeWithTags(itemBytes);
      } else if (Buffer.isBuffer(item)) {
        itemBytes = item;
        decoded = cborDecodeWithTags(itemBytes);
      } else {
        decoded = item;
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

function tagToISOString(tagged) {
  if (!isTagged(tagged, 0)) return undefined;
  if (typeof tagged.value === "string") return tagged.value;
  if (tagged.value instanceof Date) return tagged.value.toISOString();
  return String(tagged.value);
}

function main() {
  const input = process.argv[2];
  if (!input) {
    console.error("Usage: node mdoc-debug.js <base64url>");
    process.exit(1);
  }

  const normalized = normalizeB64Url(input);
  console.log("len:", normalized.length);
  console.log("prefix:", normalized.slice(0, 30));
  console.log("suffix:", normalized.slice(-30));
  console.log("b64url regex ok:", /^[A-Za-z0-9_-]+$/.test(normalized));

  const bytes = b64urlToBuf(normalized);
  console.log("byteLength:", bytes.length);
  console.log("first16:", bytes.slice(0, 16).toString("hex"));
  console.log("last16:", bytes.slice(-16).toString("hex"));
  console.log("sha256:", crypto.createHash("sha256").update(bytes).digest("hex"));

  let top = cborDecodeWithTags(bytes);
  console.log("topLevel:", describeTopLevel(top));
  let kind = classifyStructure(top);
  console.log("structure:", kind);

  if (kind === "TaggedEmbeddedCBOR") {
    top = cborDecodeWithTags(top.value);
    console.log("embeddedTopLevel:", describeTopLevel(top));
    kind = classifyStructure(top);
    console.log("structure(after tag24):", kind);
  }

  let document = top;
  if (kind === "DeviceResponse") {
    document = top.documents?.[0];
  }

  if (kind === "Document" || (document && document.docType)) {
    const issuerSigned = document.issuerSigned || {};
    const nameSpaces = issuerSigned.nameSpaces || {};
    const disclosed = parseIssuerSignedItems(nameSpaces);
    const issuerAuth = issuerSigned.issuerAuth;
    let mso;
    if (issuerAuth) {
      const cose = cborDecodeWithTags(issuerAuth);
      const payload = cose?.[2];
      if (isTagged(payload, 24) && Buffer.isBuffer(payload.value)) {
        mso = cborDecodeWithTags(payload.value);
      } else if (Buffer.isBuffer(payload)) {
        mso = cborDecodeWithTags(payload);
      }
    }
    const validityInfo = mso?.validityInfo || {};
    const summary = {
      docType: document.docType,
      disclosedAttributes: disclosed.map((d) => ({
        namespace: d.namespace,
        elementIdentifier: d.elementIdentifier,
        elementValue: d.elementValue,
        digestID: d.digestID
      })),
      validityInfo: {
        signed: tagToISOString(validityInfo.signed),
        validFrom: tagToISOString(validityInfo.validFrom),
        validUntil: tagToISOString(validityInfo.validUntil),
        expectedUpdate: tagToISOString(validityInfo.expectedUpdate)
      }
    };
    console.log("summary:", JSON.stringify(summary, null, 2));
  }
}

main();
