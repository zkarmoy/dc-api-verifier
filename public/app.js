const $ = (id) => document.getElementById(id);

const state = {
  request: null,
  lastResponse: null,
  generatedRequest: null,
  editedRequest: null,
  requestedIdentifiers: []
};

function setStatus(type, message) {
  const badge = $("statusBadge");
  badge.textContent = message;
  badge.className = `badge badge-${type}`;
}

function addLog(level, msg) {
  const log = $("log");
  const time = new Date().toLocaleTimeString();
  const line = document.createElement("div");
  line.className = `log-line ${level}`;
  line.textContent = `[${time}] ${level.toUpperCase()}: ${msg}`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    addLog("info", "Copied to clipboard");
  } catch (e) {
    addLog("error", "Failed to copy");
  }
}

function renderRequest(data) {
  state.request = data;
  state.generatedRequest = data.request;
  state.editedRequest = null;
  $("requestId").textContent = data.request_id || "—";
  $("nonce").textContent = data.state_hint?.nonce || "—";
  $("state").textContent = data.state_hint?.state || "—";
  setRequestEditor(JSON.stringify(data.request, null, 2));
  setRequestError("");
  updateRequestedIdentifiers();
  syncPidCheckboxesFromRequest(data.request);
}

function setRequestError(msg) {
  const el = $("requestJsonError");
  if (!el) return;
  if (!msg) {
    el.classList.add("hidden");
    el.textContent = "—";
  } else {
    el.textContent = msg;
    el.classList.remove("hidden");
  }
}

function setRequestEditor(text) {
  const editor = $("requestJsonEditor");
  if (editor) editor.value = text;
}

function getRequestEditorText() {
  const editor = $("requestJsonEditor");
  return editor ? editor.value.trim() : "";
}

function parseRequestEditor() {
  const text = getRequestEditorText();
  if (!text) throw new Error("Request JSON is empty");
  return JSON.parse(text);
}

function getActiveRequest() {
  return state.editedRequest || state.generatedRequest;
}

function getRequestedIdentifiersFromRequest(requestObj, docType) {
  if (!requestObj?.dcql_query?.credentials?.length) return [];
  const creds = requestObj.dcql_query.credentials;
  let cred = creds[0];
  if (docType) {
    const match = creds.find((c) => c?.meta?.doctype_value === docType);
    if (match) cred = match;
  }
  const claims = Array.isArray(cred?.claims) ? cred.claims : [];
  return claims
    .map((c) => Array.isArray(c?.path) ? c.path[1] : null)
    .filter((v) => typeof v === "string" && v.length > 0);
}

function updateRequestedIdentifiers(docType) {
  const req = getActiveRequest();
  state.requestedIdentifiers = getRequestedIdentifiersFromRequest(req, docType);
}

function setPidAddHint(msg) {
  const el = $("pidAddHint");
  if (!el) return;
  if (!msg) {
    el.classList.add("hidden");
    el.textContent = "—";
  } else {
    el.textContent = msg;
    el.classList.remove("hidden");
  }
}

function ensurePidCheckbox(attr) {
  const grid = document.querySelector(".checkbox-grid");
  if (!grid) return null;
  let input = grid.querySelector(`input[data-attr="${attr}"]`);
  if (input) return input;
  const label = document.createElement("label");
  label.className = "check";
  input = document.createElement("input");
  input.type = "checkbox";
  input.dataset.attr = attr;
  const span = document.createElement("span");
  span.textContent = attr;
  label.appendChild(input);
  label.appendChild(span);
  grid.appendChild(label);
  input.addEventListener("change", updatePidAttrUI);
  return input;
}

function syncPidCheckboxesFromRequest(requestObj) {
  if (!requestObj) return;
  const ids = getRequestedIdentifiersFromRequest(requestObj, "eu.europa.ec.eudi.pid.1");
  const boxes = Array.from(document.querySelectorAll("#pidAttrsSection input[type=checkbox][data-attr]"));
  boxes.forEach((b) => { b.checked = ids.includes(b.dataset.attr); });
  ids.forEach((id) => {
    const box = ensurePidCheckbox(id);
    if (box) box.checked = true;
  });
}

function addPidAttributeFromInput() {
  const input = $("pidAddInput");
  if (!input) return;
  const raw = input.value.trim();
  if (!raw) return;
  if (!/^[a-zA-Z0-9_]+$/.test(raw)) {
    setPidAddHint("Invalid attribute name. Use letters, numbers, underscore.");
    return;
  }

  let req;
  try {
    req = parseRequestEditor();
  } catch (e) {
    setPidAddHint("Fix request JSON before adding attributes.");
    return;
  }

  const ids = getRequestedIdentifiersFromRequest(req, "eu.europa.ec.eudi.pid.1");
  if (ids.includes(raw)) {
    setPidAddHint("Attribute already added.");
    addLog("info", `Attribute already added: ${raw}`);
    input.value = "";
    return;
  }

  if (!req.dcql_query) req.dcql_query = {};
  if (!Array.isArray(req.dcql_query.credentials)) req.dcql_query.credentials = [];
  let cred = req.dcql_query.credentials.find((c) => c?.meta?.doctype_value === "eu.europa.ec.eudi.pid.1");
  if (!cred) {
    cred = { id: "pid1", format: "mso_mdoc", meta: { doctype_value: "eu.europa.ec.eudi.pid.1" }, claims: [] };
    req.dcql_query.credentials.unshift(cred);
  }
  if (!Array.isArray(cred.claims)) cred.claims = [];
  cred.claims.push({ path: ["eu.europa.ec.eudi.pid.1", raw] });

  state.editedRequest = req;
  setRequestEditor(JSON.stringify(req, null, 2));
  updateRequestedIdentifiers("eu.europa.ec.eudi.pid.1");
  syncPidCheckboxesFromRequest(req);
  setPidAddHint("");
  input.value = "";
  addLog("info", `Added PID attribute: ${raw}`);
}

function applyRequestEdits() {
  try {
    const parsed = parseRequestEditor();
    state.editedRequest = parsed;
    setRequestEditor(JSON.stringify(parsed, null, 2));
    setRequestError("");
    updateRequestedIdentifiers();
    syncPidCheckboxesFromRequest(parsed);
    addLog("info", "Applied request edits");
  } catch (e) {
    setRequestError(`Invalid JSON: ${e.message}`);
    addLog("error", "Request JSON invalid");
  }
}

function resetRequestEdits() {
  if (!state.generatedRequest) return;
  state.editedRequest = null;
  setRequestEditor(JSON.stringify(state.generatedRequest, null, 2));
  setRequestError("");
  updateRequestedIdentifiers();
  syncPidCheckboxesFromRequest(state.generatedRequest);
  addLog("info", "Request JSON reset");
}

function prettyPrintRequest() {
  try {
    const parsed = parseRequestEditor();
    setRequestEditor(JSON.stringify(parsed, null, 2));
    setRequestError("");
    syncPidCheckboxesFromRequest(parsed);
  } catch (e) {
    setRequestError(`Invalid JSON: ${e.message}`);
  }
}

function parseTextareaJson() {
  const input = $("dcResponseInput");
  const text = input.value.trim();
  if (!text) throw new Error("dcResponse JSON is empty");
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error("Invalid JSON in textarea");
  }
}

async function postResponse(requestId, dcResponse) {
  const res = await fetch("/verifier/oid4vp/response", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request_id: requestId, dcResponse })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error || "Request failed";
    throw new Error(message);
  }
  return data;
}

function badgeFor(value) {
  if (value === true) return { cls: "badge-ok", text: "PASS" };
  if (value === false) return { cls: "badge-bad", text: "FAIL" };
  return { cls: "badge-neutral", text: "—" };
}

function formatValue(v) {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return v.map(formatValue).join(", ");
  if (typeof v === "object") {
    const tagVal = v.value ?? v._value;
    if (tagVal !== undefined && (v.tag !== undefined || v._tag !== undefined || v.type)) return formatValue(tagVal);
    if (v.type === "full-date" && v.value) return String(v.value);
    if (v.type === "date" && v.value) return String(v.value);
    if (v.data && Array.isArray(v.data)) {
      const preview = v.data.slice(0, 8).map((n) => n.toString(16).padStart(2, "0")).join("");
      return `0x${preview}…`;
    }
    return JSON.stringify(v);
  }
  return String(v);
}

const FIELD_MAP = {
  pid: {
    given_name: { label: "Given name", order: 1 },
    family_name: { label: "Family name", order: 2 },
    birth_date: { label: "Birth date", order: 3 },
    birth_place: { label: "Birth place", order: 4 },
    nationality: { label: "Nationality", order: 5 },
    issuing_authority: { label: "Issuing authority", order: 6 },
    issuing_country: { label: "Issuing country", order: 7 },
    expiry_date: { label: "Expiry date", order: 8 },
    portrait: { label: "Portrait", order: 9 }
  },
  av: {
    age_over_18: { label: "Age over 18", order: 1 },
    age_over_21: { label: "Age over 21", order: 2 },
    issuing_country: { label: "Issuing country", order: 3 },
    expiry_date: { label: "Expiry date", order: 4 }
  }
};

function normalizeValue(v) {
  if (v === null || v === undefined) return { text: "—" };
  if (typeof v === "boolean") return { text: v ? "Yes" : "No", kind: "bool", value: v };
  if (typeof v === "number") return { text: String(v) };
  if (typeof v === "string") return { text: v };
  if (Array.isArray(v)) {
    const joined = v.map((x) => normalizeValue(x).text).join(", ");
    return { text: joined };
  }
  if (typeof v === "object") {
    const tagVal = v.value ?? v._value;
    if (tagVal !== undefined && (v.tag !== undefined || v._tag !== undefined || v.type)) {
      return normalizeValue(tagVal);
    }
    if ((v.type === "full-date" || v.type === "date") && v.value) {
      return { text: String(v.value), iso: String(v.value) };
    }
    if (v.type === "Buffer" && Array.isArray(v.data)) {
      const len = v.data.length;
      return { text: `[binary] ${len} bytes`, kind: "binary", bytes: len };
    }
    if (Array.isArray(v.data)) {
      const len = v.data.length;
      return { text: `[binary] ${len} bytes`, kind: "binary", bytes: len };
    }
    return { text: JSON.stringify(v) };
  }
  return { text: String(v) };
}

function formatDateDisplay(iso) {
  if (!iso || typeof iso !== "string") return "—";
  if (/^\d{4}-\d{2}-\d{2}$/.test(iso)) {
    const [y, m, d] = iso.split("-").map((n) => parseInt(n, 10));
    const utc = new Date(Date.UTC(y, m - 1, d));
    const local = new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      timeZone: "UTC"
    }).format(utc);
    return `${iso} (${local})`;
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const local = d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
  return `${iso} (${local})`;
}

function renderBoolChip(v) {
  const cls = v ? "value-chip value-yes" : "value-chip value-no";
  const label = v ? "Yes ✓" : "No ✕";
  return `<span class="${cls}">${label}</span>`;
}

function getDocKey(docType) {
  if (docType === "eu.europa.ec.eudi.pid.1") return "pid";
  if (docType === "eu.europa.ec.av.1") return "av";
  return null;
}

function looksLikeBase64(s) {
  if (typeof s !== "string") return false;
  if (s.length < 512) return false;
  return /^[A-Za-z0-9+/=]+$/.test(s);
}

function estimateBase64Bytes(s) {
  if (!s || typeof s !== "string") return 0;
  const len = s.length;
  const padding = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((len * 3) / 4) - padding);
}

function sanitizeJsonForDisplay(value) {
  const seen = new WeakSet();

  const walk = (v) => {
    if (v === null || v === undefined) return v;
    if (typeof v === "string") {
      if (v.startsWith("data:image")) {
        const [meta, dataPart = ""] = v.split(",", 2);
        const mime = meta.split(";")[0]?.slice(5) || "application/octet-stream";
        const bytes = estimateBase64Bytes(dataPart);
        return `[omitted: ${bytes} bytes, ${mime}]`;
      }
      if (looksLikeBase64(v)) {
        const bytes = estimateBase64Bytes(v);
        return `[omitted: ${bytes} bytes, application/octet-stream]`;
      }
      return v;
    }
    if (typeof v !== "object") return v;
    if (seen.has(v)) return "[omitted: circular]";
    seen.add(v);
    if (Array.isArray(v)) return v.map(walk);
    const out = {};
    Object.keys(v).forEach((k) => {
      out[k] = walk(v[k]);
    });
    return out;
  };

  return walk(value);
}

async function decodeJp2ToCanvas(bytes) {
  if (!window.JpxImage) throw new Error("JP2 decoder not available");
  const jpx = new window.JpxImage();
  jpx.parse(bytes);
  const { width, height, componentsCount, tiles } = jpx;
  if (!width || !height || !tiles?.length) throw new Error("Invalid JP2 image data");
  const tile = tiles[0];
  const comps = tile.items;
  if (!Array.isArray(comps) || comps.length < 1) throw new Error("JP2 components missing");

  const rgba = new Uint8ClampedArray(width * height * 4);
  if (componentsCount === 1) {
    const g = comps[0];
    for (let i = 0; i < width * height; i++) {
      const v = g[i];
      const o = i * 4;
      rgba[o] = v;
      rgba[o + 1] = v;
      rgba[o + 2] = v;
      rgba[o + 3] = 255;
    }
  } else {
    const r = comps[0];
    const g = comps[1];
    const b = comps[2];
    const a = comps[3];
    for (let i = 0; i < width * height; i++) {
      const o = i * 4;
      rgba[o] = r[i];
      rgba[o + 1] = g[i];
      rgba[o + 2] = b[i];
      rgba[o + 3] = a ? a[i] : 255;
    }
  }

  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  const imageData = new ImageData(rgba, width, height);
  ctx.putImageData(imageData, 0, 0);
  return canvas;
}

function shortenSubject(subject) {
  if (!subject) return "—";
  const parts = subject.split(",").map((p) => p.trim());
  const cn = parts.find((p) => p.startsWith("CN="));
  return cn ? cn.replace("CN=", "") : subject;
}

function renderIdentityCardPID(extracted, claimsById) {
  const given = normalizeValue(claimsById.given_name);
  const family = normalizeValue(claimsById.family_name);
  const displayName = [given.text, family.text].filter((v) => v && v !== "—").join(" ");
  const validity = extracted.validityInfo || {};

  const rows = [
    ["Birth date", claimsById.birth_date, true],
    ["Birth place", claimsById.birth_place],
    ["Nationality", claimsById.nationality],
    ["Issuing authority", claimsById.issuing_authority],
    ["Issuing country", claimsById.issuing_country],
    ["Expiry date", claimsById.expiry_date, true]
  ].map(([label, raw, isDate]) => {
    const norm = normalizeValue(raw);
    if (norm.kind === "bool") {
      return `<div class="kv-label">${label}</div><div class="kv-value">${renderBoolChip(norm.value)}</div>`;
    }
    const text = isDate && norm.text && norm.text !== "—" ? formatDateDisplay(norm.text) : norm.text;
    return `<div class="kv-label">${label}</div><div class="kv-value mono">${text || "—"}</div>`;
  }).join("");

  return `
    <div class="id-header">
      <div class="chip">${extracted.docType || "docType"}</div>
      <div class="chip">${extracted.topLevelKind || "mdoc"}</div>
    </div>
    <div class="id-name">${displayName || "—"}</div>
    <div class="kv-grid">${rows}</div>
    <div class="timeline">
      <div class="timeline-bar"></div>
      <div class="timeline-labels">
        <span>${formatValue(validity.validFrom) || "—"}</span>
        <span>${formatValue(validity.validUntil) || "—"}</span>
      </div>
    </div>
    <div class="issued-by">Issued by ${shortenSubject(extracted.issuerCertificate?.subject)}</div>
  `;
}

function renderIdentityCardAV(extracted, claimsById) {
  const over18 = normalizeValue(claimsById.age_over_18);
  const over21 = normalizeValue(claimsById.age_over_21);
  const issuing = normalizeValue(claimsById.issuing_country);
  const expiry = normalizeValue(claimsById.expiry_date);

  return `
    <div class="id-header">
      <div class="chip">${extracted.docType || "docType"}</div>
      <div class="chip">Age Verification</div>
    </div>
    <div class="id-name">Age Checks</div>
    <div class="kv-grid">
      <div class="kv-label">Age over 18</div>
      <div class="kv-value">${over18.kind === "bool" ? renderBoolChip(over18.value) : over18.text}</div>
      <div class="kv-label">Age over 21</div>
      <div class="kv-value">${over21.kind === "bool" ? renderBoolChip(over21.value) : over21.text}</div>
      <div class="kv-label">Issuing country</div>
      <div class="kv-value mono">${issuing.text || "—"}</div>
      <div class="kv-label">Expiry date</div>
      <div class="kv-value mono">${expiry.text ? formatDateDisplay(expiry.text) : "—"}</div>
    </div>
    <div class="issued-by">Issued by ${shortenSubject(extracted.issuerCertificate?.subject)}</div>
  `;
}

function renderResults(data) {
  state.lastResponse = data;
  $("resultsEmpty").classList.add("hidden");
  $("resultsContent").classList.remove("hidden");
  $("errorBanner").classList.add("hidden");

  setStatus(data.ok ? "ok" : "bad", data.ok ? "OK" : "FAIL");

  const extracted = data.extracted || {};
  const docKey = getDocKey(extracted.docType);
  const allClaims = extracted.disclosedAttributes || [];
  updateRequestedIdentifiers(extracted.docType);
  const requestedIds = state.requestedIdentifiers || [];
  const namespacedClaims = docKey
    ? allClaims.filter((c) => c.namespace === extracted.docType)
    : allClaims;
  const filteredClaims = requestedIds.length
    ? namespacedClaims.filter((c) => requestedIds.includes(c.elementIdentifier))
    : namespacedClaims;

  const claimsById = filteredClaims.reduce((acc, c) => {
    acc[c.elementIdentifier] = c.elementValue;
    return acc;
  }, {});

  const isAv = docKey === "av";
  $("identityCard").innerHTML = isAv
    ? renderIdentityCardAV(extracted, claimsById)
    : renderIdentityCardPID(extracted, claimsById);

  // Portrait
  const portraitCard = $("portraitCard");
  portraitCard.classList.add("hidden");
  const portrait = extracted.portrait || {};
  const requested = extracted.requestedAttrs || [];
  const portraitRequested = requested.includes("portrait");
  if (portrait.present && portraitRequested) {
    if (portrait.dataUrl) {
      portraitCard.innerHTML = `
        <div class="section"><strong>Portrait</strong></div>
        <img class="portrait-img" src="${portrait.dataUrl}" alt="Portrait" />
      `;
      portraitCard.classList.remove("hidden");
    } else if (portrait.mimeGuess === "image/jp2" && portrait.downloadUrl) {
      portraitCard.innerHTML = `
        <div class="section"><strong>Portrait</strong></div>
        <div class="portrait-status">Decoding portrait…</div>
        <div class="section"><a class="btn btn-ghost" href="${portrait.downloadUrl}">Download JP2</a></div>
      `;
      portraitCard.classList.remove("hidden");
      (async () => {
        try {
          const res = await fetch(portrait.downloadUrl);
          if (!res.ok) throw new Error("Failed to fetch JP2");
          const bytes = new Uint8Array(await res.arrayBuffer());
          const canvas = await decodeJp2ToCanvas(bytes);
          canvas.className = "portrait-img";
          const status = portraitCard.querySelector(".portrait-status");
          if (status) status.remove();
          portraitCard.appendChild(canvas);
        } catch (e) {
          const status = portraitCard.querySelector(".portrait-status");
          if (status) {
            status.textContent = "JP2 decode failed. Please download the file.";
            status.classList.add("error");
          }
        }
      })();
    } else if (portrait.downloadUrl) {
      const bytes = portrait.byteLength || 0;
      const mime = portrait.mimeGuess || "application/octet-stream";
      portraitCard.innerHTML = `
        <div>Portrait available (${bytes} bytes, ${mime}).</div>
        <div class="section"><a class="btn btn-ghost" href="${portrait.downloadUrl}">Download</a></div>
      `;
      portraitCard.classList.remove("hidden");
    }
  }

  // Requested vs disclosed
  const requestedEl = $("requestedAttrs");
  if (requestedEl) {
    requestedEl.innerHTML = "";
  let requested = requestedIds.length ? requestedIds.slice() : (extracted.requestedAttrs || []);
  if (!requested.length && isAv) {
    requested = ["age_over_18", "age_over_21", "issuing_country", "expiry_date"];
  }
    if (docKey === "pid") {
      requested = requested.filter((a) => FIELD_MAP.pid[a]);
    }
    if (docKey === "av") {
      requested = requested.filter((a) => FIELD_MAP.av[a]);
    }
    if (!requested.length) {
      requestedEl.innerHTML = `<div class="kv-label">Requested</div><div class="kv-value">—</div>`;
    } else {
      const map = docKey ? FIELD_MAP[docKey] : null;
      requested.forEach((attr) => {
        const label = document.createElement("div");
        label.className = "kv-label";
        label.textContent = map?.[attr]?.label || attr;
        const value = document.createElement("div");
        value.className = "kv-value mono";
        const disclosed = filteredClaims.some((c) => c.elementIdentifier === attr);
        value.textContent = disclosed ? "disclosed" : "not disclosed";
        requestedEl.appendChild(label);
        requestedEl.appendChild(value);
      });
    }
  }

  // Claims list
  const claimsEl = $("claims");
  claimsEl.innerHTML = "";
  if (!allClaims.length) {
    claimsEl.innerHTML = `<div class="kv-label">No disclosed attributes</div><div class="kv-value">—</div>`;
  } else {
    allClaims.forEach((a) => {
      const label = document.createElement("div");
      label.className = "kv-label";
      const map = getDocKey(a.namespace) ? FIELD_MAP[getDocKey(a.namespace)] : null;
      label.textContent = map?.[a.elementIdentifier]?.label || a.elementIdentifier;
      const value = document.createElement("div");
      value.className = "kv-value mono";
      const norm = normalizeValue(a.elementValue);
      if (norm.kind === "binary") value.textContent = norm.text;
      else if (norm.kind === "bool") value.innerHTML = renderBoolChip(norm.value);
      else value.textContent = norm.text;
      claimsEl.appendChild(label);
      claimsEl.appendChild(value);
    });
  }

  const verification = data.verification || {};
  const issuerBadge = badgeFor(verification.issuerAuthSignatureValid);
  const digestsVal = verification.valueDigestsValid?.allOk;
  const digestsBadge = badgeFor(digestsVal);

  $("issuerSig").textContent = issuerBadge.text;
  $("issuerSig").className = issuerBadge.text === "PASS" ? "tile-value badge-ok" : issuerBadge.text === "FAIL" ? "tile-value badge-bad" : "tile-value badge-neutral";

  $("digests").textContent = digestsBadge.text;
  $("digests").className = digestsBadge.text === "PASS" ? "tile-value badge-ok" : digestsBadge.text === "FAIL" ? "tile-value badge-bad" : "tile-value badge-neutral";

  const deviceReason = verification.deviceSignatureValid?.reason || "NOT VERIFIED";
  $("deviceSig").textContent = deviceReason.includes("NOT VERIFIED") ? "NOT CHECKED" : "—";
  $("deviceSig").className = "tile-value badge-warn";

  const perItem = verification.valueDigestsValid?.perItem || [];
  const failures = perItem.filter((i) => i.ok === false).map((i) => i.elementIdentifier).join(", ");
  $("digestFailures").textContent = failures ? `Failing fields: ${failures}` : "";

  // Certificate
  const cert = extracted.issuerCertificate || {};
  console.log("[cert] renderer input:", JSON.parse(JSON.stringify(cert)));
  const certSummary = $("certSummary");
  certSummary.innerHTML = `
    <div class="kv-label">subjectCN</div><div class="kv-value mono">${cert.subjectCN || "—"}</div>
    <div class="kv-label">subjectO</div><div class="kv-value mono">${cert.subjectO || "—"}</div>
    <div class="kv-label">subjectOU</div><div class="kv-value mono">${cert.subjectOU || "—"}</div>
    <div class="kv-label">subjectC</div><div class="kv-value mono">${cert.subjectC || "—"}</div>
    <div class="kv-label">issuerCN</div><div class="kv-value mono">${cert.issuerCN || "—"}</div>
    <div class="kv-label">issuerO</div><div class="kv-value mono">${cert.issuerO || "—"}</div>
    <div class="kv-label">issuerOU</div><div class="kv-value mono">${cert.issuerOU || "—"}</div>
    <div class="kv-label">issuerC</div><div class="kv-value mono">${cert.issuerC || "—"}</div>
    <div class="kv-label">serialNumber</div><div class="kv-value mono">${cert.serialNumber || "—"}</div>
    <div class="kv-label">validity</div><div class="kv-value mono">${cert.notBefore || "—"} → ${cert.notAfter || "—"}</div>
    <div class="kv-label">publicKey</div><div class="kv-value mono">${cert.publicKeyAlg || "—"} ${cert.publicKeyCurve || ""}</div>
  `;
  $("certRaw").textContent = `Subject:\n${cert.subject || "—"}\n\nIssuer:\n${cert.issuer || "—"}`;

  const cbor = data.cbor_debug || {};
  $("byteLength").textContent = cbor.byteLength ?? "—";
  $("sha256").textContent = cbor.sha256 ?? "—";
  $("first16").textContent = cbor.first16 ?? "—";
  $("last16").textContent = cbor.last16 ?? "—";
  $("topLevelKind").textContent = cbor.topLevelKind ?? "—";

  const showFull = $("toggleRawFull")?.checked;
  const rawValue = showFull ? data : sanitizeJsonForDisplay(data);
  $("rawResponse").textContent = JSON.stringify(rawValue, null, 2);
}

function setLoading(btn, loading) {
  btn.disabled = loading;
  btn.textContent = loading ? "Loading…" : btn.dataset.label;
}

function getSelectedCred() {
  const input = document.querySelector("input[name=cred]:checked");
  return input ? input.value : "pid";
}

function getSelectedPidAttrs() {
  const boxes = Array.from(document.querySelectorAll("#pidAttrsSection input[type=checkbox][data-attr]"));
  return boxes.filter((b) => b.checked).map((b) => b.dataset.attr);
}

function setPidAttrChecks(checked) {
  const boxes = Array.from(document.querySelectorAll("#pidAttrsSection input[type=checkbox][data-attr]"));
  boxes.forEach((b) => { b.checked = checked; });
}

function updatePidAttrUI() {
  const isPid = getSelectedCred() === "pid";
  const section = $("pidAttrsSection");
  if (section) section.classList.toggle("hidden", !isPid);
  const selected = isPid ? getSelectedPidAttrs() : ["_"];
  const disabled = isPid && selected.length === 0;
  $("createRequestBtn").disabled = disabled;
  $("invokeDcApiBtn").disabled = disabled;
  $("submitResponseBtn").disabled = disabled;
  if ($("pidAttrHint")) {
    $("pidAttrHint").classList.toggle("hidden", !disabled);
  }
  if (!isPid) setPidAddHint("");
}

async function handleCreateRequest() {
  const btn = $("createRequestBtn");
  btn.dataset.label = btn.textContent;
  setLoading(btn, true);
  try {
    const cred = getSelectedCred();
    let url = `/verifier/oid4vp/request?cred=${encodeURIComponent(cred)}`;
    if (cred === "pid") {
      const attrs = getSelectedPidAttrs();
      if (!attrs.length) throw new Error("Select at least one PID attribute.");
      url += `&attrs=${encodeURIComponent(attrs.join(","))}`;
    }
    addLog("info", `Selected cred: ${cred}`);
    addLog("info", `GET ${url}`);
    const res = await fetch(url);
    const data = await res.json();
    renderRequest(data);
    state.requestCred = cred;
    addLog("info", `Request created (${cred})`);
    return data;
  } catch (e) {
    addLog("error", e.message);
    return null;
  } finally {
    setLoading(btn, false);
  }
}

async function handleInvokeDcApi() {
  const btn = $("invokeDcApiBtn");
  btn.dataset.label = btn.textContent;
  setLoading(btn, true);
  try {
    const cred = getSelectedCred();
    if (!state.request?.request_id) {
      throw new Error("Create a request first.");
    }
    const req = getActiveRequest();
    if (!req) throw new Error("No request JSON available.");
    updateRequestedIdentifiers(cred === "av" ? "eu.europa.ec.av.1" : "eu.europa.ec.eudi.pid.1");
    if (!navigator.credentials || !navigator.credentials.get) {
      throw new Error("Digital Credentials API not available in this browser");
    }
    const dcResponse = await navigator.credentials.get({
      digital: {
        requests: [
          { protocol: state.request.protocol, data: req }
        ]
      }
    });
    if (!dcResponse) throw new Error("No response from DC API");
    $("dcResponseInput").value = JSON.stringify(dcResponse, null, 2);
    addLog("info", "DC API response received");
  } catch (e) {
    addLog("error", e.message);
  } finally {
    setLoading(btn, false);
  }
}

async function handleSubmitResponse() {
  const btn = $("submitResponseBtn");
  btn.dataset.label = btn.textContent;
  setLoading(btn, true);
  const input = $("dcResponseInput");
  input.classList.remove("error");
  $("errorBanner").classList.add("hidden");

  try {
    if (!state.request?.request_id) {
      throw new Error("Missing request_id. Create a request first.");
    }
    const dcResponse = parseTextareaJson();
    updateRequestedIdentifiers(getSelectedCred() === "av" ? "eu.europa.ec.av.1" : "eu.europa.ec.eudi.pid.1");
    const data = await postResponse(state.request.request_id, dcResponse);
    renderResults(data);
    addLog("info", "Response verified");
  } catch (e) {
    input.classList.add("error");
    setStatus("bad", "FAIL");
    $("errorBanner").textContent = e.message;
    $("errorBanner").classList.remove("hidden");
    addLog("error", e.message);
  } finally {
    setLoading(btn, false);
  }
}

function handleFileUpload(ev) {
  const file = ev.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    $("dcResponseInput").value = reader.result;
    addLog("info", `Loaded ${file.name}`);
  };
  reader.readAsText(file);
}

function resetUI() {
  $("dcResponseInput").value = "";
  $("dcResponseInput").classList.remove("error");
  $("resultsContent").classList.add("hidden");
  $("resultsEmpty").classList.remove("hidden");
  $("errorBanner").classList.add("hidden");
  setStatus("neutral", "Idle");
  addLog("info", "UI reset");
}

function insertExample() {
  $("dcResponseInput").value = JSON.stringify(
    {
      protocol: "openid4vp-v1-unsigned",
      data: { vp_token: { pid1: ["<base64url-device-response>"] } }
    },
    null,
    2
  );
}

function copyLogs() {
  const lines = Array.from(document.querySelectorAll(".log-line")).map((l) => l.textContent);
  copyToClipboard(lines.join("\n"));
}

$("createRequestBtn").addEventListener("click", handleCreateRequest);
$("invokeDcApiBtn").addEventListener("click", handleInvokeDcApi);
$("submitResponseBtn").addEventListener("click", handleSubmitResponse);
$("copyRequestIdBtn").addEventListener("click", () => {
  if (state.request?.request_id) copyToClipboard(state.request.request_id);
});
$("copyRequestJsonBtn").addEventListener("click", () => {
  const text = getRequestEditorText();
  if (text) copyToClipboard(text);
});
$("copyResponseJsonBtn").addEventListener("click", () => {
  if (state.lastResponse) copyToClipboard(JSON.stringify(state.lastResponse, null, 2));
});
const rawToggle = $("toggleRawFull");
if (rawToggle) {
  rawToggle.addEventListener("change", () => {
    if (state.lastResponse) renderResults(state.lastResponse);
  });
}
$("copySubjectBtn").addEventListener("click", () => {
  const cert = state.lastResponse?.extracted?.issuerCertificate?.subject;
  if (cert) copyToClipboard(cert);
});
$("copyIssuerBtn").addEventListener("click", () => {
  const cert = state.lastResponse?.extracted?.issuerCertificate?.issuer;
  if (cert) copyToClipboard(cert);
});
$("fileInput").addEventListener("change", handleFileUpload);
$("resetBtn").addEventListener("click", resetUI);
$("exampleBtn").addEventListener("click", insertExample);
$("copyLogsBtn").addEventListener("click", copyLogs);
$("applyRequestEditsBtn")?.addEventListener("click", applyRequestEdits);
$("resetRequestEditsBtn")?.addEventListener("click", resetRequestEdits);
$("prettyRequestBtn")?.addEventListener("click", prettyPrintRequest);

document.querySelectorAll("input[name=cred]").forEach((el) => {
  el.addEventListener("change", updatePidAttrUI);
});
document.querySelectorAll("#pidAttrsSection input[type=checkbox][data-attr]").forEach((el) => {
  el.addEventListener("change", updatePidAttrUI);
});
$("pidSelectAllBtn")?.addEventListener("click", () => {
  setPidAttrChecks(true);
  updatePidAttrUI();
});
$("pidSelectNoneBtn")?.addEventListener("click", () => {
  setPidAttrChecks(false);
  updatePidAttrUI();
});
if ($("pidAddBtn")) {
  $("pidAddBtn").addEventListener("click", addPidAttributeFromInput);
}
if ($("pidAddInput")) {
  $("pidAddInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      addPidAttributeFromInput();
    }
  });
}

$("dcResponseInput").addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.key === "Enter") handleSubmitResponse();
});

setStatus("neutral", "Idle");
updatePidAttrUI();
