const $ = (id) => document.getElementById(id);

const state = {
  request: null,
  lastResponse: null,
  generatedRequest: null,
  editedRequest: null,
  requestedIdentifiers: [],
  protocol: "oid4vp",
  stepStates: {},
  issuerMetadata: null,
  supportedCredentials: []
};

const STEP_LABELS = {
  pending: "Pending",
  active: "Active",
  success: "Success",
  error: "Error"
};

function setStepState(step, status) {
  state.stepStates[step] = status;
  const stepEl = document.querySelector(`.step[data-step="${step}"]`);
  if (stepEl) {
    stepEl.classList.remove("pending", "active", "success", "error");
    stepEl.classList.add(status);
    const badge = stepEl.querySelector(".step-status");
    if (badge) badge.textContent = STEP_LABELS[status] || status;
  }
  const stepperEl = document.querySelector(`.stepper-item[data-step="${step}"]`);
  if (stepperEl) {
    stepperEl.classList.remove("pending", "active", "success", "error");
    stepperEl.classList.add(status);
  }
}

function resetStepStates() {
  setStepState(1, "active");
  setStepState(2, "pending");
  setStepState(3, "pending");
  setStepState(4, "pending");
  setStepState(5, "pending");
}

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

function connectServerLogs() {
  if (!window.EventSource) {
    addLog("warn", "Server log stream not supported in this browser.");
    return;
  }
  const es = new EventSource("/logs/stream");
  es.onmessage = (ev) => {
    try {
      const entry = JSON.parse(ev.data);
      const level = entry.level === "error" ? "error" : entry.level === "warn" ? "warn" : "info";
      addLog(level, `SERVER: ${entry.msg}`);
    } catch {
      // ignore
    }
  };
  es.onerror = () => {
    if (!state.serverLogError) {
      state.serverLogError = true;
      addLog("warn", "Server log stream disconnected.");
    }
  };
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
  const requestObj = data.request ? {
    sessionId: data.sessionId,
    request_id: data.request_id,
    request: data.request
  } : (data.data ? {
    request: {
      protocol: "org-iso-mdoc",
      data: data.data
    }
  } : (data.deviceRequest ? {
    request: {
      protocol: "org-iso-mdoc",
      data: {
        deviceRequest: data.deviceRequest,
        encryptionInfo: data.encryptionInfo
      }
    }
  } : data));
  state.generatedRequest = requestObj;
  state.editedRequest = null;
  $("requestId").textContent = data.request_id || "—";
  $("nonce").textContent = data.state_hint?.nonce || "—";
  $("state").textContent = data.state_hint?.state || "—";
  setRequestEditor(JSON.stringify(requestObj, null, 2));
  setRequestError("");
  updateRequestedIdentifiers();
  syncPidCheckboxesFromRequest(requestObj);
  syncAvCheckboxesFromRequest(requestObj);
  updateProtocolUI();
  setStepState(1, "success");
  setStepState(2, "active");
  setStepState(3, "pending");
  setStepState(4, "pending");
  setStepState(5, "pending");
}

function getProtocolFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return params.get("protocol");
}

function setProtocolInUrl(protocol) {
  const params = new URLSearchParams(window.location.search);
  params.set("protocol", protocol);
  const newUrl = `${window.location.pathname}?${params.toString()}`;
  window.history.replaceState({}, "", newUrl);
}

function loadProtocol() {
  const fromUrl = getProtocolFromUrl();
  if (fromUrl) return fromUrl === "iso18013-7" ? "iso-mdoc" : fromUrl;
  return "oid4vp";
}

function saveProtocol(protocol) {
  localStorage.setItem("avProtocol", protocol);
  setProtocolInUrl(protocol);
}

function setProtocolSelection(protocol) {
  const input = document.querySelector(`input[name=protocol][value="${protocol}"]`);
  if (input) input.checked = true;
  state.protocol = protocol;
}

function getSelectedProtocol() {
  const input = document.querySelector("input[name=protocol]:checked");
  return input ? input.value : state.protocol || "oid4vp";
}

function updateProtocolUI() {
  const selected = getSelectedProtocol();
  setProtocolSelection(selected);

  const help = $("protocolHelp");
  if (help) {
    help.textContent = selected === "iso-mdoc"
      ? "ISO 18013-5 DeviceRequest (org-iso-mdoc) over Digital Credentials API"
      : "OpenID4VP request over Digital Credentials API";
  }
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
  if (requestObj?.request?.data?.deviceRequest) {
    return [];
  }
  if (requestObj?.dcql_query?.credentials?.length) {
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
  if (requestObj?.deviceRequest?.docRequests?.length) {
    const docs = requestObj.deviceRequest.docRequests;
    let doc = docs[0];
    if (docType) {
      const match = docs.find((d) => d?.docType === docType);
      if (match) doc = match;
    }
    const ns = doc?.itemsRequest || {};
    const nsKey = docType || doc?.docType;
    const items = nsKey ? ns[nsKey] : null;
    return items ? Object.keys(items) : [];
  }
  if (Array.isArray(requestObj?.requested_attributes)) {
    return requestObj.requested_attributes.filter((v) => typeof v === "string");
  }
  if (Array.isArray(requestObj?.presentation_definition?.claims)) {
    return requestObj.presentation_definition.claims.filter((v) => typeof v === "string");
  }
  return [];
}

function updateRequestedIdentifiers(docType) {
  const req = getActiveRequest();
  state.requestedIdentifiers = getRequestedIdentifiersFromRequest(req, docType);
}

function hasCustomEditedRequest() {
  const req = state.editedRequest;
  const cred = req?.request?.data?.dcql_query?.credentials?.[0];
  const docType = cred?.meta?.doctype_value;
  return !!(docType && docType !== "eu.europa.ec.eudi.pid.1" && docType !== "eu.europa.ec.av.1");
}

function setIssuerMetaError(msg) {
  const el = $("issuerMetaError");
  if (!el) return;
  if (!msg) {
    el.classList.add("hidden");
    el.textContent = "—";
  } else {
    el.textContent = msg;
    el.classList.remove("hidden");
  }
}

function pickDisplayName(display, fallback) {
  if (Array.isArray(display)) {
    const en = display.find((d) => d?.locale === "en");
    if (en?.name) return en.name;
    if (display[0]?.name) return display[0].name;
  }
  return fallback;
}

function extractCredentialConfigs(meta) {
  const configs = meta?.credential_configurations_supported || {};
  return Object.entries(configs).map(([key, cfg]) => {
    const display = cfg?.credential_metadata?.display || cfg?.display;
    const displayName = pickDisplayName(display, key);
    const claims = Array.isArray(cfg?.credential_metadata?.claims)
      ? cfg.credential_metadata.claims
      : [];
    const claimPaths = claims
      .map((c) => (Array.isArray(c?.path) ? c.path : null))
      .filter(Boolean);
    const doctype = cfg?.doctype || null;
    const vct = cfg?.vct || null;
    const namespace = doctype || (claimPaths[0]?.[0] || null);
    const attrs = claimPaths
      .map((p) => (p.length > 0 ? p[p.length - 1] : null))
      .filter((v) => typeof v === "string");
    const mandatoryCount = claims.filter((c) => c?.mandatory).length;
    return {
      id: key,
      format: cfg?.format || "unknown",
      scope: cfg?.scope || "",
      doctype,
      vct,
      namespace,
      displayName,
      claims,
      attrs,
      mandatoryCount
    };
  });
}

function renderIssuerSummary(meta) {
  const el = $("issuerSummary");
  if (!el) return;
  if (!meta) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  const displayName = pickDisplayName(meta.display, meta.credential_issuer || "Issuer");
  const issuer = meta.credential_issuer || "—";
  const authServers = Array.isArray(meta.authorization_servers) ? meta.authorization_servers.length : 0;
  const credEndpoint = meta.credential_endpoint || "—";
  el.innerHTML = `
    <h4>${displayName}</h4>
    <div class="kv-grid">
      <div class="kv-label">issuer</div>
      <div class="kv-value"><code class="mono">${issuer}</code></div>
      <div class="kv-label">auth servers</div>
      <div class="kv-value">${authServers}</div>
      <div class="kv-label">endpoint</div>
      <div class="kv-value"><code class="mono">${credEndpoint}</code></div>
    </div>
  `;
  el.classList.remove("hidden");
}

function renderCredentialCatalog(list) {
  const container = $("credentialCatalog");
  if (!container) return;
  container.innerHTML = "";
  if (!list || list.length === 0) {
    container.classList.add("empty");
    container.textContent = "No supported credentials found in the metadata.";
    return;
  }
  container.classList.remove("empty");

  list.forEach((cred) => {
    const card = document.createElement("div");
    card.className = "credential-card";

    const name = document.createElement("div");
    name.className = "credential-name";
    name.textContent = cred.displayName;

    const tags = document.createElement("div");
    tags.className = "credential-tags";
    const formatTag = document.createElement("span");
    formatTag.className = "tag";
    formatTag.textContent = cred.format;
    tags.appendChild(formatTag);
    if (cred.doctype) {
      const d = document.createElement("span");
      d.className = "tag";
      d.textContent = cred.doctype;
      tags.appendChild(d);
    } else if (cred.vct) {
      const v = document.createElement("span");
      v.className = "tag";
      v.textContent = cred.vct;
      tags.appendChild(v);
    }

    const header = document.createElement("div");
    header.className = "credential-card-header";
    header.appendChild(name);
    header.appendChild(tags);

    const meta = document.createElement("div");
    meta.className = "credential-meta";
    const metaRows = [
      ["scope", cred.scope || "—"],
      ["claims", `${cred.attrs.length} (${cred.mandatoryCount} mandatory)`],
      ["namespace", cred.namespace || "—"]
    ];
    metaRows.forEach(([label, value]) => {
      const l = document.createElement("div");
      l.textContent = label;
      const v = document.createElement("div");
      v.textContent = value;
      meta.appendChild(l);
      meta.appendChild(v);
    });

    const claims = document.createElement("div");
    claims.className = "credential-claims";
    const preview = cred.attrs.slice(0, 6);
    preview.forEach((attr) => {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = attr;
      claims.appendChild(chip);
    });
    if (cred.attrs.length > preview.length) {
      const more = document.createElement("span");
      more.className = "chip";
      more.textContent = `+${cred.attrs.length - preview.length} more`;
      claims.appendChild(more);
    }

    const actions = document.createElement("div");
    actions.className = "credential-actions";
    const copyBtn = document.createElement("button");
    copyBtn.className = "btn btn-ghost";
    copyBtn.type = "button";
    copyBtn.textContent = "Copy claims";
    copyBtn.addEventListener("click", () => {
      copyToClipboard(JSON.stringify(cred.claims, null, 2));
    });

    const useBtn = document.createElement("button");
    useBtn.className = "btn btn-primary";
    useBtn.type = "button";
    useBtn.textContent = "Use for request";
    useBtn.disabled = cred.format !== "mso_mdoc" || !cred.namespace;
    useBtn.addEventListener("click", () => applyCredentialToRequest(cred));
    actions.appendChild(copyBtn);
    actions.appendChild(useBtn);

    card.appendChild(header);
    card.appendChild(meta);
    card.appendChild(claims);
    card.appendChild(actions);
    container.appendChild(card);
  });
}

function applyCredentialToRequest(cred) {
  if (!cred || cred.format !== "mso_mdoc" || !cred.namespace) {
    setIssuerMetaError("This credential format is not supported by the current request builder.");
    return;
  }
  setIssuerMetaError("");
  const attrs = cred.attrs.length ? cred.attrs : [];
  const baseReq = getActiveRequest() || state.generatedRequest;
  if (!baseReq) {
    setIssuerMetaError("Create a request first so the server can generate keys, then apply this credential.");
    return;
  }

  const req = JSON.parse(JSON.stringify(baseReq));
  const target = req.request?.data?.dcql_query || req.dcql_query;
  if (!target) {
    setIssuerMetaError("Request JSON missing dcql_query. Create a new request first.");
    return;
  }
  if (!Array.isArray(target.credentials)) target.credentials = [];
  const credId = cred.id || "cred1";
  const newCred = {
    id: credId,
    format: "mso_mdoc",
    meta: { doctype_value: cred.doctype || cred.namespace },
    claims: cred.claims?.length
      ? cred.claims.map((c) => ({ path: c.path }))
      : attrs.map((a) => ({ path: [cred.namespace, a] }))
  };
  target.credentials = [newCred];
  target.credential_sets = [
    {
      options: [[credId]],
      purpose: "Custom credential"
    }
  ];

  state.editedRequest = req;
  setRequestEditor(JSON.stringify(req, null, 2));
  updateRequestedIdentifiers(cred.doctype || cred.namespace);

  if (cred.doctype === "eu.europa.ec.eudi.pid.1") {
    const pidRadio = document.querySelector('input[name="cred"][value="pid"]');
    if (pidRadio) pidRadio.checked = true;
    setPidAttrChecks(false);
    attrs.forEach((a) => {
      const box = ensurePidCheckbox(a);
      if (box) box.checked = true;
    });
    updatePidAttrUI();
    addLog("info", "Applied PID attributes from metadata");
    return;
  }

  if (cred.doctype === "eu.europa.ec.av.1") {
    const avRadio = document.querySelector('input[name="cred"][value="av"]');
    if (avRadio) avRadio.checked = true;
    setAvAttrChecks(false);
    attrs.forEach((a) => {
      const box = document.querySelector(`#avAttrsSection input[data-av-attr="${a}"]`);
      if (box) box.checked = true;
    });
    updatePidAttrUI();
    addLog("info", "Applied AV attributes from metadata");
    return;
  }

  addLog("info", `Applied ${cred.displayName} (${cred.doctype || cred.namespace}) to request JSON`);
}

function importIssuerMetadata() {
  try {
    const raw = $("issuerMetadataInput")?.value?.trim();
    if (!raw) throw new Error("Paste issuer metadata JSON to import.");
    const meta = JSON.parse(raw);
    state.issuerMetadata = meta;
    const allCredentials = extractCredentialConfigs(meta);
    const mdocCredentials = allCredentials.filter((c) => c.format === "mso_mdoc");
    state.supportedCredentials = mdocCredentials;
    renderIssuerSummary(meta);
    renderCredentialCatalog(state.supportedCredentials);
    setIssuerMetaError("");
    if (mdocCredentials.length === 0) {
      setIssuerMetaError("No mso_mdoc credentials found. This UI only imports mdoc credentials.");
    }
    addLog("info", `Imported ${mdocCredentials.length} mso_mdoc credential configurations`);
  } catch (e) {
    setIssuerMetaError(`Invalid metadata JSON: ${e.message}`);
  }
}

function clearIssuerMetadata() {
  state.issuerMetadata = null;
  state.supportedCredentials = [];
  const input = $("issuerMetadataInput");
  if (input) input.value = "";
  renderIssuerSummary(null);
  renderCredentialCatalog([]);
  setIssuerMetaError("");
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

function syncAvCheckboxesFromRequest(requestObj) {
  if (!requestObj) return;
  const ids = getRequestedIdentifiersFromRequest(requestObj, "eu.europa.ec.av.1");
  const boxes = Array.from(document.querySelectorAll("#avAttrsSection input[type=checkbox][data-av-attr]"));
  boxes.forEach((b) => { b.checked = ids.includes(b.dataset.avAttr); });
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
    syncAvCheckboxesFromRequest(parsed);
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
  syncAvCheckboxesFromRequest(state.generatedRequest);
  addLog("info", "Request JSON reset");
}

function prettyPrintRequest() {
  try {
    const parsed = parseRequestEditor();
    setRequestEditor(JSON.stringify(parsed, null, 2));
    setRequestError("");
    syncPidCheckboxesFromRequest(parsed);
    syncAvCheckboxesFromRequest(parsed);
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

async function postIsoResponse(requestId, dcResponse) {
  const res = await fetch("/verifier/iso-mdoc/response", {
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
  $("verifyContent").classList.remove("hidden");
  const step5 = document.querySelector('.step[data-step="5"]');
  if (step5) step5.classList.remove("hidden");
  $("errorBanner").classList.add("hidden");

  setStatus(data.ok ? "ok" : "bad", data.ok ? "OK" : "FAIL");
  setStepState(4, data.ok ? "success" : "error");
  if (data.ok) setStepState(5, "success");

  const extracted = data.extracted || {};
  const docKey = getDocKey(extracted.docType);
  const allClaims = extracted.disclosedAttributes || [];
  updateRequestedIdentifiers(extracted.docType);
  const requestedIds = state.requestedIdentifiers || [];
  const effectiveRequested = requestedIds.length ? requestedIds : (extracted.requestedAttrs || []);
  const namespacedClaims = docKey
    ? allClaims.filter((c) => c.namespace === extracted.docType)
    : allClaims;
  const filteredClaims = effectiveRequested.length
    ? namespacedClaims.filter((c) => effectiveRequested.includes(c.elementIdentifier))
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

  const digestReason = verification.valueDigestsValid?.reason;
  if (digestsVal === null) {
    $("digests").textContent = "N/A";
    $("digests").className = "tile-value badge-neutral";
  } else {
    $("digests").textContent = digestsBadge.text;
    $("digests").className = digestsBadge.text === "PASS" ? "tile-value badge-ok" : digestsBadge.text === "FAIL" ? "tile-value badge-bad" : "tile-value badge-neutral";
  }

  const deviceReason = verification.deviceSignatureValid?.reason || "NOT VERIFIED";
  const deviceOk = verification.deviceSignatureValid?.ok;
  $("deviceSig").textContent = deviceOk === true ? "PASS" : deviceOk === false ? "FAIL" : "NOT CHECKED";
  $("deviceSig").className = deviceOk === true ? "tile-value badge-ok" : deviceOk === false ? "tile-value badge-bad" : "tile-value badge-warn";

  const perItem = verification.valueDigestsValid?.perItem || [];
  const failures = perItem.filter((i) => i.ok === false).map((i) => i.elementIdentifier).join(", ");
  $("digestFailures").textContent = failures ? `Failing fields: ${failures}` : "";
  const notes = [];
  if (digestsVal === null && digestReason) notes.push(`ValueDigests: ${digestReason}`);
  if (deviceOk === null && deviceReason) notes.push(`DeviceAuth: ${deviceReason}`);
  $("verificationNotes").textContent = notes.join(" • ");

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

function mapIsoErrorMessage(err) {
  const msg = String(err?.message || "").toLowerCase();
  const name = String(err?.name || "");
  if (
    name === "NotFoundError" ||
    name === "NotAllowedError" ||
    name === "NotSupportedError" ||
    msg.includes("not supported") ||
    msg.includes("unsupported") ||
    msg.includes("not found") ||
    msg.includes("no credential") ||
    msg.includes("no response") ||
    msg.includes("cancelled") ||
    msg.includes("canceled")
  ) {
    if (msg.includes("not supported") || msg.includes("unsupported") || name === "NotSupportedError") {
      return "This wallet does not support ISO 18013-7 presentation for this credential. Try OpenID4VP instead.";
    }
    return "No compatible ISO 18013-7 credential found in the wallet for this request. Switch to OpenID4VP (DC API) or install/import the required credential.";
  }
  return null;
}

function getSelectedPidAttrs() {
  const boxes = Array.from(document.querySelectorAll("#pidAttrsSection input[type=checkbox][data-attr]"));
  return boxes.filter((b) => b.checked).map((b) => b.dataset.attr);
}

function getSelectedAvAttrs() {
  const boxes = Array.from(document.querySelectorAll("#avAttrsSection input[type=checkbox][data-av-attr]"));
  return boxes.filter((b) => b.checked).map((b) => b.dataset.avAttr);
}

function setPidAttrChecks(checked) {
  const boxes = Array.from(document.querySelectorAll("#pidAttrsSection input[type=checkbox][data-attr]"));
  boxes.forEach((b) => { b.checked = checked; });
}

function setAvAttrChecks(checked) {
  const boxes = Array.from(document.querySelectorAll("#avAttrsSection input[type=checkbox][data-av-attr]"));
  boxes.forEach((b) => { b.checked = checked; });
}

function updatePidAttrUI() {
  const selectedCred = getSelectedCred();
  const isPid = selectedCred === "pid";
  const isAv = selectedCred === "av";
  const pidSection = $("pidAttrsSection");
  const avSection = $("avAttrsSection");
  if (pidSection) pidSection.classList.toggle("hidden", !isPid);
  if (avSection) avSection.classList.toggle("hidden", !isAv);
  if ($("pidAttrHint")) {
    $("pidAttrHint").classList.add("hidden");
  }
  if ($("avAttrHint")) {
    $("avAttrHint").classList.add("hidden");
  }
  if (!isPid) setPidAddHint("");
  if (isPid && getSelectedProtocol() === "oid4vp" && state.generatedRequest && !state.editedRequest) {
    syncRequestClaimsFromPidCheckboxes();
  }
  if (isAv && getSelectedProtocol() === "oid4vp" && state.generatedRequest && !state.editedRequest) {
    syncRequestClaimsFromAvCheckboxes();
  }
  updateProtocolUI();
}

function syncRequestClaimsFromPidCheckboxes() {
  const attrs = getSelectedPidAttrs();
  if (!attrs.length) return;
  const req = state.generatedRequest;
  if (!req) return;
  const target = req.request?.data?.dcql_query || req.dcql_query;
  if (!target) return;
  if (!Array.isArray(target.credentials)) target.credentials = [];
  let cred = target.credentials.find((c) => c?.meta?.doctype_value === "eu.europa.ec.eudi.pid.1");
  if (!cred) {
    cred = { id: "pid1", format: "mso_mdoc", meta: { doctype_value: "eu.europa.ec.eudi.pid.1" }, claims: [] };
    target.credentials.unshift(cred);
  }
  cred.id = "pid1";
  cred.claims = attrs.map((a) => ({ path: ["eu.europa.ec.eudi.pid.1", a] }));
  setRequestEditor(JSON.stringify(req, null, 2));
  updateRequestedIdentifiers("eu.europa.ec.eudi.pid.1");
}

function syncRequestClaimsFromAvCheckboxes() {
  const attrs = getSelectedAvAttrs();
  if (!attrs.length) return;
  const req = state.generatedRequest;
  if (!req) return;
  const target = req.request?.data?.dcql_query || req.dcql_query;
  if (!target) return;
  if (!Array.isArray(target.credentials)) target.credentials = [];
  let cred = target.credentials.find((c) => c?.meta?.doctype_value === "eu.europa.ec.av.1");
  if (!cred) {
    cred = { id: "av1", format: "mso_mdoc", meta: { doctype_value: "eu.europa.ec.av.1" }, claims: [] };
    target.credentials.unshift(cred);
  }
  cred.id = "av1";
  cred.claims = attrs.map((a) => ({ path: ["eu.europa.ec.av.1", a] }));
  setRequestEditor(JSON.stringify(req, null, 2));
  updateRequestedIdentifiers("eu.europa.ec.av.1");
}

async function handleCreateRequest() {
  const btn = $("createRequestBtn");
  btn.dataset.label = btn.textContent;
  setLoading(btn, true);
  let protocol = "oid4vp";
  try {
    const cred = getSelectedCred();
    protocol = getSelectedProtocol();
    state.protocol = protocol;
    let url = `/verifier/oid4vp/request?cred=${encodeURIComponent(cred)}`;
    if (cred === "pid") {
      const attrs = getSelectedPidAttrs();
      url += `&attrs=${encodeURIComponent(attrs.join(","))}`;
    }
    if (cred === "av") {
      const attrs = getSelectedAvAttrs();
      url += `&attrs=${encodeURIComponent(attrs.join(","))}`;
    }
    if (protocol === "iso-mdoc") {
      url = `/verifier/iso-mdoc/request?cred=${encodeURIComponent(cred)}`;
      if (cred === "pid") {
        const attrs = getSelectedPidAttrs();
        if (attrs.length) url += `&attrs=${encodeURIComponent(attrs.join(","))}`;
      }
      if (cred === "av") {
        const attrs = getSelectedAvAttrs();
        if (attrs.length) url += `&attrs=${encodeURIComponent(attrs.join(","))}`;
      }
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
    setStepState(1, "error");
    return null;
  } finally {
    setLoading(btn, false);
  }
}

async function handleInvokeDcApi() {
  const btn = $("invokeDcApiBtn");
  btn.dataset.label = btn.textContent;
  setLoading(btn, true);
  let protocol = "oid4vp";
  try {
    const cred = getSelectedCred();
    protocol = getSelectedProtocol();
    if (!state.request?.request_id) {
      throw new Error("Create a request first.");
    }
    const req = getActiveRequest();
    if (!req) throw new Error("No request JSON available.");
    updateRequestedIdentifiers(cred === "av" ? "eu.europa.ec.av.1" : "eu.europa.ec.eudi.pid.1");

    if (protocol === "iso-mdoc") {
      if (!navigator.credentials || !navigator.credentials.get) {
        throw new Error("Digital Credentials API not available for ISO 18013-7.");
      }
      const requestWrapper = req?.request ? req : state.generatedRequest;
      const isoData = requestWrapper?.request?.data || requestWrapper?.data || {
        deviceRequest: req.deviceRequest || state.generatedRequest?.deviceRequest,
        encryptionInfo: req.encryptionInfo || state.generatedRequest?.encryptionInfo
      };
      const isoProtocol = requestWrapper?.request?.protocol || "org-iso-mdoc";
      if (!isoData.deviceRequest) throw new Error("Missing deviceRequest in ISO request JSON.");
      if (!isoData.encryptionInfo) throw new Error("Missing encryptionInfo in ISO request JSON.");
      const isoResponse = await navigator.credentials.get({
        mediation: "required",
        digital: {
          requests: [
            { protocol: isoProtocol, data: isoData }
          ]
        }
      });
      if (!isoResponse) throw new Error("No response from wallet");
      $("dcResponseInput").value = JSON.stringify(isoResponse, null, 2);
      addLog("info", "ISO presentation response received");
      setStepState(2, "success");
      setStepState(3, "success");
      setStepState(4, "pending");
      return;
    }

    if (!navigator.credentials || !navigator.credentials.get) {
      throw new Error("Digital Credentials API not available in this browser");
    }
    const requestWrapper = req?.request ? req : state.generatedRequest;
    const oid4vpProtocol = requestWrapper?.request?.protocol || state.request?.protocol || "openid4vp-v1-unsigned";
    const oid4vpData = requestWrapper?.request?.data || req;
    const dcResponse = await navigator.credentials.get({
      mediation: "required",
      digital: {
        requests: [
          { protocol: oid4vpProtocol, data: oid4vpData }
        ]
      }
    });
    if (!dcResponse) throw new Error("No response from DC API");
    $("dcResponseInput").value = JSON.stringify(dcResponse, null, 2);
    addLog("info", "DC API response received");
    setStepState(2, "success");
    setStepState(3, "success");
    setStepState(4, "pending");
  } catch (e) {
    const friendly = protocol === "iso-mdoc" ? mapIsoErrorMessage(e) : null;
    const message = friendly || e.message;
    $("errorBanner").textContent = message;
    $("errorBanner").classList.remove("hidden");
    addLog("error", message);
    setStepState(2, "error");
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

  let protocol = "oid4vp";
  try {
    const requestId =
      state.request?.request_id ||
      state.generatedRequest?.request_id ||
      state.editedRequest?.request_id;
    if (!requestId) {
      throw new Error("Missing request_id. Create a request first.");
    }
    const dcResponse = parseTextareaJson();
    const cred = getSelectedCred();
    protocol = getSelectedProtocol();
    setStepState(3, "success");
    setStepState(4, "active");
    updateRequestedIdentifiers(cred === "av" ? "eu.europa.ec.av.1" : "eu.europa.ec.eudi.pid.1");
    const data = (protocol === "iso-mdoc")
      ? await postIsoResponse(requestId, dcResponse)
      : await postResponse(requestId, dcResponse);
    renderResults(data);
    addLog("info", "Response verified");
  } catch (e) {
    input.classList.add("error");
    setStatus("bad", "FAIL");
    setStepState(4, "error");
    $("verifyContent").classList.add("hidden");
    $("resultsEmpty").classList.remove("hidden");
    const step5 = document.querySelector('.step[data-step="5"]');
    if (step5) step5.classList.add("hidden");
    const friendly = protocol === "iso-mdoc" ? mapIsoErrorMessage(e) : null;
    const message = friendly || e.message;
    $("errorBanner").textContent = message;
    $("errorBanner").classList.remove("hidden");
    addLog("error", message);
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
  $("verifyContent").classList.add("hidden");
  $("resultsEmpty").classList.remove("hidden");
  const step5 = document.querySelector('.step[data-step="5"]');
  if (step5) step5.classList.add("hidden");
  $("errorBanner").classList.add("hidden");
  setStatus("neutral", "Idle");
  resetStepStates();
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
$("importMetadataBtn")?.addEventListener("click", importIssuerMetadata);
$("clearMetadataBtn")?.addEventListener("click", clearIssuerMetadata);

document.querySelectorAll("input[name=cred]").forEach((el) => {
  el.addEventListener("change", updatePidAttrUI);
});
document.querySelectorAll("input[name=protocol]").forEach((el) => {
  el.addEventListener("change", () => {
    const protocol = getSelectedProtocol();
    saveProtocol(protocol);
    updateProtocolUI();
  });
});
document.querySelectorAll("#pidAttrsSection input[type=checkbox][data-attr]").forEach((el) => {
  el.addEventListener("change", updatePidAttrUI);
});
document.querySelectorAll("#avAttrsSection input[type=checkbox][data-av-attr]").forEach((el) => {
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
$("avSelectAllBtn")?.addEventListener("click", () => {
  setAvAttrChecks(true);
  updatePidAttrUI();
});
$("avSelectNoneBtn")?.addEventListener("click", () => {
  setAvAttrChecks(false);
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
$("dcResponseInput").addEventListener("input", (e) => {
  const val = e.target.value.trim();
  if (!val) {
    setStepState(3, "pending");
    setStepState(4, "pending");
    return;
  }
  if (state.stepStates[3] !== "success") {
    setStepState(3, "active");
  }
});

setStatus("neutral", "Idle");
setProtocolSelection(loadProtocol());
updatePidAttrUI();
resetStepStates();
connectServerLogs();
