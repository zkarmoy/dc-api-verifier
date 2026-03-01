(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory();
  } else {
    root.UiLogic = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  function normalizeAttrToken(raw) {
    return String(raw || "").trim().toLowerCase();
  }

  function filterAttributes(attributes, query) {
    const normalized = normalizeAttrToken(query);
    if (!normalized) return attributes.slice();
    return attributes.filter((attr) => attr.includes(normalized));
  }

  function summarizeSelection(selectedCount, totalCount) {
    return selectedCount + " selected of " + totalCount;
  }

  function canCreateRequest(input) {
    const cred = input && input.cred ? input.cred : "pid";
    const pidCount = Number(input && input.pidSelectedCount ? input.pidSelectedCount : 0);
    const avCount = Number(input && input.avSelectedCount ? input.avSelectedCount : 0);
    if (cred === "av") return avCount > 0;
    return pidCount > 0;
  }

  function upsertCredentialClaims(requestObj, options) {
    if (!requestObj || !options) return requestObj;
    const docType = options.docType;
    const credId = options.credId;
    const attrs = Array.isArray(options.attrs) ? options.attrs : [];
    const target = requestObj.request && requestObj.request.data && requestObj.request.data.dcql_query
      ? requestObj.request.data.dcql_query
      : requestObj.dcql_query;
    if (!target) return requestObj;

    if (!Array.isArray(target.credentials)) target.credentials = [];
    var cred = target.credentials.find(function (entry) {
      return entry && entry.meta && entry.meta.doctype_value === docType;
    });

    if (!cred) {
      cred = {
        id: credId,
        format: "mso_mdoc",
        meta: { doctype_value: docType },
        claims: []
      };
      target.credentials.unshift(cred);
    }

    cred.id = credId;
    cred.claims = attrs.map(function (attr) {
      return { path: [docType, attr] };
    });
    return requestObj;
  }

  return {
    normalizeAttrToken: normalizeAttrToken,
    filterAttributes: filterAttributes,
    summarizeSelection: summarizeSelection,
    canCreateRequest: canCreateRequest,
    upsertCredentialClaims: upsertCredentialClaims
  };
});
