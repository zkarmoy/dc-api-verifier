const test = require('node:test');
const assert = require('node:assert/strict');

const {
  filterAttributes,
  summarizeSelection,
  canCreateRequest,
  upsertCredentialClaims
} = require('../public/ui-logic.js');

test('filterAttributes returns full list for empty query', () => {
  const attrs = ['family_name', 'given_name', 'birth_date'];
  assert.deepEqual(filterAttributes(attrs, ''), attrs);
});

test('filterAttributes matches by token', () => {
  const attrs = ['family_name', 'given_name', 'birth_date'];
  assert.deepEqual(filterAttributes(attrs, 'name'), ['family_name', 'given_name']);
});

test('summarizeSelection formats selected and total count', () => {
  assert.equal(summarizeSelection(2, 7), '2 selected of 7');
});

test('canCreateRequest requires selected attrs for current credential', () => {
  assert.equal(canCreateRequest({ cred: 'pid', pidSelectedCount: 1, avSelectedCount: 0 }), true);
  assert.equal(canCreateRequest({ cred: 'pid', pidSelectedCount: 0, avSelectedCount: 2 }), false);
  assert.equal(canCreateRequest({ cred: 'av', pidSelectedCount: 2, avSelectedCount: 0 }), false);
  assert.equal(canCreateRequest({ cred: 'av', pidSelectedCount: 0, avSelectedCount: 1 }), true);
});

test('upsertCredentialClaims updates top-level dcql_query', () => {
  const request = {
    dcql_query: {
      credentials: [
        {
          id: 'pid1',
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' },
          claims: [{ path: ['eu.europa.ec.eudi.pid.1', 'family_name'] }]
        }
      ]
    }
  };

  upsertCredentialClaims(request, {
    docType: 'eu.europa.ec.eudi.pid.1',
    credId: 'pid1',
    attrs: ['given_name', 'birth_date']
  });

  const claims = request.dcql_query.credentials[0].claims;
  assert.deepEqual(claims, [
    { path: ['eu.europa.ec.eudi.pid.1', 'given_name'] },
    { path: ['eu.europa.ec.eudi.pid.1', 'birth_date'] }
  ]);
});

test('upsertCredentialClaims updates nested request.data.dcql_query', () => {
  const request = {
    request: {
      data: {
        dcql_query: {
          credentials: []
        }
      }
    }
  };

  upsertCredentialClaims(request, {
    docType: 'eu.europa.ec.av.1',
    credId: 'av1',
    attrs: ['age_over_18']
  });

  const creds = request.request.data.dcql_query.credentials;
  assert.equal(creds.length, 1);
  assert.equal(creds[0].id, 'av1');
  assert.deepEqual(creds[0].claims, [{ path: ['eu.europa.ec.av.1', 'age_over_18'] }]);
});

test('upsertCredentialClaims supports empty attrs without removing credential entry', () => {
  const request = {
    dcql_query: {
      credentials: [
        {
          id: 'pid1',
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' },
          claims: [{ path: ['eu.europa.ec.eudi.pid.1', 'family_name'] }]
        }
      ]
    }
  };

  upsertCredentialClaims(request, {
    docType: 'eu.europa.ec.eudi.pid.1',
    credId: 'pid1',
    attrs: []
  });

  const creds = request.dcql_query.credentials;
  assert.equal(creds.length, 1);
  assert.equal(creds[0].id, 'pid1');
  assert.deepEqual(creds[0].claims, []);
});
