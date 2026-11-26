'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const h = require('../lib/helpers');

test('isAccountID accepts digits only', () => {
  assert.equal(h.isAccountID('123456789012345'), true);
  for (const bad of ['', '12a', '123/../../admin', '123%2F..', '../1', ' 1', '1 ', 123, null, undefined, '1'.repeat(33)]) {
    assert.equal(h.isAccountID(bad), false, `expected ${JSON.stringify(bad)} to be rejected`);
  }
});

test('normalizeBaseURL keeps https origins and falls back otherwise', () => {
  assert.equal(h.normalizeBaseURL('https://testoneid.inet.co.th/'), 'https://testoneid.inet.co.th');
  assert.equal(h.normalizeBaseURL('https://one.th/some/path'), 'https://one.th');
  assert.equal(h.normalizeBaseURL('http://one.th'), h.DEFAULT_BASE_URL);
  assert.equal(h.normalizeBaseURL('javascript:alert(1)'), h.DEFAULT_BASE_URL);
  assert.equal(h.normalizeBaseURL(''), h.DEFAULT_BASE_URL);
  assert.equal(h.normalizeBaseURL(undefined), h.DEFAULT_BASE_URL);
});

test('oneIDLogoutURL encodes the redirect target', () => {
  assert.equal(h.oneIDLogoutURL('https://one.th', 'https://forum.test/a?b=c&d=e'), 'https://one.th/api/oauth/logout?redirect_url=https%3A%2F%2Fforum.test%2Fa%3Fb%3Dc%26d%3De');
});

test('businessAccess', async t => {
  await t.test('no gate configured allows everyone, even when membership is unknown', () => {
    assert.equal(h.businessAccess([], null), 'allow');
    assert.equal(h.businessAccess(undefined, []), 'allow');
  });
  await t.test('unknown membership under a gate is unknown (caller fails closed)', () => {
    assert.equal(h.businessAccess(['1'], null), 'unknown');
  });
  await t.test('compares ids as trimmed strings', () => {
    assert.equal(h.businessAccess([' 0123 '], ['0123']), 'allow');
    assert.equal(h.businessAccess(['123'], [123]), 'allow');
    assert.equal(h.businessAccess(['0123'], ['123']), 'deny');
  });
  await t.test('any match allows, no match or no membership denies', () => {
    assert.equal(h.businessAccess(['1', '2'], ['9', '2']), 'allow');
    assert.equal(h.businessAccess(['1'], ['2']), 'deny');
    assert.equal(h.businessAccess(['1'], []), 'deny');
  });
  await t.test('substring of a joined list does not match', () => {
    assert.equal(h.businessAccess(['12'], ['123']), 'deny');
  });
});

test('parseBusinessIds', () => {
  assert.deepEqual(h.parseBusinessIds(JSON.stringify({ result: 'Success', data: [{ id: 1 }, { id: '002' }, {}] })), ['1', '002']);
  assert.deepEqual(h.parseBusinessIds(JSON.stringify({ data: [] })), []);
  assert.throws(() => h.parseBusinessIds(JSON.stringify({ data: null })));
  assert.throws(() => h.parseBusinessIds('not json'));
});

test('isBlocked compares numbers and strings alike', () => {
  assert.equal(h.isBlocked(['123'], 123), true);
  assert.equal(h.isBlocked([123], '123'), true);
  assert.equal(h.isBlocked(['123'], '1234'), false);
  assert.equal(h.isBlocked(['123'], undefined), false);
});

test('parseProfile', () => {
  const residential = h.parseProfile(JSON.stringify({ data: { id: 42, thai_email: 'a@b.th', account_title_th: 'นาย', first_name_th: 'ก', last_name_th: 'ข', account_category: 'Residential', birth_date: '2000-01-01' } }), 'oneid');
  assert.deepEqual(residential, { id: '42', email: 'a@b.th', displayName: 'นายก ข', provider: 'oneid', birthday: '2000-01-01' });

  const other = h.parseProfile(JSON.stringify({ data: { id: '7', account_title_eng: 'Mr.', first_name_eng: 'A', last_name_eng: 'B' } }), 'oneid');
  assert.equal(other.displayName, 'Mr. A B');

  assert.throws(() => h.parseProfile(JSON.stringify({ data: {} }), 'oneid'));
  assert.throws(() => h.parseProfile(JSON.stringify({}), 'oneid'));
});

test('getUsernameFromEmail', () => {
  assert.equal(h.getUsernameFromEmail('john@one.th'), 'john');
  assert.equal(h.getUsernameFromEmail('@one.th'), null);
  assert.equal(h.getUsernameFromEmail('john'), null);
  assert.equal(h.getUsernameFromEmail(undefined), null);
});

test('stateMatches', () => {
  const s = h.generateState();
  assert.equal(s.length, 64);
  assert.notEqual(s, h.generateState());
  assert.equal(h.stateMatches(s, s), true);
  assert.equal(h.stateMatches(s, `${s}x`), false);
  assert.equal(h.stateMatches(s, undefined), false);
  assert.equal(h.stateMatches(undefined, undefined), false);
  assert.equal(h.stateMatches('', ''), false);
  assert.equal(h.stateMatches(s, [s]), false);
});

test('readSharedToken', () => {
  assert.equal(h.readSharedToken({ query: { sharedtoken: 'abc' } }), 'abc');
  assert.equal(h.readSharedToken({ query: {}, body: { sharedtoken: 'abc' } }), 'abc');
  assert.equal(h.readSharedToken({ query: { sharedtoken: ['a', 'b'] } }), null);
  assert.equal(h.readSharedToken({ query: { sharedtoken: 'x'.repeat(9000) } }), null);
  assert.equal(h.readSharedToken({ query: {} }), null);
});

test('originalURL ignores X-Forwarded-* unless the proxy is trusted', () => {
  const req = { headers: { host: 'internal:4567', 'x-forwarded-proto': 'https', 'x-forwarded-host': 'evil.test' }, url: '/auth/oneid', socket: {} };
  assert.equal(h.originalURL(req), 'http://internal:4567/auth/oneid');
  assert.equal(h.originalURL(req, { proxy: true }), 'https://evil.test/auth/oneid');
});
