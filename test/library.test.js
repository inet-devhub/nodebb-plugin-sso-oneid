'use strict';

// Loads library.js against in-memory stand-ins for the NodeBB modules it pulls
// in through require.main.require, so the strategy and verify logic can run
// without a NodeBB install.

const test = require('node:test');
const assert = require('node:assert/strict');

const state = {};

function resetState() {
  state.settings = { id: 'client-id', secret: 'client-secret', server: 'https://one.th' };
  state.oneidToUid = {};
  state.userFields = {};
  state.restricted = [];
  state.allowed = [];
  state.createdUsers = [];
  state.successfulLogins = [];
  state.takenEmails = new Set();
  state.passportStrategies = {};
}
resetState();

const stubs = {
  './src/user': {
    create: async data => {
      const uid = 100 + state.createdUsers.length;
      state.createdUsers.push(data);
      state.userFields[uid] = { ...data };
      return uid;
    },
    setUserField: async (uid, field, value) => {
      state.userFields[uid] = { ...state.userFields[uid], [field]: value };
    },
    setUserFields: async (uid, fields) => {
      state.userFields[uid] = { ...state.userFields[uid], ...fields };
    },
    getUserField: async (uid, field) => (state.userFields[uid] || {})[field],
    getUsersFields: async uids => uids.map(uid => ({ banned: (state.userFields[uid] || {}).banned || false, reason: (state.userFields[uid] || {}).reason })),
    email: {
      available: async email => !state.takenEmails.has(email),
      confirmByUid: async () => {},
    },
    auth: { revokeSession: async () => {} },
  },
  './src/groups': { systemGroups: ['registered-users', 'banned-users'], BANNED_USERS: 'banned-users', leave: async () => {}, join: async () => {} },
  './src/meta': { settings: { get: async () => state.settings }, configs: { cookie: { get: () => ({}) } }, config: { onlineCutoff: 30 } },
  './src/database': {
    getObjectField: async (key, field) => (key === 'oneid:uid' ? state.oneidToUid[field] : undefined),
    setObjectField: async (key, field, value) => {
      if (key === 'oneid:uid') state.oneidToUid[field] = value;
    },
    setObject: async (key, obj) => {
      const uid = key.split(':')[1];
      state.userFields[uid] = { ...state.userFields[uid], ...obj };
      state.allowed.push(Number(uid));
    },
    sortedSetAdd: async () => {},
    deleteObjectField: async () => {},
  },
  './src/middleware/helpers': { buildBodyClass: () => '' },
  './src/socket.io': { in: () => ({ emit: () => {} }) },
  './src/controllers/authentication': {
    onSuccessfulLogin: async (req, uid) => {
      state.successfulLogins.push(uid);
    },
  },
  './src/routes/helpers': {},
  nconf: { get: key => ({ url: 'https://forum.test', relative_path: '' })[key] },
  winston: { verbose() {}, warn() {}, error() {}, info() {} },
  passport: {
    use: (name, strategy) => {
      state.passportStrategies[name] = strategy;
    },
  },
};

const originalRequire = require.main.require.bind(require.main);
require.main.require = id => (Object.prototype.hasOwnProperty.call(stubs, id) ? stubs[id] : originalRequire(id));

const OAuth2Strategy = require('passport-oauth2');
const prototypeAuthenticate = OAuth2Strategy.prototype.authenticate;
const prototypeUserProfile = OAuth2Strategy.prototype.userProfile;

const OneIDAuth = require('../library');

async function buildStrategy() {
  const strategies = await OneIDAuth.buildStrategy([]);
  return { strategies, strategy: state.passportStrategies.oneid };
}

function fakeReq(query = {}, session = {}) {
  const res = {
    redirectedTo: null,
    redirect(url) {
      this.redirectedTo = url;
    },
  };
  return { query, body: {}, session, headers: { host: 'forum.test' }, url: '/auth/oneid/callback', socket: {}, res, loggedIn: false };
}

/** Run strategy.authenticate and resolve with the first passport action it takes. */
function runAuthenticate(strategy, req) {
  return new Promise(resolve => {
    const s = Object.create(strategy);
    s.redirect = url => resolve({ action: 'redirect', url });
    s.error = err => resolve({ action: 'error', err });
    s.fail = info => resolve({ action: 'fail', info });
    s.success = (user, info) => resolve({ action: 'success', user, info });
    s.authenticate(req, {});
    // Paths that answer through req.res.redirect instead of a passport action
    const poll = setInterval(() => {
      if (req.res.redirectedTo) {
        clearInterval(poll);
        resolve({ action: 'res.redirect', url: req.res.redirectedTo });
      }
    }, 5);
    setTimeout(() => {
      clearInterval(poll);
      resolve({ action: 'timeout' });
    }, 1000).unref();
  });
}

test.beforeEach(() => resetState());

test('does not patch the shared passport-oauth2 prototype', async () => {
  await buildStrategy();
  assert.equal(OAuth2Strategy.prototype.authenticate, prototypeAuthenticate);
  assert.equal(OAuth2Strategy.prototype.userProfile, prototypeUserProfile);
});

test('no strategy without client credentials', async () => {
  state.settings = {};
  const strategies = await OneIDAuth.buildStrategy([]);
  assert.deepEqual(strategies, []);
});

test('reads the refcode field the ACP form saves', async () => {
  state.settings.refcode = 'REF1';
  const { strategy } = await buildStrategy();
  assert.equal(strategy._oauth2._refCode, 'REF1');
});

test('login redirect carries a fresh state that is stored in the session', async () => {
  const { strategy } = await buildStrategy();
  const req = fakeReq({}, {});
  const result = await runAuthenticate(strategy, req);
  assert.equal(result.action, 'redirect');
  const location = new URL(result.url);
  assert.equal(location.origin + location.pathname, 'https://one.th/api/oauth/getcode');
  assert.equal(location.searchParams.get('client_id'), 'client-id');
  assert.equal(location.searchParams.get('response_type'), 'code');
  assert.equal(location.searchParams.get('redirect_uri'), 'https://forum.test/auth/oneid/callback');
  assert.match(location.searchParams.get('state'), /^[0-9a-f]{64}$/);
  assert.equal(req.session.oneidOAuthState, location.searchParams.get('state'));
});

test('callback code is rejected without a matching state', async t => {
  const { strategy } = await buildStrategy();
  let exchanged = false;
  strategy._oauth2.getOAuthAccessToken = () => {
    exchanged = true;
  };

  for (const [name, query, session] of [
    ['no state in session', { code: 'c', state: 'abc' }, {}],
    ['no state in query', { code: 'c' }, { oneidOAuthState: 'abc' }],
    ['different state', { code: 'c', state: 'abd' }, { oneidOAuthState: 'abc' }],
    ['array code', { code: ['c', 'd'], state: 'abc' }, { oneidOAuthState: 'abc' }],
  ]) {
    await t.test(name, async () => {
      const result = await runAuthenticate(strategy, fakeReq(query, session));
      assert.equal(result.action, 'error');
      assert.equal(result.err.message, '[[error:csrf-invalid]]');
    });
  }
  assert.equal(exchanged, false);
});

test('callback with matching state exchanges the code, and the state is single use', async () => {
  const { strategy } = await buildStrategy();
  const calls = [];
  strategy._oauth2.getOAuthAccessToken = (code, params, cb) => {
    calls.push({ code, params });
    cb(Object.assign(new Error('bad'), { statusCode: 500 }));
  };
  const session = { oneidOAuthState: 'abc' };
  await runAuthenticate(strategy, fakeReq({ code: 'the-code', state: 'abc' }, session));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].code, 'the-code');
  assert.equal(calls[0].params.grant_type, 'authorization_code');
  assert.equal(session.oneidOAuthState, undefined);

  const replay = await runAuthenticate(strategy, fakeReq({ code: 'the-code', state: 'abc' }, session));
  assert.equal(replay.action, 'error');
  assert.equal(calls.length, 1);
});

test('shared token is exchanged as JSON with refcode only when configured', async t => {
  for (const [name, refcode, expectRefcode] of [
    ['without refcode', undefined, false],
    ['with refcode', 'REF1', true],
  ]) {
    await t.test(name, async () => {
      resetState();
      if (refcode) state.settings.refcode = refcode;
      const { strategy } = await buildStrategy();
      let sent;
      strategy._oauth2._request = (method, url, headers, body, accessToken, cb) => {
        sent = { method, url, headers, body: JSON.parse(body) };
        cb(Object.assign(new Error('expired'), { statusCode: 400 }));
      };
      const req = fakeReq({ sharedtoken: 'tok' });
      const result = await runAuthenticate(strategy, req);

      assert.equal(sent.url, 'https://one.th/api/oauth/shared-token');
      assert.equal(sent.headers['Content-Type'], 'application/json');
      assert.equal(sent.body.shared_token, 'tok');
      assert.equal(sent.body.client_id, 'client-id');
      assert.equal('refcode' in sent.body, expectRefcode);
      if (expectRefcode) assert.equal(sent.body.refcode, 'REF1');

      // A rejected shared token falls back to the normal login
      assert.deepEqual(result, { action: 'res.redirect', url: '/auth/oneid' });
    });
  }
});

test('rejected authorization code sends the user to the forbidden page via OneID logout', async () => {
  const { strategy } = await buildStrategy();
  strategy._oauth2._request = (method, url, headers, body, accessToken, cb) => cb(Object.assign(new Error('invalid_grant'), { statusCode: 400 }));
  const result = await runAuthenticate(strategy, fakeReq({ code: 'c', state: 'abc' }, { oneidOAuthState: 'abc' }));
  assert.equal(result.action, 'res.redirect');
  assert.equal(result.url, `https://one.th/api/oauth/logout?redirect_url=${encodeURIComponent('https://forum.test/error/forbidden')}`);
});

function runVerify(profile) {
  return new Promise(resolve => {
    OneIDAuth.verify(fakeReq(), 'at', 'rt', { username: 'oneuser' }, profile, (err, user) => resolve({ err, user }));
  });
}

test('verify', async t => {
  await t.test('creates and links a new user, and confirms a free e-mail', async () => {
    const { err, user } = await runVerify({ id: '555', email: 'jane@one.th', displayName: 'Jane', associateBiz: null });
    assert.equal(err, null);
    assert.equal(user.uid, 100);
    assert.equal(state.oneidToUid['555'], 100);
    assert.equal(state.createdUsers[0].username, 'jane');
    assert.equal(state.userFields[100].email, 'jane@one.th');
    assert.deepEqual(state.successfulLogins, [100]);
  });

  await t.test('does not take over an e-mail owned by another account, and still logs in', async () => {
    state.takenEmails.add('jane@one.th');
    const { err, user } = await runVerify({ id: '555', email: 'jane@one.th', displayName: 'Jane', associateBiz: null });
    assert.equal(err, null);
    assert.equal(user.uid, 100);
    assert.equal(state.userFields[100].email, undefined);
  });

  await t.test('falls back to the OneID username when there is no e-mail', async () => {
    const { err } = await runVerify({ id: '556', displayName: 'No Mail', associateBiz: null });
    assert.equal(err, null);
    assert.equal(state.createdUsers[0].username, 'oneuser');
  });

  await t.test('reuses the linked user on the next login', async () => {
    state.oneidToUid['555'] = 7;
    const { user } = await runVerify({ id: '555', email: 'jane@one.th', displayName: 'Jane', associateBiz: [] });
    assert.equal(user.uid, 7);
    assert.equal(state.createdUsers.length, 0);
  });

  await t.test('block list denies, matching number against string', async () => {
    state.settings.denyAccountList = [{ account_id: '555' }];
    const { err } = await runVerify({ id: 555, email: 'jane@one.th', associateBiz: [] });
    assert.equal(err.code, 'forbidden');
    assert.equal(state.createdUsers.length, 0);
  });

  await t.test('business gate: member of an allowed business logs in', async () => {
    state.settings.businessList = [{ id: '0001' }];
    const { err, user } = await runVerify({ id: '555', email: 'jane@one.th', associateBiz: ['0001'] });
    assert.equal(err, null);
    assert.ok(user.uid);
  });

  await t.test('business gate: non-member existing user is denied and restricted', async () => {
    state.settings.businessList = [{ id: '0001' }];
    state.oneidToUid['555'] = 7;
    state.userFields[7] = {};
    const { err } = await runVerify({ id: '555', associateBiz: ['0002'] });
    assert.equal(err.code, 'forbidden');
    assert.equal(state.userFields[7].banned, 1);
    assert.equal(state.userFields[7].reason, 'forbidden');
  });

  await t.test('business gate: unknown membership denies without restricting', async () => {
    state.settings.businessList = [{ id: '0001' }];
    state.oneidToUid['555'] = 7;
    state.userFields[7] = {};
    const { err } = await runVerify({ id: '555', associateBiz: null });
    assert.equal(err.code, 'forbidden');
    assert.equal(state.userFields[7].banned, undefined);
  });

  await t.test('user restricted by this plugin is allowed again once access is granted', async () => {
    state.oneidToUid['555'] = 7;
    state.userFields[7] = { banned: 1, reason: 'forbidden' };
    const { err, user } = await runVerify({ id: '555', associateBiz: [] });
    assert.equal(err, null);
    assert.equal(user.uid, 7);
    assert.deepEqual(state.allowed, [7]);
  });

  await t.test('user banned by an administrator stays banned', async () => {
    state.oneidToUid['555'] = 7;
    state.userFields[7] = { banned: 1, reason: 'spam' };
    const { err } = await runVerify({ id: '555', associateBiz: [] });
    assert.equal(err.code, 'forbidden');
    assert.deepEqual(state.allowed, []);
    assert.deepEqual(state.successfulLogins, []);
  });
});

test('logout filter returns the payload with an encoded OneID logout URL', async () => {
  const payload = await OneIDAuth.userLogout({ next: '/' });
  assert.equal(payload.next, `https://one.th/api/oauth/logout?redirect_url=${encodeURIComponent('https://forum.test')}`);
});
