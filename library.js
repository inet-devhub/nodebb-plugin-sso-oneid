'use strict';

const querystring = require('node:querystring');
const OAuth2Strategy = require('passport-oauth2');

const User = require.main.require('./src/user');
const Groups = require.main.require('./src/groups');
const meta = require.main.require('./src/meta');
const db = require.main.require('./src/database');
const middlewareHelpers = require.main.require('./src/middleware/helpers');
const sockets = require.main.require('./src/socket.io');
const authenticationController = require.main.require('./src/controllers/authentication');
const routeHelpers = require.main.require('./src/routes/helpers');
const nconf = require.main.require('nconf');
const winston = require.main.require('winston');
const passport = require.main.require('passport');

const helpers = require('./lib/helpers');

const { InternalOAuthError, AuthorizationError } = OAuth2Strategy;

const constants = Object.freeze({
  name: 'oneid',
  settingsKey: 'sso-oneid',
  sessionStateKey: 'oneidOAuthState',
  admin: {
    route: '/plugins/sso-oneid',
    icon: 'fa-cogs',
  },
});

const OneIDAuth = {
  baseURL: helpers.DEFAULT_BASE_URL,
  authorizationURL: '/api/oauth/getcode',
  tokenURL: '/oauth/token',
  sharedTokenURL: '/api/oauth/shared-token',
  profileURL: '/go-api/v1/citizen/service/account?q=all',
  businessURL: '/api/v3/business/service/list-business',
  businessCheck: [],
  blockAccounts: [],
  intranetEnabled: false,
  intranet: {
    baseURL: '',
    apiKey: '',
  },
};

const AVATAR_MAX_BYTES = 5 * 1024 * 1024;

function forbiddenError() {
  const err = new Error('forbidden');
  err.code = 'forbidden';
  return err;
}

function forbiddenRedirectURL() {
  return helpers.oneIDLogoutURL(OneIDAuth.baseURL, `${nconf.get('url')}/error/forbidden`);
}

/**
 * OneID token exchange. Replaces node-oauth's OAuth2#getOAuthAccessToken on the
 * strategy's own OAuth2 client: the code exchange is form-encoded, the
 * shared-token exchange is JSON and goes to a different endpoint.
 * `this` is the node-oauth OAuth2 instance.
 */
function getOAuthAccessToken(code, params, callback) {
  params = { ...(params || {}) };
  params.client_id = this._clientId;
  params.client_secret = this._clientSecret;

  let tokenUrl = this._baseSite + this._accessTokenUrl;
  let headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  let postData;

  if (Object.prototype.hasOwnProperty.call(params, 'shared_token')) {
    tokenUrl = this._baseSite + this._sharedTokenURL;
    if (this._refCode) params.refcode = this._refCode;
    headers = { 'Content-Type': 'application/json' };
    postData = JSON.stringify(params);
  } else {
    const codeParam = params.grant_type === 'refresh_token' ? 'refresh_token' : 'code';
    params[codeParam] = code;
    postData = querystring.stringify(params);
  }

  this._request('POST', tokenUrl, headers, postData, null, (error, data) => {
    if (error) return callback(error);
    let results;
    try {
      results = JSON.parse(data);
    } catch {
      results = querystring.parse(data);
    }
    const accessToken = results.access_token;
    const refreshToken = results.refresh_token;
    delete results.refresh_token;
    callback(null, accessToken, refreshToken, results);
  });
}

/**
 * OneID flavour of passport-oauth2. Subclassed rather than patching
 * OAuth2Strategy.prototype, which is shared with every other plugin that
 * resolves the same passport-oauth2 module.
 */
class OneIDStrategy extends OAuth2Strategy {
  constructor(options, verify) {
    super(options, verify);
    this.name = constants.name;
    this._profileURL = options.profileURL;
    this._businessURL = options.businessURL;

    this._oauth2._useAuthorizationHeaderForGET = true;
    this._oauth2.getOAuthAccessToken = getOAuthAccessToken;
    this._oauth2._refCode = options.refCode || '';
    this._oauth2._sharedTokenURL = options.sharedTokenURL;
  }

  authenticate(req, options) {
    options = options || {};

    if (req.query && req.query.error) {
      if (req.query.error === 'access_denied') {
        return this.fail({ message: req.query.error_description });
      }
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }

    let callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      callbackURL = new URL(callbackURL, helpers.originalURL(req, { proxy: this._trustProxy })).href;
    }

    // 1. Authorization-code callback: the code is only accepted together with
    //    the state value this browser session was given (login CSRF protection).
    if (req.query && req.query.code) {
      const expected = req.session && req.session[constants.sessionStateKey];
      if (req.session) delete req.session[constants.sessionStateKey];

      if (typeof req.query.code !== 'string' || !helpers.stateMatches(expected, req.query.state)) {
        winston.warn('[sso-oneid] Rejected authorization callback: missing or invalid state');
        return this.error(new Error('[[error:csrf-invalid]]'));
      }

      const params = this.tokenParams(options);
      params.grant_type = 'authorization_code';
      if (callbackURL) params.redirect_uri = callbackURL;
      return this._exchangeToken(req, req.query.code, params, false);
    }

    // 2. Shared-token hand-off from another OneID-integrated service.
    const sharedToken = helpers.readSharedToken(req);
    if (sharedToken) {
      return this._exchangeToken(req, null, { shared_token: sharedToken }, true);
    }

    // 3. Start the authorization-code flow.
    if (!req.session) {
      return this.error(new Error('OneID login requires a session'));
    }
    const state = helpers.generateState();
    req.session[constants.sessionStateKey] = state;

    const params = {
      ...this.authorizationParams(options),
      response_type: 'code',
      state,
      client_id: this._oauth2._clientId,
    };
    if (callbackURL) params.redirect_uri = callbackURL;

    const location = new URL(this._oauth2._authorizeUrl);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) location.searchParams.set(key, value);
    }
    this.redirect(location.href);
  }

  _exchangeToken(req, code, params, isSharedToken) {
    this._oauth2.getOAuthAccessToken(code, params, (err, accessToken, refreshToken, results) => {
      if (err) {
        if (err.statusCode >= 400) {
          if (req.session && req.session.registration) delete req.session.registration;

          if (isSharedToken) {
            // Shared tokens are single use and short lived; an expired, reused or
            // wrong-environment token falls back to the normal login, which completes
            // without a prompt because the user is already signed in at OneID.
            winston.warn(`[sso-oneid] Shared token rejected by OneID (HTTP ${err.statusCode}), falling back to normal login`);
            return req.res.redirect(`${nconf.get('relative_path')}/auth/${constants.name}`);
          }

          winston.warn(`[sso-oneid] Token exchange rejected by OneID (HTTP ${err.statusCode})`);
          return OneIDAuth.clearSession(req, req.res)
            .catch(e => winston.error(`[sso-oneid] Clear session error: ${e.message}`))
            .then(() => req.res.redirect(forbiddenRedirectURL()));
        }
        return this.error(this._createOAuthError('Failed to obtain access token', err));
      }
      if (!accessToken) {
        return this.error(new Error('Failed to obtain access token'));
      }

      this._loadUserProfile(accessToken, (err, profile) => {
        if (err) return this.error(err);

        const verified = (err, user, info) => {
          if (err) return this.error(err);
          if (!user) return this.fail(info);
          this.success(user, info || {});
        };

        try {
          this._verify(req, accessToken, refreshToken, results, profile, verified);
        } catch (ex) {
          return this.error(ex);
        }
      });
    });
  }

  userProfile(accessToken, done) {
    const get = url =>
      new Promise((resolve, reject) => {
        this._oauth2.get(url, accessToken, (err, body) => (err ? reject(err) : resolve(body)));
      });

    (async () => {
      let profile;
      try {
        profile = helpers.parseProfile(await get(this._profileURL), constants.name);
      } catch (err) {
        return done(new InternalOAuthError('failed to fetch user profile', err));
      }

      // Business membership is only needed when a business allowlist is set.
      // A failed lookup leaves it unknown (null); the allowlist check then denies.
      try {
        profile.associateBiz = helpers.parseBusinessIds(await get(this._businessURL));
      } catch (err) {
        winston.warn(`[sso-oneid] Could not fetch business membership for account ${profile.id}: ${err.message || err.statusCode}`);
        profile.associateBiz = null;
      }

      done(null, profile);
    })();
  }
}

OneIDAuth.init = async function (data) {
  winston.verbose('[sso-oneid] Init sso configuration');
  routeHelpers.setupAdminPageRoute(data.router, '/admin/plugins/sso-oneid', (req, res) => {
    res.render('admin/plugins/sso-oneid', {
      title: 'One ID',
      baseUrl: nconf.get('url'),
    });
  });

  routeHelpers.setupPageRoute(data.router, '/error/forbidden', [], async (req, res) => {
    if (req.loggedIn) {
      return res.redirect(`${nconf.get('relative_path')}/`);
    }

    const logoutURL = helpers.oneIDLogoutURL(OneIDAuth.baseURL, `${nconf.get('url')}/login`);
    res.status(403).render('403', {
      error: `ขออภัย! บัญชีของคุณ <strong>ไม่อนุญาต</strong> ให้เข้าใช้งานระบบได้! <a href="${logoutURL}">- Logout from One ID -</a>`,
      bodyClass: middlewareHelpers.buildBodyClass(req, res),
    });
  });
};

OneIDAuth.addApiRoutes = async ({ router, middleware, helpers: apiHelpers }) => {
  winston.verbose('[sso-oneid] Add API route');
  const middlewares = [middleware.ensureLoggedIn];

  routeHelpers.setupApiRoute(router, 'get', '/oneid/avatar/:accountID', middlewares, async (req, res) => {
    if (!OneIDAuth.intranetEnabled || !OneIDAuth.intranet.baseURL) {
      return apiHelpers.formatApiResponse(502, res, 'Intranet not connected');
    }

    // Must be digits only: the value is placed into the intranet URL, and Express
    // has already decoded %2F, so anything looser allows path traversal there.
    const { accountID } = req.params;
    if (!helpers.isAccountID(accountID)) {
      return apiHelpers.formatApiResponse(400, res, 'Invalid account id');
    }

    try {
      const avatarURL = `${OneIDAuth.intranet.baseURL.replace(/\/+$/, '')}/account/${encodeURIComponent(accountID)}/avatar`;
      const response = await fetch(avatarURL, {
        method: 'GET',
        signal: AbortSignal.timeout(3000),
        headers: { Authorization: `Bearer ${OneIDAuth.intranet.apiKey}` },
      });

      if (response.status !== 200) {
        winston.warn(`[sso-oneid] Avatar server returned HTTP ${response.status}`);
        return apiHelpers.formatApiResponse(502, res, 'Avatar server returned an error');
      }
      if (Number(response.headers.get('content-length')) > AVATAR_MAX_BYTES) {
        return apiHelpers.formatApiResponse(502, res, 'Avatar too large');
      }

      const body = Buffer.from(await response.arrayBuffer());
      if (body.length > AVATAR_MAX_BYTES) {
        return apiHelpers.formatApiResponse(502, res, 'Avatar too large');
      }

      const sharp = require.main.require('sharp');
      const image = sharp(body);
      const { width, height } = await image.metadata();
      const size = Math.min(width, height);
      const { data, info } = await image
        .extract({
          left: Math.floor((width - size) / 2),
          top: Math.floor((height - size) / 2),
          width: size,
          height: size,
        })
        .toBuffer({ resolveWithObject: true });

      res.set({
        'Content-Type': `image/${info.format}`,
        'Cache-Control': 'private, max-age=3600',
        'X-Content-Type-Options': 'nosniff',
      });
      return res.status(200).end(data);
    } catch (e) {
      winston.error(`[sso-oneid] Fetch user avatar error: ${e.message}`);
      return apiHelpers.formatApiResponse(503, res, 'External intranet avatar error');
    }
  });
};

OneIDAuth.clearSession = async function (req, res) {
  if (req.loggedIn && req.sessionID) {
    res.clearCookie(nconf.get('sessionKey'), meta.configs.cookie.get());

    const { uid, sessionID } = req;

    await User.auth.revokeSession(sessionID, uid);
    await new Promise((resolve, reject) => req.logout(err => (err ? reject(err) : resolve())));
    await new Promise((resolve, reject) => req.session.destroy(err => (err ? reject(err) : resolve())));

    await User.setUserField(uid, 'lastonline', Date.now() - meta.config.onlineCutoff * 60000);
    await db.sortedSetAdd('users:online', Date.now() - meta.config.onlineCutoff * 60000, uid);

    sockets.in(`sess_${sessionID}`).emit('checkSession', 0);
  }
};

/** Reload the business allowlist and the block list from the ACP settings. */
OneIDAuth.reloadAuthorization = async function (settings) {
  if (!settings) {
    settings = (await meta.settings.get(constants.settingsKey)) || {};
  }
  OneIDAuth.businessCheck = helpers.toIdList((settings.businessList || []).map(b => b && b.id));
  OneIDAuth.blockAccounts = helpers.toIdList((settings.denyAccountList || []).map(b => b && b.account_id));
};

OneIDAuth.userLogout = async function (payload) {
  payload.next = helpers.oneIDLogoutURL(OneIDAuth.baseURL, nconf.get('url'));
  return payload;
};

OneIDAuth.addMenuItem = function (custom_header, callback) {
  custom_header.authentication.push({
    route: constants.admin.route,
    icon: constants.admin.icon,
    name: 'One ID',
  });
  callback(null, custom_header);
};

/** Passport verify callback: access checks, account lookup or creation, ban handling. */
OneIDAuth.verify = async function (req, accessToken, refreshToken, params, profile, done) {
  let uid;
  let restrictOnDeny = false;
  try {
    profile.username = params && params.username;
    await OneIDAuth.reloadAuthorization();

    if (helpers.isBlocked(OneIDAuth.blockAccounts, profile.id)) {
      winston.warn(`[sso-oneid] Blocked by account block list: ${profile.id}`);
      throw forbiddenError();
    }

    const access = helpers.businessAccess(OneIDAuth.businessCheck, profile.associateBiz);
    if (access === 'unknown') {
      // Fail closed, but do not mark the user as restricted for an outage.
      winston.warn(`[sso-oneid] Business membership unknown for account ${profile.id}, denying login`);
      throw forbiddenError();
    }
    if (access === 'deny') {
      winston.warn(`[sso-oneid] Account ${profile.id} is not associated with any configured business`);
      uid = await OneIDAuth.getUidByOneID(profile.id);
      restrictOnDeny = true;
      throw forbiddenError();
    }

    ({ uid } = await OneIDAuth.login(profile));

    const status = await OneIDAuth.isRestrictedUser(uid);
    if (status.banned) {
      if (status.reason !== 'forbidden') {
        // Banned by an administrator: keep the ban.
        throw forbiddenError();
      }
      // Restricted earlier by this plugin and now allowed again.
      await OneIDAuth.allowUser(uid);
    }

    if (req.session && req.session.registration) {
      delete req.session.registration;
    }
    await authenticationController.onSuccessfulLogin(req, uid);
    winston.verbose(`[sso-oneid] Successful login uid ${uid}`);
    return done(null, { uid });
  } catch (err) {
    if (err && err.message === 'forbidden') {
      try {
        if (restrictOnDeny && uid) {
          const status = await OneIDAuth.isRestrictedUser(uid);
          if (!status.banned) await OneIDAuth.restrictedUser(uid, 'forbidden');
        }
        await OneIDAuth.clearSession(req, req.res);
      } catch (e) {
        winston.error(`[sso-oneid] Restrict user error: ${e.message}`);
      }
      err.code = 'forbidden';
      return done(err);
    }
    winston.error(`[sso-oneid] Passport authenticate error: ${err && err.message}`);
    return done(err);
  }
};

OneIDAuth.buildStrategy = async function (strategies) {
  winston.verbose('[sso-oneid] SSO get strategy');
  const settings = (await meta.settings.get(constants.settingsKey)) || {};
  // ACP values take precedence over the environment variables.
  const clientID = settings.id || process.env.SSO_ONEID_CLIENT_ID;
  const clientSecret = settings.secret || process.env.SSO_ONEID_CLIENT_SECRET;
  if (!clientID || !clientSecret) {
    return strategies;
  }

  OneIDAuth.baseURL = helpers.normalizeBaseURL(settings.server);
  OneIDAuth.intranetEnabled = Boolean(settings.intranetSyncEnabled) && !['false', 'off', '0'].includes(String(settings.intranetSyncEnabled));
  OneIDAuth.intranet = {
    baseURL: settings.intranetApiServer || '',
    apiKey: settings.intranetApiKey || '',
  };
  await OneIDAuth.reloadAuthorization(settings);

  const strategy = new OneIDStrategy(
    {
      clientID,
      clientSecret,
      refCode: settings.refcode || settings.refCode || '',
      authorizationURL: `${OneIDAuth.baseURL}${OneIDAuth.authorizationURL}`,
      tokenURL: `${OneIDAuth.baseURL}${OneIDAuth.tokenURL}`,
      profileURL: `${OneIDAuth.baseURL}${OneIDAuth.profileURL}`,
      businessURL: `${OneIDAuth.baseURL}${OneIDAuth.businessURL}`,
      sharedTokenURL: `${OneIDAuth.baseURL}${OneIDAuth.sharedTokenURL}`,
      callbackURL: `${nconf.get('url')}/auth/${constants.name}/callback`,
      passReqToCallback: true,
    },
    OneIDAuth.verify
  );
  passport.use(constants.name, strategy);

  strategies.push({
    name: constants.name,
    url: `/auth/${constants.name}`,
    // NodeBB's own state check would reject the shared-token hand-off on the
    // callback route; OneIDStrategy checks `state` itself instead.
    checkState: false,
    callbackURL: `/auth/${constants.name}/callback`,
    scope: ['identify', 'email'],
    icons: {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" height="16px" viewBox="0 0 208 192" class="LgbsSe-Bz112c"><image xlink:href="${nconf.get('url')}/plugins/nodebb-plugin-sso-oneid/images/sso-oneid.svg" x="0" y="0" width="208" height="192" /></svg>`,
    },
    labels: {
      login: 'Sign in with One ID',
      register: 'Sign up with One ID',
    },
  });
  return strategies;
};

OneIDAuth.getStrategy = function (strategies, callback) {
  OneIDAuth.buildStrategy(strategies).then(
    result => callback(null, result),
    err => {
      winston.error(`[sso-oneid] Could not set up the OneID strategy: ${err.message}`);
      callback(err);
    }
  );
};

OneIDAuth.getAssociation = function (data, callback) {
  User.getUserField(data.uid, 'oneid', (err, accountID) => {
    if (err) {
      return callback(err, data);
    }

    if (!data.associations) data.associations = [];
    if (accountID) {
      data.associations.push({
        associated: true,
        url: `${OneIDAuth.baseURL}/portal_index`,
        name: constants.name,
        icon: constants.admin.icon,
      });
    }

    callback(null, data);
  });
};

/** Find or create the NodeBB user for a OneID profile and link the two. */
OneIDAuth.login = async function (profile) {
  let uid = await OneIDAuth.getUidByOneID(profile.id);

  if (!uid) {
    const username = helpers.getUsernameFromEmail(profile.email) || profile.username;
    if (!username) {
      throw new Error('[[error:invalid-username]]');
    }
    const pictureURL = `${nconf.get('url')}/api/v3/plugins/oneid/avatar/${encodeURIComponent(profile.id)}`;

    winston.verbose(`[sso-oneid] Create new user for account ${profile.id}`);
    uid = await User.create({
      username,
      fullname: profile.displayName,
      birthday: profile.birthday,
      oneid_name: profile.displayName,
      uploadedpicture: pictureURL,
      picture: pictureURL,
    });

    // Link straight away, so a failure further down can never create a second
    // account on the next login attempt.
    await OneIDAuth.link(uid, profile.id);

    if (OneIDAuth.intranetEnabled) {
      await User.setUserField(uid, 'intranet_avatar', pictureURL);
    }
    await OneIDAuth.assignEmail(uid, profile.email);
  } else {
    await User.setUserFields(uid, { oneid_name: profile.displayName, account_id: profile.id });
  }

  await OneIDAuth.link(uid, profile.id);
  return { uid };
};

OneIDAuth.link = async function (uid, accountID) {
  await User.setUserField(uid, 'oneid', accountID);
  await db.setObjectField('oneid:uid', accountID, uid);
};

/** Set the OneID e-mail as the user's confirmed e-mail, unless another account already owns it. */
OneIDAuth.assignEmail = async function (uid, email) {
  if (!email) return;
  try {
    if (!(await User.email.available(email))) {
      winston.warn(`[sso-oneid] E-mail of uid ${uid} is already used by another account; not assigned`);
      return;
    }
    await User.setUserField(uid, 'email', email);
    await User.email.confirmByUid(uid);
  } catch (err) {
    winston.warn(`[sso-oneid] Could not confirm e-mail for uid ${uid}: ${err.message}`);
  }
};

OneIDAuth.getUidByOneID = async function (accountID) {
  return await db.getObjectField('oneid:uid', accountID);
};

OneIDAuth.deleteUserData = async function (data) {
  const accountID = await User.getUserField(data.uid, 'oneid');
  if (accountID) {
    await db.deleteObjectField('oneid:uid', accountID);
  }
};

// Without this, deleteUserData cannot read the `oneid` field.
OneIDAuth.appendUserHashWhitelist = function (data, callback) {
  data.whitelist.push('oneid');
  setImmediate(callback, null, data);
};

OneIDAuth.handleErrors = function (data, next) {
  data.cases.forbidden = async function (err, req, res) {
    return res.redirect(forbiddenRedirectURL());
  };
  return next(null, data);
};

OneIDAuth.restrictedUser = async function (uid, reason) {
  winston.warn(`[sso-oneid] Set restricted to user: ${uid}`);
  // Leave all other system groups so privileges are constrained to "banned-users"
  const systemGroups = Groups.systemGroups.filter(group => group !== Groups.BANNED_USERS);
  await Groups.leave(systemGroups, uid);
  await Groups.join(Groups.BANNED_USERS, uid);

  await User.setUserFields(uid, { banned: 1, reason });
};

OneIDAuth.allowUser = async function (uid) {
  winston.warn(`[sso-oneid] Reset restricted to user: ${uid}`);
  await db.setObject(`user:${uid}`, { banned: 0, reason: 'accepted' });
  await Promise.all([Groups.leave(Groups.BANNED_USERS, uid), Groups.join(['registered-users'], uid)]);
};

OneIDAuth.isRestrictedUser = async function (uid) {
  const banned = await User.getUsersFields([uid], ['banned', 'reason']);
  if (Array.isArray(banned) && banned.length === 1) return { banned: banned[0].banned, reason: banned[0].reason };
  return { banned: false };
};

// Exposed for tests.
OneIDAuth._OneIDStrategy = OneIDStrategy;

module.exports = OneIDAuth;
