'use strict';

const User = require.main.require('./src/user');
const Groups = require.main.require('./src/groups');
const meta = require.main.require('./src/meta');
const db = require.main.require('./src/database');
const middlewareHelpers = require.main.require('./src/middleware/helpers');
const sockets = require.main.require('./src/socket.io');
const authenticationController = require.main.require('./src/controllers/authentication');
const nconf = require.main.require('nconf');
const async = require.main.require('async');
const winston = require.main.require('winston');
const passport = require.main.require('passport');
const url = require.main.require('url');

const utils = require('./static/lib/utils');
const util = require.main.require('util');
const { InternalOAuthError } = require('passport-oauth2');
const querystring = require('querystring');

const constants = Object.freeze({
  name: 'oneid',
  admin: {
    route: '/plugins/sso-oneid',
    icon: 'fa-cogs',
  },
  oauth2: {
    callbackURL: '',
    authorizationURL: '',
    tokenURL: '',
    clientID: '',
    clientSecret: '',
    refCode: '',
    profileURL: '',
    sharedTokenURL: '',
    passReqToCallback: true,
  },
});

const OneIDAuth = {
  baseURL: 'https://one.th',
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

const destroyAsync = util.promisify((req, callback) => req.session.destroy(callback));
const logoutAsync = util.promisify((req, callback) => req.logout(callback));

OneIDAuth.init = function (data, callback) {
  winston.verbose('[sso-oneid] Init sso configuration');
  const hostHelpers = require.main.require('./src/routes/helpers');
  hostHelpers.setupAdminPageRoute(data.router, '/admin/plugins/sso-oneid', (req, res) => {
    res.render('admin/plugins/sso-oneid', {
      title: 'One ID',
      baseUrl: nconf.get('url'),
    });
  });

  hostHelpers.setupPageRoute(data.router, '/error/forbidden', [], async (req, res) => {
    if (req.loggedIn) res.redirect('/');
    const err = new Error();
    err.code = 'forbidden';
    err.message = `ขออภัย! บัญชีของคุณ <strong>ไม่อนุญาต</strong> ให้เข้าใช้งานระบบได้! <a href="${OneIDAuth.baseURL}/api/oauth/logout?redirect_url=${nconf.get('url')}/login">- Logout from One ID -</a>`;

    const _data = {
      error: String(err.message),
      bodyClass: middlewareHelpers.buildBodyClass(req, res),
    };

    req.uid = 999;
    res.render('403', _data);
  });

  callback();
};

OneIDAuth.clearSession = async function (req, res) {
  if (req.loggedIn && req.sessionID) {
    res.clearCookie(nconf.get('sessionKey'), meta.configs.cookie.get());

    const { uid } = req;
    const { sessionID } = req;

    await User.auth.revokeSession(sessionID, uid);
    await logoutAsync(req);
    await destroyAsync(req);

    await User.setUserField(uid, 'lastonline', Date.now() - meta.config.onlineCutoff * 60000);
    await db.sortedSetAdd('users:online', Date.now() - meta.config.onlineCutoff * 60000, uid);

    sockets.in(`sess_${sessionID}`).emit('checkSession', 0);
  }
};

OneIDAuth.reloadAuthorization = function (_settings, _callback) {
  winston.verbose(`[sso-oneid] Reload authorization function`);
  async.waterfall(
    [
      function (callback) {
        if (_settings) return callback(null, _settings);

        winston.verbose(`[sso-oneid] Load settings configuration`);
        meta.settings.get('sso-oneid', function (err, settings) {
          if (err) return callback(err);
          callback(null, settings);
        });
      },
    ],
    function (err, settings) {
      if (err) {
        winston.error(`[sso-oneid] Load authorization configure error`, err);
        return;
      }

      winston.verbose(`[sso-oneid] Setting variables to new value`);
      // Reset business check
      OneIDAuth.businessCheck = [];
      if (settings.businessList) {
        for (const b of settings.businessList) {
          OneIDAuth.businessCheck.push(b.id);
        }
      }

      // Read block account
      OneIDAuth.blockAccounts = [];
      if (settings.denyAccountList) {
        for (const b of settings.denyAccountList) {
          OneIDAuth.blockAccounts.push(b.account_id);
        }
      }

      if (_callback instanceof Function) _callback();
    }
  );
};

OneIDAuth.userLoggedOut = async ({ req, res, uid, sessionID }) => {
  winston.verbose('[sso-oneid] User logged out called');

  sockets.in(`sess_${sessionID}`).emit('checkSession', 0);
  const redirectURL = `${OneIDAuth.baseURL}/api/oauth/logout?redirect_url=${nconf.get('url')}`;
  const payload = {
    next: redirectURL,
  };

  if (req.body.noscript === 'true') {
    return res.redirect(payload.next);
  }
  res.status(200).send(payload);
};

OneIDAuth.addMenuItem = function (custom_header, callback) {
  custom_header.authentication.push({
    route: constants.admin.route,
    icon: constants.admin.icon,
    name: 'One ID',
  });
  callback(null, custom_header);
};

OneIDAuth.getStrategy = function (strategies, callback) {
  winston.verbose('[sso-oneid] SSO get strategy');
  const opts = constants.oauth2;
  opts.callbackURL = `${nconf.get('url')}/auth/${constants.name}/callback`;

  winston.verbose('[sso-oneid] Load setting');
  meta.settings.get('sso-oneid', function (err, settings) {
    if (err) return callback(err);
    if (!settings.id || !settings.secret) {
      return callback(null, strategies);
    }

    opts.clientID = settings.id;
    opts.clientSecret = settings.secret;
    opts.refCode = settings.refCode;
    opts.authorizationURL = `${OneIDAuth.baseURL}${OneIDAuth.authorizationURL}`;
    opts.tokenURL = `${OneIDAuth.baseURL}${OneIDAuth.tokenURL}`;
    opts.profileURL = `${OneIDAuth.baseURL}${OneIDAuth.profileURL}`;
    opts.businessURL = `${OneIDAuth.baseURL}${OneIDAuth.businessURL}`;
    opts.sharedTokenURL = `${OneIDAuth.baseURL}${OneIDAuth.sharedTokenURL}`;
    if (settings.url) options.callbackURL = settings.url + '/auth/' + constants.name.toLowerCase() + '/callback';

    // Load sso-oneid config
    OneIDAuth.intranetEnabled = settings.intranetEnabled;
    OneIDAuth.intranet = {
      baseURL: settings.intranetApiServer,
      apiKey: settings.intranetApiKey,
    };

    OneIDAuth.reloadAuthorization(settings);

    const PassportOAuth = require('passport-oauth2');
    PassportOAuth.Strategy.prototype.authenticate = OneIDAuth.authenticate;

    PassportOAuth.Strategy.prototype.userProfile = async function (accessToken, done) {
      this._oauth2._useAuthorizationHeaderForGET = true;
      const _self = this;

      async.parallel(
        {
          _profile: function (callback) {
            _self._oauth2.get(opts.profileURL, accessToken, function (err, body, res) {
              winston.verbose('[sso-oneid] Fetch user profile');
              if (err) return done(new InternalOAuthError('failed to fetch user profile', err));
              try {
                const oauth2User = JSON.parse(body).data;
                const user = {
                  id: oauth2User.id,
                  email: oauth2User.thai_email,
                  displayName: `${oauth2User.account_title_th}${oauth2User.first_name_th} ${oauth2User.last_name_th}`,
                  provider: constants.name,
                  birthday: oauth2User.birth_date,
                };
                if (oauth2User.account_category != 'Residential') {
                  user.displayName = `${oauth2User.account_title_eng} ${oauth2User.first_name_eng} ${oauth2User.last_name_eng}`;
                }
                callback(null, user);
              } catch (e) {
                callback(e);
              }
            });
          },
          _biz: function (callback) {
            _self._oauth2.get(opts.businessURL, accessToken, function (err, body, res) {
              winston.verbose('[sso-oneid] Fetch user business associate');
              if (err) return done(new InternalOAuthError('failed to fetch user associate business', err));
              try {
                const biz = [];
                const userBiz = JSON.parse(body).data;
                for (const b of userBiz) {
                  biz.push(b.id);
                }
                callback(null, biz);
              } catch (e) {
                callback(e);
              }
            });
          },
        },
        function (err, result) {
          if (err) return done(new InternalOAuthError('failed to fetch user profile', err));
          const user = result._profile;
          user.associateBiz = result._biz;
          return done(null, user);
        }
      );
    }; // end prototype

    const authenticator = new PassportOAuth(opts, function (req, accessToken, refreshToken, params, profile, done) {
      winston.verbose(`[sso-oneid] Passport authenticator called`);
      profile.username = params.username;
      // Get uid
      async.waterfall(
        [
          function (callback) {
            OneIDAuth.reloadAuthorization(null, function () {
              callback(null);
            });
          },
          // Block account
          function (callback) {
            OneIDAuth.denyUser(profile, function (err) {
              callback(err);
            });
          },
          // Check associate biz
          function (callback) {
            OneIDAuth.checkAssociateBusiness(profile, function (err) {
              if (!err) return callback(null);

              OneIDAuth.getUidByOneID(profile.id, function (_, uid) {
                callback(err, { uid: uid });
              });
            });
          },
          // Login
          function (callback) {
            OneIDAuth.login(profile, function (err, user) {
              if (err) return callback(err);
              callback(null, user);
            });
          },
        ],
        async function (err, user) {
          if (user && user.uid) {
            user.banned = await OneIDAuth.isRestrictedUser(user.uid);
            winston.verbose(`[sso-oneid] Get restricted user: ${user.uid} Banned status: ${JSON.stringify(user.banned)}`);
          }

          if (!err && user.banned) {
            if (user.banned.banned && user.banned.reason === 'forbidden') {
              // Reset
              OneIDAuth.allowUser(user.uid);
              user.banned.banned = false;
              user.banned.reason = null;
              winston.verbose(`[sso-oneid] Reset restricted user: ${user.uid}`);
            } else if (user.banned.banned) {
              err = new Error('forbidden');
            }

            winston.verbose(`[sso-oneid] Prepare user restricted: ${JSON.stringify(user)}`);
            // final check banned
            if (!user.banned.banned) {
              // normal user
              winston.verbose(`[sso-oneid] Successful logged in: ${JSON.stringify(user)}`);
              if (req.session.hasOwnProperty('registration')) {
                delete req.session.registration;
              }
              authenticationController.onSuccessfulLogin(req, user.uid);
              return done(null, { uid: user.uid });
            }
          }

          if (err instanceof Error && err.message === 'forbidden') {
            if (user && user.banned && !user.banned.banned) OneIDAuth.restrictedUser(user.uid, `${err.message}`);
            err.code = 'forbidden';
            OneIDAuth.clearSession(req, req.res);
            return done(err);
          }
          winston.error(`[sso-oneid] Passport authenticate error: ${err}`);
          done(err);
        }
      );
    });

    winston.verbose('[sso-oneid] Set custom oauth2 getOAuthAccessToken');
    authenticator._oauth2.getOAuthAccessToken = OneIDAuth.getOAuthAccessToken;
    authenticator._oauth2._refCode = `${opts.refCode}`;
    authenticator._oauth2._sharedTokenURL = `${opts.sharedTokenURL}`;

    passport.use(constants.name, authenticator);

    winston.verbose('[sso-oneid] Push sso-oneid to authentication strategies');
    strategies.push({
      name: constants.name,
      url: `/auth/${constants.name}`,
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

    callback(null, strategies);
  });
};

OneIDAuth.getAssociation = function (data, callback) {
  winston.verbose('[sso-oneid] Get account associate to social auth');
  User.getUserField(data.uid, 'oneid', (err, accountID) => {
    if (err) {
      return callback(err, data);
    }

    if (accountID) {
      data.associations.push({
        associated: true,
        url: 'https://one.th/portal_index',
        name: constants.name,
        icon: constants.admin.icon,
      });
    }

    callback(null, data);
  });
};

// reject oneid user
OneIDAuth.denyUser = function (profile, callback) {
  winston.verbose(`[sso-oneid] Check black list user: ${profile.id} - ${profile.username}`);
  const setBlockAccounts = new Set(OneIDAuth.blockAccounts);
  if (setBlockAccounts.has(profile.id)) {
    winston.warn(`[sso-oneid] Block by account blacklist user: ${profile.id} - ${profile.username}`);
    return callback(new Error('forbidden'));
  }
  callback(null);
};

OneIDAuth.checkAssociateBusiness = function (profile, callback) {
  winston.verbose('[sso-oneid] Check account associate to configured business');
  // nothing to do
  if (OneIDAuth.businessCheck.length == 0) {
    winston.verbose('[sso-oneid] No business list configure');
    return callback(null);
  }

  // id not associate to any biz
  if (!profile.associateBiz || (profile.associateBiz && profile.associateBiz.length == 0)) {
    winston.warn(`[sso-oneid] Reject account ${profile.id} - ${profile.username} was no associate to any business`);
    return callback(new Error('forbidden'));
  }
  const setBusinessCheck = new Set(OneIDAuth.businessCheck);
  for (const b of profile.associateBiz) {
    if (setBusinessCheck.has(b)) {
      // existed
      return callback(null);
    }
  }
  winston.warn(`[sso-oneid] Reject account ${profile.id} - ${profile.username} was no associate to configured business list`);
  callback(new Error('forbidden'));
};

OneIDAuth.login = function (profile, callback) {
  winston.verbose(`[sso-oneid] Log in account: ${profile.id} - ${profile.username}`);

  // Success login
  const success = async uid => {
    // Auto confirm email
    await User.setUserField(uid, 'email', profile.email);
    await User.email.confirmByUid(uid);

    await User.setUserField(uid, 'oneid', profile.id);
    await db.setObjectField('oneid:uid', profile.id, uid);

    const systemGroupsToJoin = ['registered-users'];
    await Groups.join(systemGroupsToJoin, uid);

    callback(null, {
      uid: uid,
    });
  };

  OneIDAuth.getUidByOneID(profile.id, function (err, uid) {
    if (err) callback(err);
    if (!uid) {
      // New user
      const username = OneIDAuth.getUsernameFromEmail(profile.email);
      if (!username) {
        username = profile.username;
      }
      winston.verbose(`[sso-oneid] Create new user: ${username}`);
      User.create(
        {
          username: username,
          email: undefined, // auto confirm
          userslug: username,
          fullname: profile.displayName,
          birthday: profile.birthday,
          oneid_name: profile.displayName,
        },
        (err, uid) => {
          if (err) return callback(err);
          winston.verbose('[sso-oneid] Created user success');
          success(uid);
        }
      );
    } else {
      // Existed user
      // update user infomation
      User.setUserField(uid, 'oneid_name', profile.displayName);
      success(uid);
    }
  });
};

OneIDAuth.getUidByOneID = function (accountID, callback) {
  winston.verbose(`[sso-oneid] Get Uid by One ID: ${accountID}`);

  db.getObjectField('oneid:uid', accountID, function (err, uid) {
    if (err) return callback(err);

    if (uid) winston.verbose(`[sso-oneid] Found account uid: ${uid}`);
    callback(null, uid);
  });
};

OneIDAuth.deleteUserData = function (data, callback) {
  winston.verbose(`[sso-oneid] Delete user: ${JSON.stringify(data)}`);
  async.waterfall(
    [
      async.apply(User.getUserField, data.uid, `oneid`),
      function (oAuthIdToDelete, next) {
        winston.verbose(`[sso-oneid] Delete account id: ${oAuthIdToDelete}`);
        db.deleteObjectField(`oneid:uid`, oAuthIdToDelete, next);
      },
    ],
    err => {
      if (err) {
        winston.error(`[sso-oneid] Could not remove OAuthId data for uid ${data.uid}. Error: ${JSON.stringify(err)}`);
        return callback(err);
      }

      callback(null, data);
    }
  );
};

// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
OneIDAuth.appendUserHashWhitelist = function (data, callback) {
  data.whitelist.push('oneid');
  setImmediate(callback, null, data);
};

OneIDAuth.getUsernameFromEmail = function (email) {
  if (!email) {
    return null;
  }

  const atIndex = email.indexOf('@');
  if (atIndex === -1) {
    return null;
  }

  return email.substring(0, atIndex);
};

OneIDAuth.handleErrors = function (data, next) {
  data.cases['forbidden'] = async function (err, req, res, _next) {
    return req.res.redirect(`${OneIDAuth.baseURL}/api/oauth/logout?redirect_url=${nconf.get('url')}/error/forbidden`);
  };
  return next(null, data);
};

OneIDAuth.restrictedUser = async function (uid, reason) {
  winston.warn(`[sso-oneid] Set restricted to user: ${uid}`);
  // Leaving all other system groups to have privileges constrained to the "banned-users" group
  const systemGroups = Groups.systemGroups.filter(group => group !== Groups.BANNED_USERS);
  await Groups.leave(systemGroups, uid);
  await Groups.join(Groups.BANNED_USERS, uid);

  await User.setUserFields(uid, { banned: 1, reason });
};

OneIDAuth.allowUser = async function (uid) {
  winston.warn(`[sso-oneid] Reset restricted to user: ${uid}`);

  await db.setObject(`user:${uid}`, { banned: 0, reason: 'accepted' });

  await Groups.leave(Groups.BANNED_USERS, uid);
  const systemGroupsToJoin = ['registered-users'];
  await Promise.all([Groups.leave(Groups.BANNED_USERS, uid), Groups.join(systemGroupsToJoin, uid)]);
};

OneIDAuth.isRestrictedUser = async function (uid) {
  const banned = await User.getUsersFields([uid], ['banned', 'reason']);
  if (Array.isArray(banned) && banned.length == 1) return { banned: banned[0].banned, reason: banned[0].reason };
  return { banned: false };
};

OneIDAuth.getOAuthAccessToken = function (code, params, callback) {
  winston.verbose('[sso-onied] Custom getOAuthAccessToken was called');
  var params = params || {};
  params['client_id'] = this._clientId;
  params['client_secret'] = this._clientSecret;
  var tokenUrl = this._baseSite + this._accessTokenUrl;
  var post_headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  var post_data;

  if (params.hasOwnProperty('shared_token')) {
    tokenUrl = this._baseSite + this._sharedTokenURL;
    params['refcode'] = this._refCode;
    post_headers = {
      'Content-Type': 'application/json',
    };
    post_data = JSON.stringify(params);
  } else {
    var codeParam = params.grant_type === 'refresh_token' ? 'refresh_token' : 'code';
    params[codeParam] = code;
    post_data = querystring.stringify(params);
  }

  this._request('POST', tokenUrl, post_headers, post_data, null, function (error, data, response) {
    if (error) callback(error);
    else {
      var results;
      try {
        results = JSON.parse(data);
      } catch (e) {
        results = querystring.parse(data);
      }
      var access_token = results['access_token'];
      var refresh_token = results['refresh_token'];
      delete results['refresh_token'];
      callback(null, access_token, refresh_token, results);
    }
  });
};

// Custom oneid authenticate
OneIDAuth.authenticate = function (req, options) {
  winston.verbose('[sso-onied] Custom authenticate was called');
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }

  const getOAuthAccessToken = function (code, params) {
    self._oauth2.getOAuthAccessToken(code, params, function (err, accessToken, refreshToken, params) {
      if (err) {
        if (err.hasOwnProperty('statusCode') && err.statusCode >= 400) {
          if (req.session.hasOwnProperty('registration')) {
            delete req.session.registration;
          }
          OneIDAuth.clearSession(req, req.res);
          return req.res.redirect(`${OneIDAuth.baseURL}/api/oauth/logout?redirect_url=${nconf.get('url')}/error/forbidden`);
        }
        return self.error(self._createOAuthError('Failed to obtain access token', err));
      }
      if (!accessToken) {
        return self.error(new Error('Failed to obtain access token'));
      }

      self._loadUserProfile(accessToken, function (err, profile) {
        if (err) {
          return self.error(err);
        }

        function verified(err, user, info) {
          if (err) {
            return self.error(err);
          }
          if (!user) {
            return self.fail(info);
          }

          info = info || {};
          self.success(user, info);
        }

        try {
          if (self._passReqToCallback) {
            var arity = self._verify.length;
            if (arity == 6) {
              self._verify(req, accessToken, refreshToken, params, profile, verified);
            } else {
              // arity == 5
              self._verify(req, accessToken, refreshToken, profile, verified);
            }
          } else {
            var arity = self._verify.length;
            if (arity == 5) {
              self._verify(accessToken, refreshToken, params, profile, verified);
            } else {
              // arity == 4
              self._verify(accessToken, refreshToken, profile, verified);
            }
          }
        } catch (ex) {
          return self.error(ex);
        }
      });
    });
  };

  if ((req.query && req.query.code) || (req.body && req.body.code)) {
    var code = (req.query && req.query.code) || (req.body && req.body.code);

    var params = self.tokenParams(options);
    params.grant_type = 'authorization_code';
    if (callbackURL) {
      params.redirect_uri = callbackURL;
    }
    getOAuthAccessToken(code, params);
  } else if ((req.query && req.query.sharedtoken) || (req.body && req.body.sharedtoken)) {
    const params = {
      shared_token: req.query.sharedtoken,
    };

    getOAuthAccessToken(null, params);
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    if (callbackURL) {
      params.redirect_uri = callbackURL;
    }

    var parsed = url.parse(self._oauth2._authorizeUrl, true);
    utils.merge(parsed.query, params);
    parsed.query['client_id'] = self._oauth2._clientId;
    delete parsed.search;

    var location = url.format(parsed);
    self.redirect(location);
  }
};

module.exports = OneIDAuth;
