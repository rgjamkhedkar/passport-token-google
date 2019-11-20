/**
 * Module dependencies.
 */
import util from "util";
import * as passport from "passport";
import PassportOauth, { StrategyOptionsWithRequest } from "passport-oauth2";

const OAuth2Strategy = PassportOauth.Strategy;

export interface Profile extends passport.Profile {
  profileUrl: string;

  _raw: string;
  _json: any;
}

/**
 * `Strategy` constructor.
 *
 * The Google authentication strategy authenticates requests by delegating to
 * Google using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Google application's client id
 *   - `clientSecret`  your Google application's client secret
 *   - `callbackURL`   URL to which Google will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new GoogleStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/google/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function GoogleTokenStrategy(
  this: any,
  options: StrategyOptionsWithRequest,
  verify: any
) {
  options = options || {};
  options.authorizationURL =
    options.authorizationURL || "https://accounts.google.com/o/oauth2/auth";
  options.tokenURL =
    options.tokenURL || "https://accounts.google.com/o/oauth2/token";

  OAuth2Strategy.call(this, options, verify);
  this.name = "google-token";
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(GoogleTokenStrategy, OAuth2Strategy);

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
GoogleTokenStrategy.prototype.authenticate = function(req: any, options: any) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }

  var accessToken = req.body
    ? req.body.access_token ||
      req.query.access_token ||
      req.headers.access_token
    : req.headers.access_token || req.query.access_token;
  var refreshToken = req.body
    ? req.body.refresh_token ||
      req.query.refresh_token ||
      req.headers.refresh_token
    : req.headers.refresh_token || req.query.refresh_token;

  self._loadUserProfile(accessToken, function(err: any, profile: Profile) {
    if (err) {
      return self.fail(err);
    }

    function verified(err: any, user: any, info: any) {
      if (err) {
        return self.error(err);
      }
      if (!user) {
        return self.fail(info);
      }
      self.success(user, info);
    }

    if (self._passReqToCallback) {
      self._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      self._verify(accessToken, refreshToken, profile, verified);
    }
  });
};

/**
 * Retrieve user profile from Google.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `google`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
GoogleTokenStrategy.prototype.userProfile = function(
  accessToken: string,
  done: (err: any, profile?: Profile) => void
) {
  var profileUrl =
    "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" + accessToken;
  this._oauth2.get(profileUrl, null, function(err: any, body: any, res: any) {
    if (err) {
      return done(
        new PassportOauth.InternalOAuthError(
          "failed to fetch user profile",
          err
        )
      );
    }

    try {
      var json = JSON.parse(body);

      var profile: Profile = {
        profileUrl: profileUrl,
        provider: "google",
        id: json.id || json.sub,
        displayName: json.name,
        name: {
          familyName: json.family_name,
          givenName: json.given_name
        },
        emails: [{ value: json.email }],
        _raw: body,
        _json: json
      };

      done(null, profile);
    } catch (e) {
      done(e);
    }
  });
};

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
GoogleTokenStrategy.prototype._loadUserProfile = function(
  accessToken: string,
  done: (err: any) => void
) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, done);
  }
  function skipIt() {
    return done(null);
  }

  if (
    typeof this._skipUserProfile == "function" &&
    this._skipUserProfile.length > 1
  ) {
    // async
    this._skipUserProfile(accessToken, function(err: any, skip: any) {
      if (err) {
        return done(err);
      }
      if (!skip) {
        return loadIt();
      }
      return skipIt();
    });
  } else {
    var skip =
      typeof this._skipUserProfile == "function"
        ? this._skipUserProfile()
        : this._skipUserProfile;
    if (!skip) {
      return loadIt();
    }
    return skipIt();
  }
};

/**
 * Expose `GoogleTokenStrategy`.
 */
export default GoogleTokenStrategy;
