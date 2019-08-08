var passport = require('passport-strategy');
var util = require('util');
var saml = require('./saml');

function Strategy (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('SAML authentication strategy requires a verify function');
  }

  // Customizing the name can be useful to support multiple SAML configurations at the same time.
  // Unlike other options, this one gets deleted instead of passed along.
  if  (options.name) {
    this.name  = options.name;
    delete options.name;
  }
  else {
    this.name = 'saml';
  }

  passport.Strategy.call(this);

  this._verify = verify;
  this._saml = new saml.SAML(options);
  this._passReqToCallback = !!options.passReqToCallback;
  this._authnRequestBinding = options.authnRequestBinding || 'HTTP-Redirect';
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  var self = this;

  options.samlFallback = options.samlFallback || 'login-request';

  function validateCallback(err, profile, loggedOut) {
      if (err) {
        self.error(err);

        return;
      }

      if (loggedOut) {
        console.log('***********');
        req.logout(req, function (err) {
          if (err) {
            self.error(err);

            return;
          }

          if (profile) {
            req.samlLogoutRequest = profile;
            self._saml.getLogoutResponseUrl(req, options, redirectIfSuccess);
          }

          self.pass();
        });

        return;
      }

      var verified = function (err, user, info) {
        if (err) {
          self.error(err);

          return;
        }

        if (!user) {
          self.fail(info);

          return;
        }

        self.success(user, info);
      };

      if (self._passReqToCallback) {
        self._verify(req, profile, verified);
      } else {
        self._verify(profile, verified);
      }
  }

  function redirectIfSuccess(err, url) {
    if (err) {
      self.error(err);
    } else {
      self.redirect(url);
    }
  }

  if (req.query && (req.query.SAMLResponse || req.query.SAMLRequest)) {
    console.log('validate redirect\n');
    this._saml.validateRedirect(req.query, validateCallback);
  } else if (req.body && req.body.SAMLResponse) {
    console.log('validate post response\n');
    this._saml.validatePostResponse(req.body, validateCallback);
  } else if (req.body && req.body.SAMLRequest) {
    console.log('validate post request\n');
    this._saml.validatePostRequest(req.body, validateCallback);
  } else {
    console.log('authenticate else');
    var requestHandler = {
      'login-request': function() {
        console.log('doing login-request\n');
        if (self._authnRequestBinding === 'HTTP-POST') {
          console.log('doing HTTP-POST');
          this._saml.getAuthorizeForm(req, function(err, data) {
            if (err) {
              self.error(err);
            } else {
              var res = req.res;
              res.send(data);
            }
          });
        } else { // Defaults to HTTP-Redirect
          this._saml.getAuthorizeUrl(req, options, redirectIfSuccess);
        }
      }.bind(self),
      'logout-request': function() {
        console.log('doing logout-request');
          this._saml.getLogoutUrl(req, options, redirectIfSuccess);
      }.bind(self)
    }[options.samlFallback];

    if (typeof requestHandler !== 'function') {
      return self.fail();
    }

    requestHandler();
  }
};

Strategy.prototype.logout = function(req, callback) {
  this._saml.getLogoutUrl(req, {}, callback);
};

Strategy.prototype.generateServiceProviderMetadata = function( decryptionCert, signingCert ) {
  return this._saml.generateServiceProviderMetadata( decryptionCert, signingCert );
};

module.exports = Strategy;
