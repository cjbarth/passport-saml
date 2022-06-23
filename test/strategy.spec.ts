"use strict";

import { expect } from "chai";
import * as sinon from "sinon";
import { Profile, SAML, SamlConfig, Strategy as SamlStrategy } from "../src";
import { RequestWithUser, VerifiedCallback, VerifyWithoutRequest } from "../src/types";
import { FAKE_CERT } from "./types";

const noop = () => undefined;

describe("Strategy()", function () {
  it("should require ctor `options` argument", function () {
    // @ts-ignore
    expect(() => new SamlStrategy(noop)).to.throw("Mandatory SAML options missing");
  });

  it("should require that `signonVerify` be a function", function () {
    // @ts-ignore
    expect(() => new SamlStrategy({}, {})).to.throw(
      "SAML authentication strategy requires a verify function"
    );
  });

  describe("authenticate", function () {
    let getAuthorizeFormStub: sinon.SinonStub;
    let getAuthorizeUrlStub: sinon.SinonStub;
    let getLogoutResponseUrlStub: sinon.SinonStub;
    let getLogoutUrlAsyncStub: sinon.SinonStub;
    let validatePostResponseAsync: sinon.SinonStub;
    let errorStub: sinon.SinonStub;
    let redirectStub: sinon.SinonStub;
    let requestWithUser = {} as unknown as RequestWithUser;
    let requestWithUserPostResponse = {} as unknown as RequestWithUser;

    beforeEach(function () {
      getAuthorizeFormStub = sinon.stub(SAML.prototype, "getAuthorizeFormAsync").resolves();
      getAuthorizeUrlStub = sinon.stub(SAML.prototype, "getAuthorizeUrlAsync").resolves();
      getLogoutResponseUrlStub = sinon.stub(SAML.prototype, "getLogoutResponseUrl");
      getLogoutUrlAsyncStub = sinon.stub(SAML.prototype, "getLogoutUrlAsync").resolves();
      validatePostResponseAsync = sinon
        .stub(SAML.prototype, "validatePostResponseAsync")
        .resolves();
      errorStub = sinon.stub(SamlStrategy.prototype, "error");
      redirectStub = sinon.stub(SamlStrategy.prototype, "redirect");

      requestWithUser = {
        logout: noop,
        res: { send: noop },
      } as unknown as RequestWithUser;
      requestWithUserPostResponse = {
        body: { SAMLResponse: {} },
        logout: noop,
        res: { send: noop },
      } as unknown as RequestWithUser;
    });

    afterEach(function () {
      getAuthorizeFormStub.restore();
      getAuthorizeUrlStub.restore();
      getLogoutResponseUrlStub.restore();
      getLogoutUrlAsyncStub.restore();
      validatePostResponseAsync.restore();
      errorStub.restore();
      redirectStub.restore();
    });

    it("calls getAuthorizeForm when authnRequestBinding is HTTP-POST for login-request", function (done) {
      const strategy = new SamlStrategy(
        {
          authnRequestBinding: "HTTP-POST",
          cert: FAKE_CERT,
        },
        noop,
        noop
      );

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnce(getAuthorizeFormStub);
        done();
      });
    });

    it("calls getAuthorizeForm when authnRequestBinding is not HTTP-POST for logout-request", function (done) {
      const strategy = new SamlStrategy(
        {
          cert: FAKE_CERT,
        },
        noop,
        noop
      );

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, { samlFallback: "logout-request" });

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnce(getLogoutUrlAsyncStub);
        done();
      });
    });

    it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST for login-request", function (done) {
      const strategy = new SamlStrategy({ cert: FAKE_CERT }, noop, noop);

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnce(getAuthorizeUrlStub);
        sinon.assert.calledOnce(redirectStub);
        done();
      });
    });

    it("determines that logout was unsuccessful where user doesn't match", function (done) {
      const strategy = new SamlStrategy(
        { cert: FAKE_CERT },
        function (_profile: Profile | null, done: VerifiedCallback) {
          // for signon
          if (_profile) {
            done(null, { name: _profile.nameID });
          }
        },
        function (_profile: Profile | null, done: VerifiedCallback) {
          // for logout
          if (_profile) {
            done(null, { name: _profile.nameID });
          }
        }
      );

      validatePostResponseAsync.resolves({
        profile: {
          ID: "ID",
          issuer: "issuer",
          nameID: "some other user",
          nameIDFormat: "nameIDFormat",
        },
        loggedOut: true,
      });

      // Pretend we already loaded a users session from a cookie or something
      // by calling `strategy.authenticate` when the request comes in
      requestWithUserPostResponse.user = {
        name: "some user",
      };

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUserPostResponse, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnceWithMatch(
          getLogoutResponseUrlStub,
          sinon.match.any,
          sinon.match.any,
          sinon.match.any,
          false,
          sinon.match.func
        );
        done();
      });
    });

    it("determines that logout was successful where user matches", function (done) {
      const strategy = new SamlStrategy(
        { cert: FAKE_CERT },
        function (_profile: Profile | null, done: VerifiedCallback) {
          // for signon
          if (_profile) {
            done(null, { name: _profile.nameID });
          }
        },
        function (_profile: Profile | null, done: VerifiedCallback) {
          // for logout
          if (_profile) {
            done(null, { name: _profile.nameID });
          }
        }
      );

      validatePostResponseAsync.resolves({
        profile: {
          ID: "ID",
          issuer: "issuer",
          nameID: "some user",
          nameIDFormat: "nameIDFormat",
        },
        loggedOut: true,
      });

      // Pretend we already loaded a users session from a cookie or something
      // by calling `strategy.authenticate` when the request comes in
      requestWithUserPostResponse.user = {
        name: "some user",
      };

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUserPostResponse, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnceWithMatch(
          getLogoutResponseUrlStub,
          sinon.match.any,
          sinon.match.any,
          sinon.match.any,
          true,
          sinon.match.func
        );
        done();
      });
    });
  });

  describe("logout", function () {
    let getLogoutUrlAsyncStub: sinon.SinonStub;

    beforeEach(function () {
      getLogoutUrlAsyncStub = sinon.stub(SAML.prototype, "getLogoutUrlAsync").resolves();
    });

    afterEach(function () {
      getLogoutUrlAsyncStub.restore();
    });

    it("should call through to get logout URL", function () {
      // @ts-ignore
      new SamlStrategy({ cert: FAKE_CERT }, noop, noop).logout({ query: "" });
      sinon.assert.calledOnce(getLogoutUrlAsyncStub);
    });
  });

  describe("generateServiceProviderMetadata", function () {
    let generateServiceProviderMetadataStub: sinon.SinonStub;

    beforeEach(function () {
      generateServiceProviderMetadataStub = sinon.stub(
        SAML.prototype,
        "generateServiceProviderMetadata"
      );
    });

    afterEach(function () {
      generateServiceProviderMetadataStub.restore();
    });

    it("should call through to generate metadata", function () {
      const samlConfig: SamlConfig = { cert: FAKE_CERT };
      const signonVerify: VerifyWithoutRequest = function (
        _profile: Profile | null,
        done: VerifiedCallback
      ): void {
        throw Error("This shouldn't be called to generate metadata");
      };

      const logoutVerify: VerifyWithoutRequest = function (
        _profile: Profile | null,
        done: VerifiedCallback
      ): void {
        throw Error("This shouldn't be called to generate metadata");
      };
      new SamlStrategy(samlConfig, signonVerify, logoutVerify).generateServiceProviderMetadata("");
      sinon.assert.calledOnce(generateServiceProviderMetadataStub);
    });
  });
});
