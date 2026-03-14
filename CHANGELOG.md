# Changelog

All notable changes to @agentine/aegis will be documented in this file.

## [1.0.0] - 2026-03-14

### Added

- **Core framework** — `Authenticator` class with `use()`, `initialize()`, `authenticate()`, `authorize()`, `serializeUser()`, `deserializeUser()`, `logout()`, `isAuthenticated()`, `isUnauthenticated()`, `passReqToCallback` support, and flash message integration.
- **LocalStrategy** — username/password authentication with async verify callback.
- **OAuth2Strategy** — generic OAuth 2.0 base strategy with PKCE enforcement, `state` parameter validation, and async/await native API.
- **Google, GitHub, Facebook, Twitter/X, Apple, Microsoft strategies** — first-party provider strategies built on OAuth2Strategy.
- **SAMLStrategy** — SAML 2.0 with signature validation, `InResponseTo`/Destination checks, assertion conditions, and cert enforcement.
- **OpenID Connect strategy** — OIDC with `id_token` validation, nonce enforcement, JWKS key verification (RSA, EC), and issuer validation.
- **Session strategy** — built-in session serialization/deserialization via `express-session`.
- **Express adapter** — `initialize()` middleware for `req.login()`, `req.logout()`, `req.isAuthenticated()` augmentation; Fastify and Koa adapter stubs.
- **Security defaults** — session regeneration on login (session fixation prevention), open redirect validation, SameSite cookie guidance, PKCE required for all OAuth flows.
- **TypeScript-first** — full type safety with generics for user types; no DefinitelyTyped dependency.
- **Zero runtime dependencies** — pure Node.js, no `passport-strategy`, `pause`, or `utils-merge`.
- **CI/CD** — GitHub Actions workflows for test (`ci.yml`) and npm publish on release (`publish.yml`) with npm provenance.
- **Benchmarks** — performance comparison suite vs. passport.js baseline.
- **Comprehensive README** — migration guide, API reference, strategy configuration examples.
