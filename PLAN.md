# Aegis — Modern Authentication Middleware for Node.js

**Package:** `@agentine/aegis`
**Registry:** npm (verified available)
**Replaces:** passport.js (`passport` + `passport-local` + `passport-oauth2` + `passport-google-oauth20` + 500+ strategy packages)

---

## Why

Passport.js is the de facto authentication framework for Node.js — 6.3M weekly downloads, 23.5K stars, used by millions of Express applications worldwide. It has a single maintainer (Jared Hanson, 96% of commits) who has effectively stopped active development. The last release was v0.7.0 in November 2023; the last meaningful commit was August 2024 (README updates only). There are 393 open issues, no funding, no security advisory process, and the community has been asking "is this project dead?" for years.

Authentication is the single most security-critical component in web applications. Passport's stagnation means:
- No modern OAuth features (PKCE, DPoP)
- No TypeScript support (relies on DefinitelyTyped)
- Callback-based internals in an async/await world
- Session fixation and state validation bugs go unpatched
- Hundreds of strategy packages each with their own abandoned maintainer

No API-compatible replacement exists. Auth.js is Next.js-specific. Lucia was deprecated. SaaS solutions (Auth0, WorkOS) are different paradigms entirely.

---

## Design Principles

1. **Passport-compatible API** — same middleware pattern, same `req.login()`/`req.logout()`/`req.isAuthenticated()` augmentation. Migration is an import path change.
2. **TypeScript-first** — full type safety, generics for user types, no DefinitelyTyped needed.
3. **Strategies built-in** — consolidate the fragmented ecosystem. One package provides Local, OAuth2, Google, GitHub, Facebook, Twitter/X, Apple, Microsoft, SAML, and OpenID Connect.
4. **Async/await native** — no callback gymnastics. Strategies return Promises.
5. **Zero dependencies** — pure Node.js. No `passport-strategy`, no `pause`, no `utils-merge`.
6. **Express-first, framework-agnostic** — Express adapter built-in. Fastify and Koa adapters via thin wrappers.
7. **Modern security defaults** — PKCE for all OAuth flows, `state` parameter enforced, SameSite cookie defaults, session regeneration on login.

---

## Architecture

```
@agentine/aegis
├── src/
│   ├── index.ts                 # Public API exports
│   ├── authenticator.ts         # Core Authenticator class (replaces passport.Passport)
│   ├── strategy.ts              # Base Strategy abstract class
│   ├── middleware/
│   │   ├── authenticate.ts      # authenticate() middleware factory
│   │   ├── authorize.ts         # authorize() middleware (optional secondary auth)
│   │   └── initialize.ts        # initialize() middleware (req augmentation)
│   ├── session/
│   │   ├── serializer.ts        # Session serialize/deserialize
│   │   └── session-strategy.ts  # Built-in session strategy
│   ├── strategies/
│   │   ├── local.ts             # Username/password (replaces passport-local)
│   │   ├── oauth2.ts            # Generic OAuth 2.0 base (replaces passport-oauth2)
│   │   ├── google.ts            # Google OAuth 2.0 (replaces passport-google-oauth20)
│   │   ├── github.ts            # GitHub OAuth 2.0 (replaces passport-github2)
│   │   ├── facebook.ts          # Facebook OAuth (replaces passport-facebook)
│   │   ├── twitter.ts           # Twitter/X OAuth 2.0 (replaces passport-twitter)
│   │   ├── apple.ts             # Apple Sign-In (replaces passport-apple)
│   │   ├── microsoft.ts         # Microsoft/Azure AD (replaces passport-azure-ad)
│   │   ├── saml.ts              # SAML 2.0 (replaces passport-saml)
│   │   └── oidc.ts              # OpenID Connect (replaces passport-openidconnect)
│   ├── adapters/
│   │   ├── express.ts           # Express/Connect adapter (default)
│   │   ├── fastify.ts           # Fastify adapter
│   │   └── koa.ts               # Koa adapter
│   ├── errors.ts                # AuthenticationError, etc.
│   └── types.ts                 # Shared TypeScript types
├── tests/
├── package.json
├── tsconfig.json
└── README.md
```

---

## API Surface (Passport Compatibility)

```typescript
import aegis, { Strategy, LocalStrategy, GoogleStrategy } from '@agentine/aegis';

// Drop-in passport replacement
const app = express();
app.use(aegis.initialize());
app.use(aegis.session());

// Session serialization (same as passport)
aegis.serializeUser((user, done) => done(null, user.id));
aegis.deserializeUser((id, done) => User.findById(id, done));

// Also supports async/await (new!)
aegis.serializeUser(async (user) => user.id);
aegis.deserializeUser(async (id) => User.findById(id));

// Strategy registration (same as passport)
aegis.use(new LocalStrategy(async (username, password) => {
  const user = await User.findOne({ username });
  if (!user || !await user.verifyPassword(password)) return false;
  return user;
}));

aegis.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback',
}, async (accessToken, refreshToken, profile) => {
  return User.findOrCreate({ googleId: profile.id });
}));

// Middleware (same as passport)
app.post('/login', aegis.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true,
}));

// req augmentation (same as passport)
app.get('/profile', (req, res) => {
  if (req.isAuthenticated()) {
    res.json(req.user);
  }
});
```

### Migration from passport

```typescript
// Before:
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

// After (option 1 — alias):
import passport from '@agentine/aegis';
import { LocalStrategy, GoogleStrategy } from '@agentine/aegis';

// After (option 2 — rename):
import aegis, { LocalStrategy, GoogleStrategy } from '@agentine/aegis';
```

---

## Implementation Phases

### Phase 1: Core Framework & Local Strategy
**Goal:** Working Express authentication with username/password

- `Authenticator` class with strategy registry, `use()`, `unuse()`
- `Strategy` abstract base class with `authenticate()` method
- `initialize()` middleware — augments `req` with `login()`, `logout()`, `isAuthenticated()`, `isUnauthenticated()`
- `authenticate()` middleware factory — strategy dispatch, success/failure/redirect handling
- Session serialization/deserialization (`serializeUser`, `deserializeUser`)
- `SessionStrategy` — automatic session restore on request
- `LocalStrategy` — username/password verification with configurable field names
- `AuthenticationError` class and error handling
- Full TypeScript types with generics (`Authenticator<User>`)
- Support both callback and async/await patterns for backward compatibility
- Express adapter (default)
- Test suite with Express integration tests

### Phase 2: OAuth 2.0 Base & Provider Strategies
**Goal:** Working OAuth 2.0 authentication with major providers

- `OAuth2Strategy` base class:
  - Authorization URL construction with PKCE (S256) by default
  - Token exchange (authorization code → access + refresh tokens)
  - State parameter generation and validation (CSRF protection)
  - User profile fetching (provider-specific)
  - Token refresh support
  - Configurable scopes
- Provider strategies (each extends OAuth2Strategy):
  - `GoogleStrategy` — Google OAuth 2.0 with profile parsing
  - `GitHubStrategy` — GitHub OAuth 2.0 with profile parsing
  - `FacebookStrategy` — Facebook OAuth with profile parsing
  - `TwitterStrategy` — Twitter/X OAuth 2.0 (NOT OAuth 1.0a)
- Pure Node.js HTTP for token exchange (no `node-oauth`, no `axios`)
- Test suite with mocked OAuth flows

### Phase 3: Enterprise Strategies & Framework Adapters
**Goal:** Enterprise auth support and multi-framework compatibility

- `AppleStrategy` — Apple Sign-In (JWT-based ID token)
- `MicrosoftStrategy` — Microsoft/Azure AD OAuth 2.0
- `OIDCStrategy` — Generic OpenID Connect Discovery
- `SAMLStrategy` — SAML 2.0 assertion parsing (XML signature validation)
- Fastify adapter (`@agentine/aegis/fastify`)
- Koa adapter (`@agentine/aegis/koa`)
- `authorize()` middleware — connect third-party accounts to existing session
- Multi-strategy authentication (try strategies in sequence)

### Phase 4: Polish & Ship
**Goal:** Production-ready release

- Passport compatibility layer:
  - `import passport from '@agentine/aegis'` works with passport-style code
  - Accept passport-style `verify(accessToken, refreshToken, profile, done)` callbacks
  - Support `passReqToCallback` option
  - Flash message support (`failureFlash`, `successFlash`)
- Comprehensive README with:
  - Quick start guide
  - Migration guide from passport.js
  - Strategy configuration reference
  - Security best practices
  - TypeScript usage examples
- Security documentation:
  - PKCE explanation and configuration
  - Session security (regeneration, fixation prevention)
  - CSRF/state parameter handling
  - Cookie security defaults
- Benchmarks vs passport.js
- CI/CD pipeline (GitHub Actions)
- npm publish as `@agentine/aegis`
- GitHub release

---

## Key Differentiators vs Passport

| Feature | passport.js | aegis |
|---|---|---|
| TypeScript | DefinitelyTyped (external) | Native, generic types |
| API style | Callbacks only | Async/await + callbacks |
| Strategies | 500+ separate packages | Built-in (one install) |
| Dependencies | 3+ per strategy | Zero |
| OAuth PKCE | Not supported | Default for all flows |
| Session security | Manual regeneration | Auto-regenerate on login |
| State parameter | Optional, easily skipped | Enforced by default |
| Maintenance | 1 person, 393 open issues | Active |
| Node.js support | Minimum not documented | Node 18+ (LTS) |
| Framework support | Express only | Express, Fastify, Koa |

---

## Technical Decisions

- **Node.js 18+** — use native `fetch`, `crypto.subtle`, `URL`, `URLSearchParams`
- **ESM + CJS dual publish** — support both import styles via package.json exports map
- **No runtime dependencies** — all HTTP, crypto, and encoding handled with Node.js builtins
- **SAML uses builtin XML parsing** — `DOMParser` not available in Node, so use a minimal SAX parser (vendored, <500 LOC) for SAML XML. This is the one place where a vendored dependency is justified.
- **MIT license** — same as passport
