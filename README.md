# @agentine/aegis

**Modern, TypeScript-first authentication middleware for Node.js.** Drop-in replacement for passport.js — same API, zero dependencies, async/await native, PKCE by default.

[![npm](https://img.shields.io/npm/v/@agentine/aegis)](https://www.npmjs.com/package/@agentine/aegis)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why aegis?

Passport.js has 6.3M weekly downloads and a single maintainer who stopped active development in 2023. With 393 open issues and no modern OAuth features, using passport in a security-critical application means accepting known gaps:

- No PKCE support (authorization code interception attacks)
- No TypeScript (relies on DefinitelyTyped, often out of sync)
- Callback-based internals incompatible with async/await
- Session fixation and state validation bugs unpatched
- 500+ separate strategy packages, each with its own abandoned maintainer

aegis fixes all of this while keeping the same API. Migrating is an import path change.

| Feature | passport.js | aegis |
|---|---|---|
| TypeScript | DefinitelyTyped (external) | Native, full generics |
| API style | Callbacks only | Async/await + callbacks |
| Strategies | 500+ separate packages | Built-in (one install) |
| Dependencies | 3+ per strategy | Zero |
| OAuth PKCE | Not supported | Default for all flows |
| Session security | Manual regeneration | Auto-regenerate on login |
| State parameter | Optional, easy to skip | Enforced by default |
| Framework support | Express only | Express, Fastify, Koa |
| Node.js minimum | Not documented | Node 18+ (LTS) |

---

## Installation

```bash
npm install @agentine/aegis
```

Requires Node.js 18 or later. No additional strategy packages needed.

---

## Quick Start

```typescript
import express from 'express';
import session from 'express-session';
import aegis, { LocalStrategy } from '@agentine/aegis';

const app = express();

app.use(express.json());
app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
app.use(aegis.initialize());
app.use(aegis.session());

// Register a strategy
aegis.use(new LocalStrategy(async (username, password) => {
  const user = await db.users.findOne({ username });
  if (!user || !await user.verifyPassword(password)) return false;
  return user;
}));

// Session serialization
aegis.serializeUser(async (user) => user.id);
aegis.deserializeUser(async (id) => db.users.findById(id));

// Login route
app.post('/login', aegis.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
}));

// Protected route
app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.json({ user: req.user });
});

// Logout
app.post('/logout', (req, res) => {
  req.logout(() => res.redirect('/login'));
});
```

---

## Migration from passport.js

Migrating from passport is an import path change:

```typescript
// Before
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';

// After — option 1 (alias, zero code changes)
import passport from '@agentine/aegis';
import { LocalStrategy, GoogleStrategy, GitHubStrategy } from '@agentine/aegis';

// After — option 2 (rename)
import aegis, { LocalStrategy, GoogleStrategy, GitHubStrategy } from '@agentine/aegis';
```

All passport API methods work identically:
- `passport.use()` / `passport.unuse()`
- `passport.initialize()` / `passport.session()`
- `passport.authenticate()`
- `passport.serializeUser()` / `passport.deserializeUser()`
- `req.login()` / `req.logIn()`
- `req.logout()` / `req.logOut()`
- `req.isAuthenticated()` / `req.isUnauthenticated()`
- `failureFlash`, `successFlash`, `passReqToCallback` options

New in aegis (not in passport):
- Async verify functions return a value instead of calling `done(null, user)`
- PKCE enabled by default on all OAuth flows
- `state` parameter enforced by default
- Session regeneration on login (prevents session fixation)

---

## Strategies

### Local Strategy

Username/password authentication from `req.body`.

```typescript
import { LocalStrategy } from '@agentine/aegis';

// Async verify (recommended)
aegis.use(new LocalStrategy(async (username, password) => {
  const user = await User.findOne({ username });
  if (!user || !await bcrypt.compare(password, user.passwordHash)) return false;
  return user;
}));

// Callback verify (passport-compatible)
aegis.use(new LocalStrategy((username, password, done) => {
  User.findOne({ username }, (err, user) => {
    if (err) return done(err);
    if (!user || !user.verifyPassword(password)) return done(null, false, { message: 'Invalid credentials' });
    return done(null, user);
  });
}));

// Custom field names
aegis.use(new LocalStrategy(
  { usernameField: 'email', passwordField: 'pass' },
  async (email, password) => { /* ... */ },
));
```

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `usernameField` | `string` | `'username'` | `req.body` field for the username |
| `passwordField` | `string` | `'password'` | `req.body` field for the password |
| `passReqToCallback` | `boolean` | `false` | Pass `req` as first argument to the verify function |

---

### OAuth2 Strategy (generic)

Base class for custom OAuth 2.0 providers. All provider strategies extend this.

```typescript
import { OAuth2Strategy } from '@agentine/aegis';

aegis.use(new OAuth2Strategy(
  {
    authorizationURL: 'https://provider.example.com/oauth/authorize',
    tokenURL: 'https://provider.example.com/oauth/token',
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'https://myapp.com/auth/callback',
    scope: ['read:user', 'read:email'],
  },
  async (accessToken, refreshToken, profile) => {
    return User.findOrCreate({ providerId: profile.id });
  },
));
```

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `authorizationURL` | `string` | — | Provider authorization endpoint |
| `tokenURL` | `string` | — | Provider token endpoint |
| `clientID` | `string` | — | OAuth client ID |
| `clientSecret` | `string` | — | OAuth client secret |
| `callbackURL` | `string` | — | Your application's redirect URI |
| `scope` | `string \| string[]` | — | Requested scopes |
| `pkce` | `boolean` | `true` | Enable PKCE (S256) — strongly recommended |
| `state` | `boolean` | `true` | Enable CSRF state parameter — strongly recommended |
| `passReqToCallback` | `boolean` | `false` | Pass `req` as first argument to verify |

---

### Google Strategy

```typescript
import { GoogleStrategy } from '@agentine/aegis';

aegis.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
    // scope defaults to ['openid', 'profile', 'email']
  },
  async (accessToken, refreshToken, profile) => {
    return User.findOrCreate({
      googleId: profile.id,
      email: profile.emails?.[0]?.value,
      displayName: profile.displayName,
    });
  },
));

app.get('/auth/google', aegis.authenticate('google'));
app.get('/auth/google/callback',
  aegis.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/'),
);
```

**Profile fields:** `id`, `displayName`, `name.givenName`, `name.familyName`, `emails[].value`, `photos[].value`

---

### GitHub Strategy

```typescript
import { GitHubStrategy } from '@agentine/aegis';

aegis.use(new GitHubStrategy(
  {
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: '/auth/github/callback',
    // scope defaults to ['read:user', 'user:email']
  },
  async (accessToken, refreshToken, profile) => {
    return User.findOrCreate({ githubId: profile.id });
  },
));

app.get('/auth/github', aegis.authenticate('github'));
app.get('/auth/github/callback',
  aegis.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/'),
);
```

**Note:** GitHub does not always return the email in the main profile. aegis automatically fetches `/user/emails` and includes verified addresses when available.

---

### Facebook Strategy

```typescript
import { FacebookStrategy } from '@agentine/aegis';

aegis.use(new FacebookStrategy(
  {
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: '/auth/facebook/callback',
    scope: ['email', 'public_profile'],
    profileFields: ['id', 'name', 'email', 'picture'], // optional
  },
  async (accessToken, refreshToken, profile) => {
    return User.findOrCreate({ facebookId: profile.id });
  },
));
```

---

### Twitter/X Strategy

Uses Twitter API v2 with OAuth 2.0 (not legacy OAuth 1.0a). PKCE is required and always enabled.

```typescript
import { TwitterStrategy } from '@agentine/aegis';

aegis.use(new TwitterStrategy(
  {
    clientID: process.env.TWITTER_CLIENT_ID,
    clientSecret: process.env.TWITTER_CLIENT_SECRET,
    callbackURL: '/auth/twitter/callback',
    // scope defaults to ['tweet.read', 'users.read', 'offline.access']
  },
  async (accessToken, refreshToken, profile) => {
    return User.findOrCreate({ twitterId: profile.id });
  },
));
```

**Note:** Twitter API v2 does not return email addresses.

---

### Apple Strategy (Sign in with Apple)

Apple uses JWT-based ID tokens instead of a userinfo endpoint. aegis verifies the JWT signature using Apple's published JWKS (cached for 1 hour), validates issuer/audience/expiry, and enforces nonce-based replay protection.

Apple only sends user name data on the **first** login. Store it at that point.

```typescript
import { AppleStrategy } from '@agentine/aegis';

aegis.use(new AppleStrategy(
  {
    clientID: 'com.example.myapp',   // Your App ID / Services ID
    clientSecret: process.env.APPLE_CLIENT_SECRET, // Signed JWT (see Apple docs)
    callbackURL: '/auth/apple/callback',
    scope: ['name', 'email'],
  },
  async (accessToken, refreshToken, profile) => {
    return User.findOrCreate({
      appleId: profile.id,
      email: profile.emails?.[0]?.value,
      // Store name on first login — Apple won't send it again
      displayName: profile.displayName || undefined,
    });
  },
));

// Apple POSTs the callback — use POST route
app.post('/auth/apple/callback',
  aegis.authenticate('apple', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/'),
);
```

**Note:** The Apple `clientSecret` is a signed JWT, not a simple string. See [Apple's documentation](https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens) for how to generate it.

---

### Microsoft Strategy (Azure AD / Microsoft Entra)

Supports personal Microsoft accounts (`common` tenant) and Azure AD tenants.

```typescript
import { MicrosoftStrategy } from '@agentine/aegis';

aegis.use(new MicrosoftStrategy(
  {
    clientID: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    callbackURL: '/auth/microsoft/callback',
    tenant: 'common',  // or your tenant ID for organization-only login
    // scope defaults to ['openid', 'profile', 'email', 'User.Read']
  },
  async (accessToken, refreshToken, profile) => {
    return User.findOrCreate({ microsoftId: profile.id });
  },
));
```

---

### OIDC Strategy (OpenID Connect)

Generic OpenID Connect with automatic endpoint discovery via `.well-known/openid-configuration`. Works with any compliant provider (Okta, Auth0, Keycloak, etc.).

```typescript
import { OIDCStrategy } from '@agentine/aegis';

aegis.use(new OIDCStrategy(
  {
    issuer: 'https://accounts.example.com',
    clientID: process.env.OIDC_CLIENT_ID,
    clientSecret: process.env.OIDC_CLIENT_SECRET,
    callbackURL: '/auth/oidc/callback',
    // scope defaults to ['openid', 'profile', 'email']
  },
  async (accessToken, refreshToken, profile) => {
    return User.findOrCreate({ sub: profile.id });
  },
));
```

Endpoint discovery is cached after the first request. The id_token is validated per OIDC Core: signature (RSA256/384/512 via JWKS), issuer, audience, expiry, and nonce.

---

### SAML Strategy

SP-initiated SSO with XML signature verification. Requires the IdP's signing certificate.

```typescript
import { SAMLStrategy } from '@agentine/aegis';

aegis.use(new SAMLStrategy(
  {
    entryPoint: 'https://idp.example.com/saml2/sso',
    issuer: 'https://myapp.com',        // Your entity ID
    callbackURL: 'https://myapp.com/auth/saml/callback',
    cert: process.env.SAML_IDP_CERT,   // IdP signing certificate (PEM or raw base64)
  },
  async (profile) => {
    return User.findOrCreate({
      samlId: profile.nameID,
      email: profile.attributes['email'],
    });
  },
));

// Initiate SAML flow
app.get('/auth/saml', aegis.authenticate('saml'));

// Handle IdP POST-back
app.post('/auth/saml/callback',
  express.urlencoded({ extended: false }),
  aegis.authenticate('saml', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/'),
);
```

**SAML profile fields:**

| Field | Description |
|---|---|
| `issuer` | IdP entity ID from the assertion |
| `nameID` | The user's NameID value |
| `nameIDFormat` | NameID format URI |
| `sessionIndex` | SAML session index (for SLO) |
| `attributes` | All `AttributeStatement` values as `Record<string, string>` |

---

## Framework Adapters

### Express (default)

Express is the default. No adapter import needed — just use aegis middleware directly:

```typescript
import aegis from '@agentine/aegis';
import express from 'express';
import session from 'express-session';

const app = express();
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(aegis.initialize());
app.use(aegis.session());
```

### Fastify

```typescript
import Fastify from 'fastify';
import fastifySession from '@fastify/session';
import aegis, { LocalStrategy } from '@agentine/aegis';
import { toFastifyHook } from '@agentine/aegis';

const fastify = Fastify();

await fastify.register(fastifySession, { secret: process.env.SESSION_SECRET });

aegis.use(new LocalStrategy(async (username, password) => { /* ... */ }));
aegis.serializeUser(async (user) => user.id);
aegis.deserializeUser(async (id) => User.findById(id));

fastify.addHook('preHandler', toFastifyHook(aegis.initialize()));
fastify.addHook('preHandler', toFastifyHook(aegis.session()));

fastify.post('/login', {
  preHandler: toFastifyHook(
    aegis.authenticate('local', { session: false }),
  ),
}, async (request, reply) => {
  return { user: request.raw.user };
});
```

### Koa

```typescript
import Koa from 'koa';
import session from 'koa-session';
import bodyParser from 'koa-bodyparser';
import aegis, { LocalStrategy } from '@agentine/aegis';
import { toKoaMiddleware } from '@agentine/aegis';

const app = new Koa();
app.keys = [process.env.SESSION_SECRET];

app.use(session({}, app));
app.use(bodyParser());
app.use(toKoaMiddleware(aegis.initialize()));
app.use(toKoaMiddleware(aegis.session()));

// The authenticated user is available on ctx.state.user
app.use(async (ctx) => {
  if (ctx.path === '/login' && ctx.method === 'POST') {
    await new Promise<void>((resolve, reject) => {
      toKoaMiddleware(aegis.authenticate('local', { session: true }))(ctx as any, async () => {
        resolve();
      });
    });
    ctx.redirect('/');
  }
});
```

---

## TypeScript Usage

aegis is TypeScript-first. Use the `User` generic to get full type safety across your application:

```typescript
import { Authenticator, LocalStrategy } from '@agentine/aegis';

interface AppUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
}

// Typed authenticator
const auth = new Authenticator<AppUser>();

auth.serializeUser(async (user: AppUser) => user.id);
auth.deserializeUser(async (id): Promise<AppUser | null> => db.users.findById(id));

auth.use(new LocalStrategy<AppUser>(async (username, password) => {
  const user = await db.users.findOne({ email: username });
  if (!user || !await bcrypt.compare(password, user.passwordHash)) return false;
  return user; // typed as AppUser
}));

// req.user is typed as AppUser | undefined
app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ email: req.user.email, role: req.user.role }); // fully typed
});
```

### Multiple independent authenticators

```typescript
const userAuth = new Authenticator<User>();
const adminAuth = new Authenticator<Admin>();

// Each has its own strategy registry and session serialization
userAuth.use(new LocalStrategy<User>(verifyUser));
adminAuth.use(new LocalStrategy<Admin>(verifyAdmin));
```

---

## API Reference

### `new Authenticator<User>()`

The main class. The default export is a pre-created instance (`new Authenticator()`).

#### `.use(strategy)` / `.use(name, strategy)`

Register a strategy. Strategies self-name via their `name` property; pass an explicit name to override.

#### `.unuse(name)`

Remove a registered strategy.

#### `.initialize(options?)`

Returns middleware that augments `req` with `login()`, `logout()`, `isAuthenticated()`, and `isUnauthenticated()`.

| Option | Default | Description |
|---|---|---|
| `userProperty` | `'user'` | Property name on `req` where the user is stored |

#### `.session(options?)`

Returns middleware that restores authentication from the session on each request.

| Option | Default | Description |
|---|---|---|
| `optional` | `false` | Don't fail if no session is present |

#### `.authenticate(strategy, options?, callback?)`

Returns authentication middleware.

`strategy` can be a single name or an array of names (tried in order until one succeeds).

| Option | Type | Description |
|---|---|---|
| `session` | `boolean` | Save user to session on success (default: `true`) |
| `optional` | `boolean` | Pass through without error if authentication fails |
| `successRedirect` | `string` | Redirect on success |
| `failureRedirect` | `string` | Redirect on failure |
| `failureFlash` | `string \| boolean` | Flash failure message (requires `connect-flash`) |
| `successFlash` | `string \| boolean` | Flash success message (requires `connect-flash`) |
| `failureMessage` | `string \| boolean` | Store failure message in `req.session.messages` |
| `successMessage` | `string \| boolean` | Store success message in `req.session.messages` |
| `assignProperty` | `string` | Store user on `req[property]` instead of establishing a session |

**Custom callback:**

```typescript
app.post('/login', (req, res, next) => {
  aegis.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ error: info?.message });
    req.login(user, (err) => {
      if (err) return next(err);
      res.json({ user });
    });
  })(req, res, next);
});
```

#### `.authorize(strategy, options?)`

Links an additional account to an existing session without replacing `req.user`. The linked account is stored on `req.account` (or `req[options.assignProperty]`).

#### `.serializeUser(fn)` / `.deserializeUser(fn)`

Register session serialization/deserialization. Both async and callback styles are supported:

```typescript
// Async
aegis.serializeUser(async (user) => user.id);
aegis.deserializeUser(async (id) => User.findById(id));

// Callback (passport-compatible)
aegis.serializeUser((user, done) => done(null, user.id));
aegis.deserializeUser((id, done) => User.findById(id, done));
```

### `req` methods (added by `initialize()`)

| Method | Description |
|---|---|
| `req.isAuthenticated()` | Returns `true` if a user is authenticated |
| `req.isUnauthenticated()` | Returns `true` if no user is authenticated |
| `req.login(user, done)` | Log in a user (establishes session) |
| `req.logout(done)` | Log out the current user (clears session) |
| `req.user` | The authenticated user object |

### `AuthenticationError`

Thrown when authentication fails and no redirect is configured:

```typescript
import { AuthenticationError } from '@agentine/aegis';

// In Express error handler:
app.use((err, req, res, next) => {
  if (err instanceof AuthenticationError) {
    return res.status(err.status).json({ error: err.message });
  }
  next(err);
});
```

---

## Security Best Practices

### PKCE (Proof Key for Code Exchange)

PKCE is **enabled by default** for all OAuth 2.0 flows. It prevents authorization code interception attacks even when TLS is terminated early. Do not disable it unless your provider explicitly does not support it.

```typescript
// PKCE is on by default — no configuration needed
new GoogleStrategy({ clientID, clientSecret, callbackURL }, verify);

// Explicit disable (not recommended)
new OAuth2Strategy({ /* ... */, pkce: false }, verify);
```

### State Parameter (CSRF Protection)

The state parameter is **enforced by default** on all OAuth 2.0 flows. aegis generates a cryptographically random 48-hex-char state, stores it in the session, and validates it on callback. Mismatches return HTTP 403.

### Session Regeneration

aegis regenerates the session ID on every successful login to prevent session fixation attacks. This requires `express-session` (or compatible) to expose `req.session.regenerate()`.

### Redirect URL Validation

The `authenticate()` middleware validates all redirect URLs before issuing redirects:
- Relative paths (`/path`) are allowed
- `https://` URLs are allowed (for OAuth provider redirects)
- `http://localhost` URLs are allowed (for development)
- Protocol-relative URLs (`//evil.com`) are rejected with HTTP 400
- Non-https schemes (`javascript:`, `data:`, etc.) are rejected

### Cookie Security

Configure `express-session` with appropriate cookie settings for production:

```typescript
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,      // Prevent XSS access to the cookie
    secure: true,        // Require HTTPS (set this in production)
    sameSite: 'lax',     // CSRF protection
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));
```

### SAML Security Notes

- The `cert` option is required. aegis will throw at construction time if it is missing.
- Signature verification uses the provided certificate for both the response-level and assertion-level signatures.
- `InResponseTo` attribute is validated to prevent unsolicited response injection.
- `Destination` attribute is validated to prevent response re-use across service providers.
- Assertion conditions (`NotBefore`, `NotOnOrAfter`, `AudienceRestriction`) are validated with 5-minute clock skew tolerance.

---

## Benchmarks

Run against Node.js 22 on Apple M-series:

```
initialize() middleware:
  aegis initialize(): 1,086,818 ops/sec (0.92 µs/op)

authenticate("local") — success:
  aegis local auth (success): 685,556 ops/sec (1.46 µs/op)

authenticate("local") — failure:
  aegis local auth (failure): 487,755 ops/sec (2.05 µs/op)
```

Run the benchmarks yourself:

```bash
npm run bench
```

---

## License

MIT
