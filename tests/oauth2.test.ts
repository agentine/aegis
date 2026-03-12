import { describe, it, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { Authenticator } from '../src/authenticator.js';
import { OAuth2Strategy, type OAuth2Profile } from '../src/strategies/oauth2.js';
import { GoogleStrategy } from '../src/strategies/google.js';
import { GitHubStrategy } from '../src/strategies/github.js';
import { FacebookStrategy } from '../src/strategies/facebook.js';
import { TwitterStrategy } from '../src/strategies/twitter.js';
import type { AegisRequest, AegisResponse, NextFunction, DoneCallback } from '../src/types.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeReq(url: string, session: Record<string, unknown> = {}): AegisRequest {
  return {
    url,
    method: 'GET',
    headers: { host: 'localhost:3000' },
    session,
    user: undefined,
    login: () => {},
    logIn: () => {},
    logout: () => {},
    logOut: () => {},
    isAuthenticated: () => false,
    isUnauthenticated: () => true,
  } as unknown as AegisRequest;
}

function makeRes(): AegisResponse {
  return {} as AegisResponse;
}

/** Create a tiny HTTP server that responds with JSON, for token/profile mocking. */
function createMockServer(routes: Record<string, unknown>): Promise<{
  server: ReturnType<typeof createServer>;
  port: number;
  close: () => Promise<void>;
}> {
  return new Promise((resolve) => {
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const url = new URL(req.url || '/', `http://localhost`);
        const key = url.pathname;
        const response = routes[key];
        if (response) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(response));
        } else {
          res.writeHead(404);
          res.end('Not found');
        }
      });
    });
    server.listen(0, () => {
      const addr = server.address() as { port: number };
      resolve({
        server,
        port: addr.port,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

// ---------------------------------------------------------------------------
// OAuth2Strategy base
// ---------------------------------------------------------------------------

describe('OAuth2Strategy', () => {
  it('redirects to authorization URL on initial request', async () => {
    const strategy = new OAuth2Strategy(
      {
        authorizationURL: 'https://provider.com/auth',
        tokenURL: 'https://provider.com/token',
        clientID: 'test-client',
        clientSecret: 'test-secret',
        callbackURL: 'http://localhost:3000/callback',
        scope: 'openid profile',
        state: false,
        pkce: false,
      },
      async () => ({ id: '1' }),
    );

    let redirectUrl = '';
    strategy._setup({
      success: () => {},
      fail: () => {},
      redirect: (url) => { redirectUrl = url; },
      pass: () => {},
      error: () => {},
    });

    const req = makeReq('/auth');
    await strategy.authenticate(req);

    assert.ok(redirectUrl.startsWith('https://provider.com/auth?'));
    assert.ok(redirectUrl.includes('client_id=test-client'));
    assert.ok(redirectUrl.includes('redirect_uri='));
    assert.ok(redirectUrl.includes('response_type=code'));
    assert.ok(redirectUrl.includes('scope=openid+profile'));
  });

  it('includes state parameter when state=true', async () => {
    const strategy = new OAuth2Strategy(
      {
        authorizationURL: 'https://provider.com/auth',
        tokenURL: 'https://provider.com/token',
        clientID: 'test-client',
        clientSecret: 'test-secret',
        callbackURL: 'http://localhost:3000/callback',
        state: true,
        pkce: false,
      },
      async () => ({ id: '1' }),
    );

    let redirectUrl = '';
    strategy._setup({
      success: () => {},
      fail: () => {},
      redirect: (url) => { redirectUrl = url; },
      pass: () => {},
      error: () => {},
    });

    const session: Record<string, unknown> = {};
    const req = makeReq('/auth', session);
    await strategy.authenticate(req);

    assert.ok(redirectUrl.includes('state='));
    assert.ok(session['oauth2:state'], 'State should be stored in session');
  });

  it('includes PKCE challenge when pkce=true', async () => {
    const strategy = new OAuth2Strategy(
      {
        authorizationURL: 'https://provider.com/auth',
        tokenURL: 'https://provider.com/token',
        clientID: 'test-client',
        clientSecret: 'test-secret',
        callbackURL: 'http://localhost:3000/callback',
        state: false,
        pkce: true,
      },
      async () => ({ id: '1' }),
    );

    let redirectUrl = '';
    strategy._setup({
      success: () => {},
      fail: () => {},
      redirect: (url) => { redirectUrl = url; },
      pass: () => {},
      error: () => {},
    });

    const session: Record<string, unknown> = {};
    const req = makeReq('/auth', session);
    await strategy.authenticate(req);

    assert.ok(redirectUrl.includes('code_challenge='));
    assert.ok(redirectUrl.includes('code_challenge_method=S256'));
    assert.ok(session['oauth2:code_verifier'], 'PKCE verifier should be stored in session');
  });

  it('fails when error param is returned', async () => {
    const strategy = new OAuth2Strategy(
      {
        authorizationURL: 'https://provider.com/auth',
        tokenURL: 'https://provider.com/token',
        clientID: 'test-client',
        clientSecret: 'test-secret',
        callbackURL: 'http://localhost:3000/callback',
        state: false,
        pkce: false,
      },
      async () => ({ id: '1' }),
    );

    let failInfo: unknown;
    strategy._setup({
      success: () => {},
      fail: (info) => { failInfo = info; },
      redirect: () => {},
      pass: () => {},
      error: () => {},
    });

    const req = makeReq('/callback?error=access_denied&error_description=User+denied');
    await strategy.authenticate(req);

    assert.ok(failInfo);
    assert.equal((failInfo as { message: string }).message, 'User denied');
  });

  it('fails on state mismatch', async () => {
    const strategy = new OAuth2Strategy(
      {
        authorizationURL: 'https://provider.com/auth',
        tokenURL: 'https://provider.com/token',
        clientID: 'test-client',
        clientSecret: 'test-secret',
        callbackURL: 'http://localhost:3000/callback',
        state: true,
        pkce: false,
      },
      async () => ({ id: '1' }),
    );

    let failInfo: unknown;
    let failStatus: number | undefined;
    strategy._setup({
      success: () => {},
      fail: (info, status) => { failInfo = info; failStatus = status; },
      redirect: () => {},
      pass: () => {},
      error: () => {},
    });

    const session: Record<string, unknown> = { 'oauth2:state': 'correct-state' };
    const req = makeReq('/callback?code=abc&state=wrong-state', session);
    await strategy.authenticate(req);

    assert.ok(failInfo);
    assert.ok((failInfo as { message: string }).message.includes('state mismatch'));
    assert.equal(failStatus, 403);
  });

  it('exchanges code for token and calls verify', async () => {
    const mockServer = await createMockServer({
      '/token': { access_token: 'mock-at', refresh_token: 'mock-rt', token_type: 'bearer' },
    });

    try {
      let verifiedProfile: OAuth2Profile | undefined;
      let verifiedAccessToken: string | undefined;

      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://provider.com/auth',
          tokenURL: `http://localhost:${mockServer.port}/token`,
          clientID: 'test-client',
          clientSecret: 'test-secret',
          callbackURL: 'http://localhost:3000/callback',
          state: false,
          pkce: false,
        },
        async (accessToken, refreshToken, profile) => {
          verifiedAccessToken = accessToken;
          verifiedProfile = profile;
          return { id: profile.id, name: profile.displayName };
        },
      );

      let successUser: unknown;
      strategy._setup({
        success: (user) => { successUser = user; },
        fail: () => {},
        redirect: () => {},
        pass: () => {},
        error: (err) => { throw err; },
      });

      const req = makeReq('/callback?code=test-code');
      await strategy.authenticate(req);

      assert.equal(verifiedAccessToken, 'mock-at');
      assert.ok(successUser);
    } finally {
      await mockServer.close();
    }
  });

  it('supports callback-style verify', async () => {
    const mockServer = await createMockServer({
      '/token': { access_token: 'mock-at', token_type: 'bearer' },
    });

    try {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://provider.com/auth',
          tokenURL: `http://localhost:${mockServer.port}/token`,
          clientID: 'test-client',
          clientSecret: 'test-secret',
          callbackURL: 'http://localhost:3000/callback',
          state: false,
          pkce: false,
        },
        (accessToken, refreshToken, profile, done) => {
          done(null, { id: '1', token: accessToken });
        },
      );

      let successUser: unknown;
      strategy._setup({
        success: (user) => { successUser = user; },
        fail: () => {},
        redirect: () => {},
        pass: () => {},
        error: (err) => { throw err; },
      });

      const req = makeReq('/callback?code=test-code');
      await strategy.authenticate(req);

      assert.ok(successUser);
      assert.equal((successUser as { token: string }).token, 'mock-at');
    } finally {
      await mockServer.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Provider strategies
// ---------------------------------------------------------------------------

describe('GoogleStrategy', () => {
  it('has correct name', () => {
    const strategy = new GoogleStrategy(
      { clientID: 'id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );
    assert.equal(strategy.name, 'google');
  });

  it('redirects to Google auth URL', async () => {
    const strategy = new GoogleStrategy(
      { clientID: 'google-id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );

    let redirectUrl = '';
    strategy._setup({
      success: () => {},
      fail: () => {},
      redirect: (url) => { redirectUrl = url; },
      pass: () => {},
      error: () => {},
    });

    const req = makeReq('/auth/google', {});
    await strategy.authenticate(req);

    assert.ok(redirectUrl.startsWith('https://accounts.google.com/o/oauth2/v2/auth?'));
    assert.ok(redirectUrl.includes('client_id=google-id'));
  });
});

describe('GitHubStrategy', () => {
  it('has correct name', () => {
    const strategy = new GitHubStrategy(
      { clientID: 'id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );
    assert.equal(strategy.name, 'github');
  });

  it('redirects to GitHub auth URL', async () => {
    const strategy = new GitHubStrategy(
      { clientID: 'gh-id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );

    let redirectUrl = '';
    strategy._setup({
      success: () => {},
      fail: () => {},
      redirect: (url) => { redirectUrl = url; },
      pass: () => {},
      error: () => {},
    });

    const req = makeReq('/auth/github', {});
    await strategy.authenticate(req);

    assert.ok(redirectUrl.startsWith('https://github.com/login/oauth/authorize?'));
    assert.ok(redirectUrl.includes('client_id=gh-id'));
  });
});

describe('FacebookStrategy', () => {
  it('has correct name', () => {
    const strategy = new FacebookStrategy(
      { clientID: 'id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );
    assert.equal(strategy.name, 'facebook');
  });

  it('redirects to Facebook auth URL', async () => {
    const strategy = new FacebookStrategy(
      { clientID: 'fb-id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );

    let redirectUrl = '';
    strategy._setup({
      success: () => {},
      fail: () => {},
      redirect: (url) => { redirectUrl = url; },
      pass: () => {},
      error: () => {},
    });

    const req = makeReq('/auth/facebook', {});
    await strategy.authenticate(req);

    assert.ok(redirectUrl.startsWith('https://www.facebook.com/v18.0/dialog/oauth?'));
    assert.ok(redirectUrl.includes('client_id=fb-id'));
  });
});

describe('TwitterStrategy', () => {
  it('has correct name', () => {
    const strategy = new TwitterStrategy(
      { clientID: 'id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );
    assert.equal(strategy.name, 'twitter');
  });

  it('redirects to Twitter auth URL with PKCE', async () => {
    const strategy = new TwitterStrategy(
      { clientID: 'tw-id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );

    let redirectUrl = '';
    strategy._setup({
      success: () => {},
      fail: () => {},
      redirect: (url) => { redirectUrl = url; },
      pass: () => {},
      error: () => {},
    });

    const session: Record<string, unknown> = {};
    const req = makeReq('/auth/twitter', session);
    await strategy.authenticate(req);

    assert.ok(redirectUrl.startsWith('https://twitter.com/i/oauth2/authorize?'));
    assert.ok(redirectUrl.includes('client_id=tw-id'));
    assert.ok(redirectUrl.includes('code_challenge='));
    assert.ok(redirectUrl.includes('code_challenge_method=S256'));
  });
});

// ---------------------------------------------------------------------------
// Authenticator integration
// ---------------------------------------------------------------------------

describe('Authenticator with OAuth2 strategies', () => {
  it('registers and retrieves OAuth2 strategies', () => {
    const auth = new Authenticator();
    const google = new GoogleStrategy(
      { clientID: 'id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );
    const github = new GitHubStrategy(
      { clientID: 'id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );

    auth.use(google);
    auth.use(github);

    assert.ok(auth._strategy('google'));
    assert.ok(auth._strategy('github'));
  });

  it('can register with custom name', () => {
    const auth = new Authenticator();
    const google = new GoogleStrategy(
      { clientID: 'id', clientSecret: 'secret', callbackURL: 'http://localhost/cb' },
      async () => ({ id: '1' }),
    );

    auth.use('google-custom', google);
    assert.ok(auth._strategy('google-custom'));
  });
});

// ---------------------------------------------------------------------------
// Token refresh
// ---------------------------------------------------------------------------

describe('OAuth2Strategy token refresh', () => {
  it('refreshes an access token', async () => {
    const mockServer = await createMockServer({
      '/token': { access_token: 'new-at', token_type: 'bearer', expires_in: 3600 },
    });

    try {
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: 'https://provider.com/auth',
          tokenURL: `http://localhost:${mockServer.port}/token`,
          clientID: 'test-client',
          clientSecret: 'test-secret',
          callbackURL: 'http://localhost:3000/callback',
        },
        async () => ({ id: '1' }),
      );

      const result = await strategy.refreshAccessToken('old-rt');
      assert.equal(result.access_token, 'new-at');
    } finally {
      await mockServer.close();
    }
  });
});
