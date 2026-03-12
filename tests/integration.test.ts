import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import session from 'express-session';
import { Authenticator, LocalStrategy, AuthenticationError, Strategy } from '../src/index.js';
import type { AegisRequest, DoneCallback } from '../src/index.js';

// ---- Helpers ----

interface TestUser {
  id: number;
  username: string;
}

const USERS: TestUser[] = [
  { id: 1, username: 'alice' },
  { id: 2, username: 'bob' },
];

function findUser(username: string, password: string): TestUser | false {
  if (password !== 'secret') return false;
  const user = USERS.find((u) => u.username === username);
  return user || false;
}

function createApp(authenticator: Authenticator<TestUser>): express.Express {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(
    session({
      secret: 'test-secret',
      resave: false,
      saveUninitialized: false,
    }),
  );
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  app.use(authenticator.initialize() as any);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  app.use(authenticator.session() as any);
  return app;
}

function request(
  server: http.Server,
  method: string,
  path: string,
  body?: Record<string, string>,
  cookie?: string,
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string; cookie?: string }> {
  return new Promise((resolve, reject) => {
    const addr = server.address() as { port: number };
    const headers: Record<string, string> = {};
    let data: string | undefined;

    if (body) {
      data = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data).toString();
    }
    if (cookie) {
      headers['Cookie'] = cookie;
    }

    const req = http.request(
      { hostname: '127.0.0.1', port: addr.port, path, method, headers },
      (res) => {
        let resBody = '';
        res.on('data', (chunk) => (resBody += chunk));
        res.on('end', () => {
          const setCookie = res.headers['set-cookie']?.[0]?.split(';')[0];
          resolve({
            status: res.statusCode!,
            headers: res.headers,
            body: resBody,
            cookie: setCookie,
          });
        });
      },
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ---- Tests ----

describe('Aegis Integration Tests', () => {
  let authenticator: Authenticator<TestUser>;
  let app: express.Express;
  let server: http.Server;

  before(() => {
    authenticator = new Authenticator<TestUser>();

    authenticator.serializeUser((user, done) => {
      done(null, user.id);
    });

    authenticator.deserializeUser((id, done) => {
      const user = USERS.find((u) => u.id === id);
      done(null, user || false);
    });

    authenticator.use(
      new LocalStrategy<TestUser>((username, password, done) => {
        const user = findUser(username, password);
        if (!user) return done(null, false, { message: 'Invalid credentials' });
        done(null, user);
      }),
    );

    app = createApp(authenticator);

    // Routes
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    app.post('/login', authenticator.authenticate('local', {
      successRedirect: '/profile',
      failureRedirect: '/login-failed',
    }) as any);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    app.post('/login-json', authenticator.authenticate('local') as any, (req, res) => {
      res.json({ user: (req as unknown as AegisRequest).user });
    });

    app.get('/profile', (req, res) => {
      const aegisReq = req as unknown as AegisRequest;
      if (aegisReq.isAuthenticated()) {
        res.json({ user: aegisReq.user });
      } else {
        res.status(401).json({ error: 'Not authenticated' });
      }
    });

    app.post('/logout', (req, res) => {
      const aegisReq = req as unknown as AegisRequest;
      aegisReq.logout((err) => {
        if (err) return res.status(500).json({ error: 'Logout failed' });
        res.json({ ok: true });
      });
    });

    server = app.listen(0);
  });

  after(() => {
    server.close();
  });

  describe('LocalStrategy', () => {
    it('should authenticate with valid credentials and redirect on success', async () => {
      const res = await request(server, 'POST', '/login', {
        username: 'alice',
        password: 'secret',
      });
      assert.equal(res.status, 302);
      assert.equal(res.headers.location, '/profile');
      assert.ok(res.cookie, 'Should set session cookie');
    });

    it('should redirect on failure with invalid credentials', async () => {
      const res = await request(server, 'POST', '/login', {
        username: 'alice',
        password: 'wrong',
      });
      assert.equal(res.status, 302);
      assert.equal(res.headers.location, '/login-failed');
    });

    it('should fail with missing credentials', async () => {
      const res = await request(server, 'POST', '/login-json', {});
      assert.equal(res.status, 400);
    });

    it('should return user on successful auth without redirect', async () => {
      const res = await request(server, 'POST', '/login-json', {
        username: 'bob',
        password: 'secret',
      });
      assert.equal(res.status, 200);
      const body = JSON.parse(res.body);
      assert.equal(body.user.username, 'bob');
      assert.equal(body.user.id, 2);
    });
  });

  describe('Session serialize/deserialize round-trip', () => {
    it('should persist authentication across requests via session', async () => {
      // Login
      const loginRes = await request(server, 'POST', '/login', {
        username: 'alice',
        password: 'secret',
      });
      assert.equal(loginRes.status, 302);
      const sessionCookie = loginRes.cookie!;

      // Access profile with session cookie
      const profileRes = await request(server, 'GET', '/profile', undefined, sessionCookie);
      assert.equal(profileRes.status, 200);
      const body = JSON.parse(profileRes.body);
      assert.equal(body.user.username, 'alice');
      assert.equal(body.user.id, 1);
    });
  });

  describe('req.isAuthenticated / req.isUnauthenticated', () => {
    it('should return false when not authenticated', async () => {
      const res = await request(server, 'GET', '/profile');
      assert.equal(res.status, 401);
      const body = JSON.parse(res.body);
      assert.equal(body.error, 'Not authenticated');
    });

    it('should return true after successful login', async () => {
      const loginRes = await request(server, 'POST', '/login', {
        username: 'alice',
        password: 'secret',
      });
      const profileRes = await request(
        server,
        'GET',
        '/profile',
        undefined,
        loginRes.cookie!,
      );
      assert.equal(profileRes.status, 200);
    });
  });

  describe('req.login / req.logout', () => {
    it('should logout and clear session', async () => {
      // Login first
      const loginRes = await request(server, 'POST', '/login', {
        username: 'alice',
        password: 'secret',
      });
      const sessionCookie = loginRes.cookie!;

      // Verify authenticated
      const profileRes1 = await request(server, 'GET', '/profile', undefined, sessionCookie);
      assert.equal(profileRes1.status, 200);

      // Logout
      const logoutRes = await request(server, 'POST', '/logout', {}, sessionCookie);
      assert.equal(logoutRes.status, 200);
      assert.deepEqual(JSON.parse(logoutRes.body), { ok: true });

      // Verify no longer authenticated
      const profileRes2 = await request(server, 'GET', '/profile', undefined, sessionCookie);
      assert.equal(profileRes2.status, 401);
    });
  });

  describe('authenticate with successRedirect/failureRedirect', () => {
    it('should redirect to successRedirect on success', async () => {
      const res = await request(server, 'POST', '/login', {
        username: 'alice',
        password: 'secret',
      });
      assert.equal(res.status, 302);
      assert.equal(res.headers.location, '/profile');
    });

    it('should redirect to failureRedirect on failure', async () => {
      const res = await request(server, 'POST', '/login', {
        username: 'alice',
        password: 'wrong',
      });
      assert.equal(res.status, 302);
      assert.equal(res.headers.location, '/login-failed');
    });
  });

  describe('async/await verify function', () => {
    it('should work with async verify', async () => {
      const auth2 = new Authenticator<TestUser>();
      auth2.serializeUser(async (user) => user.id);
      auth2.deserializeUser(async (id) => USERS.find((u) => u.id === id) || false);

      auth2.use(
        new LocalStrategy<TestUser>(async (username, password) => {
          return findUser(username, password) || false;
        }),
      );

      const app2 = createApp(auth2);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      app2.post('/login', auth2.authenticate('local') as any, (req, res) => {
        res.json({ user: (req as unknown as AegisRequest).user });
      });

      const server2 = app2.listen(0);
      try {
        const res = await request(server2, 'POST', '/login', {
          username: 'alice',
          password: 'secret',
        });
        assert.equal(res.status, 200);
        const body = JSON.parse(res.body);
        assert.equal(body.user.username, 'alice');
      } finally {
        server2.close();
      }
    });
  });

  describe('callback-style verify function', () => {
    it('should work with callback-style verify', async () => {
      const auth3 = new Authenticator<TestUser>();
      auth3.serializeUser((user: TestUser, done: DoneCallback<number>) => done(null, user.id));
      auth3.deserializeUser((id: string | number, done: DoneCallback<TestUser>) => {
        const user = USERS.find((u) => u.id === id);
        done(null, user || false);
      });

      auth3.use(
        new LocalStrategy<TestUser>(
          (username: string, password: string, done: DoneCallback<TestUser>) => {
            const user = findUser(username, password);
            if (!user) return done(null, false, { message: 'Bad creds' });
            done(null, user);
          },
        ),
      );

      const app3 = createApp(auth3);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      app3.post('/login', auth3.authenticate('local') as any, (req, res) => {
        res.json({ user: (req as unknown as AegisRequest).user });
      });

      const server3 = app3.listen(0);
      try {
        const res = await request(server3, 'POST', '/login', {
          username: 'bob',
          password: 'secret',
        });
        assert.equal(res.status, 200);
        const body = JSON.parse(res.body);
        assert.equal(body.user.username, 'bob');
      } finally {
        server3.close();
      }
    });
  });

  describe('custom callback', () => {
    it('should call custom callback with user on success', async () => {
      const auth4 = new Authenticator<TestUser>();
      auth4.serializeUser(async (user) => user.id);
      auth4.deserializeUser(async (id) => USERS.find((u) => u.id === id) || false);
      auth4.use(
        new LocalStrategy<TestUser>(async (username, password) => {
          return findUser(username, password) || false;
        }),
      );

      const app4 = createApp(auth4);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      app4.post('/login', (req: any, res: any, next: any) => {
        (auth4.authenticate('local', {}, (err: unknown, user: unknown, info: unknown) => {
          if (err) return next(err);
          if (!user) return res.status(401).json({ error: 'fail', info });
          res.json({ custom: true, user });
        }) as any)(req, res, next);
      });

      const server4 = app4.listen(0);
      try {
        const res = await request(server4, 'POST', '/login', {
          username: 'alice',
          password: 'secret',
        });
        assert.equal(res.status, 200);
        const body = JSON.parse(res.body);
        assert.equal(body.custom, true);
        assert.equal(body.user.username, 'alice');
      } finally {
        server4.close();
      }
    });
  });

  describe('Strategy base class', () => {
    it('should allow custom strategies', async () => {
      class AlwaysPassStrategy extends Strategy {
        name = 'always-pass';
        authenticate(_req: AegisRequest): void {
          this.success({ id: 99, username: 'auto' });
        }
      }

      const auth5 = new Authenticator<TestUser>();
      auth5.serializeUser(async (user) => user.id);
      auth5.deserializeUser(async () => ({ id: 99, username: 'auto' }));
      auth5.use(new AlwaysPassStrategy());

      const app5 = createApp(auth5);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      app5.get('/auto', auth5.authenticate('always-pass') as any, (req, res) => {
        res.json({ user: (req as unknown as AegisRequest).user });
      });

      const server5 = app5.listen(0);
      try {
        const res = await request(server5, 'GET', '/auto');
        assert.equal(res.status, 200);
        const body = JSON.parse(res.body);
        assert.equal(body.user.username, 'auto');
      } finally {
        server5.close();
      }
    });
  });

  describe('Error handling', () => {
    it('should return error for unknown strategy', async () => {
      const auth6 = new Authenticator();
      const app6 = express();
      app6.use(express.json());
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      app6.use(auth6.initialize() as any);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      app6.post('/login', auth6.authenticate('nonexistent') as any);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      app6.use((err: any, _req: any, res: any, _next: any) => {
        res.status(500).json({ error: err.message });
      });

      const server6 = app6.listen(0);
      try {
        const res = await request(server6, 'POST', '/login', {
          username: 'alice',
          password: 'secret',
        });
        assert.equal(res.status, 500);
        assert.ok(JSON.parse(res.body).error.includes('nonexistent'));
      } finally {
        server6.close();
      }
    });

    it('AuthenticationError should have status property', () => {
      const err = new AuthenticationError('test error', 403);
      assert.equal(err.message, 'test error');
      assert.equal(err.status, 403);
      assert.equal(err.name, 'AuthenticationError');
      assert.ok(err instanceof Error);
    });
  });

  describe('Authenticator use/unuse', () => {
    it('should register and unregister strategies', () => {
      const auth = new Authenticator();
      const strategy = new LocalStrategy(async () => false);
      auth.use(strategy);
      assert.ok(auth._strategy('local'));
      auth.unuse('local');
      assert.equal(auth._strategy('local'), undefined);
    });

    it('should accept name override', () => {
      const auth = new Authenticator();
      const strategy = new LocalStrategy(async () => false);
      auth.use('my-local', strategy);
      assert.ok(auth._strategy('my-local'));
      assert.equal(auth._strategy('local'), undefined);
    });
  });

  describe('LocalStrategy options', () => {
    it('should support custom field names', async () => {
      const auth = new Authenticator<TestUser>();
      auth.serializeUser(async (user) => user.id);
      auth.deserializeUser(async (id) => USERS.find((u) => u.id === id) || false);

      auth.use(
        new LocalStrategy<TestUser>(
          { usernameField: 'email', passwordField: 'pass' },
          async (email, pass) => {
            // In this test, treat email as username
            return findUser(email, pass) || false;
          },
        ),
      );

      const app7 = createApp(auth);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      app7.post('/login', auth.authenticate('local') as any, (req, res) => {
        res.json({ user: (req as unknown as AegisRequest).user });
      });

      const server7 = app7.listen(0);
      try {
        const res = await request(server7, 'POST', '/login', {
          email: 'alice',
          pass: 'secret',
        });
        assert.equal(res.status, 200);
        const body = JSON.parse(res.body);
        assert.equal(body.user.username, 'alice');
      } finally {
        server7.close();
      }
    });
  });
});
