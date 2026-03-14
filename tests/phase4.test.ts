import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { Authenticator, LocalStrategy, OAuth2Strategy } from '../src/index.js';
import type { AegisRequest, AegisResponse, NextFunction, AuthenticateOptions } from '../src/index.js';
import { IncomingMessage, ServerResponse } from 'node:http';

function createMockReq(body?: Record<string, string>): AegisRequest {
  const req = Object.create(IncomingMessage.prototype) as AegisRequest;
  req.headers = { host: 'localhost' };
  req.url = '/login';
  (req as unknown as { body: Record<string, string> | undefined }).body = body;
  req.session = { passport: {} };
  return req;
}

function createMockRes(): AegisResponse & { _status?: number; _headers?: Record<string, string>; _body?: string } {
  const res = Object.create(ServerResponse.prototype) as AegisResponse & { _status?: number; _headers?: Record<string, string>; _body?: string };
  res.writeHead = ((status: number, headers?: Record<string, string>) => {
    res._status = status;
    res._headers = headers;
    return res;
  }) as unknown as typeof res.writeHead;
  res.end = ((body?: string) => {
    res._body = body;
    return res;
  }) as unknown as typeof res.end;
  return res;
}

describe('passReqToCallback — LocalStrategy', () => {
  it('should pass req as first argument when passReqToCallback is true', async () => {
    const auth = new Authenticator();
    auth.serializeUser(async () => '1');
    auth.deserializeUser(async () => ({ id: '1' }));

    let receivedReq: unknown;

    auth.use(
      new LocalStrategy(
        { passReqToCallback: true },
        async (req: unknown, username: unknown, password: unknown) => {
          receivedReq = req;
          if (username === 'admin' && password === 'pass') return { id: '1' };
          return false;
        },
      ),
    );

    const initMw = auth.initialize();
    const authMw = auth.authenticate('local', { session: false });

    const req = createMockReq({ username: 'admin', password: 'pass' });
    const res = createMockRes();
    initMw(req, res, () => {});

    await new Promise<void>((resolve) => {
      authMw(req, res, (() => resolve()) as NextFunction);
    });

    assert.strictEqual(receivedReq, req, 'req should be passed as first argument');
  });

  it('should NOT pass req when passReqToCallback is false', async () => {
    const auth = new Authenticator();
    auth.serializeUser(async () => '1');
    auth.deserializeUser(async () => ({ id: '1' }));

    let firstArg: unknown;

    auth.use(
      new LocalStrategy(async (username: string, password: string) => {
        firstArg = username;
        if (username === 'admin' && password === 'pass') return { id: '1' };
        return false;
      }),
    );

    const initMw = auth.initialize();
    const authMw = auth.authenticate('local', { session: false });

    const req = createMockReq({ username: 'admin', password: 'pass' });
    const res = createMockRes();
    initMw(req, res, () => {});

    await new Promise<void>((resolve) => {
      authMw(req, res, (() => resolve()) as NextFunction);
    });

    assert.strictEqual(firstArg, 'admin', 'first arg should be username, not req');
  });

  it('should pass req with callback-style verify', async () => {
    const auth = new Authenticator();
    auth.serializeUser(async () => '1');
    auth.deserializeUser(async () => ({ id: '1' }));

    let receivedReq: unknown;

    auth.use(
      new LocalStrategy(
        { passReqToCallback: true },
        (req: unknown, username: unknown, password: unknown, done: Function) => {
          receivedReq = req;
          if (username === 'admin' && password === 'pass') {
            done(null, { id: '1' });
          } else {
            done(null, false);
          }
        },
      ),
    );

    const initMw = auth.initialize();
    const authMw = auth.authenticate('local', { session: false });

    const req = createMockReq({ username: 'admin', password: 'pass' });
    const res = createMockRes();
    initMw(req, res, () => {});

    await new Promise<void>((resolve) => {
      authMw(req, res, (() => resolve()) as NextFunction);
    });

    assert.strictEqual(receivedReq, req);
  });
});

describe('failureFlash and successFlash', () => {
  it('should call req.flash on failure when failureFlash is set', async () => {
    const auth = new Authenticator();
    auth.serializeUser(async () => '1');
    auth.deserializeUser(async () => null);

    auth.use(
      new LocalStrategy(async () => false),
    );

    const initMw = auth.initialize();
    const authMw = auth.authenticate('local', {
      failureFlash: true,
      failureRedirect: '/login',
    });

    const req = createMockReq({ username: 'admin', password: 'wrong' });
    const res = createMockRes();

    const flashCalls: [string, string][] = [];
    (req as unknown as { flash: Function }).flash = (type: string, msg: string) => {
      flashCalls.push([type, msg]);
    };

    initMw(req, res, () => {});
    await new Promise<void>((resolve) => {
      authMw(req, res, (() => resolve()) as NextFunction);
      // flash + redirect happens synchronously after async verify resolves
      setTimeout(resolve, 50);
    });

    assert.ok(flashCalls.length > 0, 'flash should have been called');
    assert.strictEqual(flashCalls[0][0], 'error');
  });

  it('should use custom flash message string', async () => {
    const auth = new Authenticator();
    auth.serializeUser(async () => '1');
    auth.deserializeUser(async () => null);

    auth.use(new LocalStrategy(async () => false));

    const initMw = auth.initialize();
    const authMw = auth.authenticate('local', {
      failureFlash: 'Wrong credentials!',
      failureRedirect: '/login',
    });

    const req = createMockReq({ username: 'admin', password: 'wrong' });
    const res = createMockRes();

    const flashCalls: [string, string][] = [];
    (req as unknown as { flash: Function }).flash = (type: string, msg: string) => {
      flashCalls.push([type, msg]);
    };

    initMw(req, res, () => {});
    await new Promise<void>((resolve) => {
      authMw(req, res, (() => resolve()) as NextFunction);
      setTimeout(resolve, 50);
    });

    assert.ok(flashCalls.length > 0);
    assert.deepStrictEqual(flashCalls[0], ['error', 'Wrong credentials!']);
  });

  it('should call req.flash on success when successFlash is set', async () => {
    const auth = new Authenticator();
    auth.serializeUser(async () => '1');
    auth.deserializeUser(async () => ({ id: '1' }));

    auth.use(
      new LocalStrategy(async (username: string, password: string) => {
        if (username === 'admin' && password === 'pass') return { id: '1' };
        return false;
      }),
    );

    const initMw = auth.initialize();
    const authMw = auth.authenticate('local', {
      session: false,
      successFlash: 'Welcome back!',
    });

    const req = createMockReq({ username: 'admin', password: 'pass' });
    const res = createMockRes();

    const flashCalls: [string, string][] = [];
    (req as unknown as { flash: Function }).flash = (type: string, msg: string) => {
      flashCalls.push([type, msg]);
    };

    initMw(req, res, () => {});
    await new Promise<void>((resolve) => {
      authMw(req, res, (() => resolve()) as NextFunction);
    });

    assert.ok(flashCalls.length > 0);
    assert.deepStrictEqual(flashCalls[0], ['success', 'Welcome back!']);
  });
});

describe('failureMessage and successMessage', () => {
  it('should store failure message in session', async () => {
    const auth = new Authenticator();
    auth.serializeUser(async () => '1');
    auth.deserializeUser(async () => null);

    auth.use(new LocalStrategy(async () => false));

    const initMw = auth.initialize();
    const authMw = auth.authenticate('local', {
      failureMessage: 'Bad login',
      failureRedirect: '/login',
    });

    const req = createMockReq({ username: 'admin', password: 'wrong' });
    const res = createMockRes();

    initMw(req, res, () => {});
    await new Promise<void>((resolve) => {
      authMw(req, res, (() => resolve()) as NextFunction);
      setTimeout(resolve, 50);
    });

    const messages = (req.session as Record<string, unknown>).messages as string[];
    assert.ok(messages);
    assert.ok(messages.includes('Bad login'));
  });

  it('should store success message in session', async () => {
    const auth = new Authenticator();
    auth.serializeUser(async () => '1');
    auth.deserializeUser(async () => ({ id: '1' }));

    auth.use(
      new LocalStrategy(async (username: string, password: string) => {
        if (username === 'admin' && password === 'pass') return { id: '1' };
        return false;
      }),
    );

    const initMw = auth.initialize();
    const authMw = auth.authenticate('local', {
      session: false,
      successMessage: 'Logged in successfully',
    });

    const req = createMockReq({ username: 'admin', password: 'pass' });
    const res = createMockRes();

    initMw(req, res, () => {});
    await new Promise<void>((resolve) => {
      authMw(req, res, (() => resolve()) as NextFunction);
    });

    const messages = (req.session as Record<string, unknown>).messages as string[];
    assert.ok(messages);
    assert.ok(messages.includes('Logged in successfully'));
  });
});
