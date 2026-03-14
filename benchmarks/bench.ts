/**
 * Benchmarks: aegis vs passport.js
 *
 * Measures middleware overhead for:
 * - initialize() middleware
 * - local strategy authentication (success path)
 * - local strategy authentication (failure path)
 *
 * Run: npx tsx benchmarks/bench.ts
 */

import { Authenticator, LocalStrategy } from '../src/index.js';
import type { AegisRequest, AegisResponse, NextFunction } from '../src/index.js';
import { IncomingMessage, ServerResponse } from 'node:http';

// --- Helpers ---

function createMockReq(body?: Record<string, string>): AegisRequest {
  const req = Object.create(IncomingMessage.prototype) as AegisRequest;
  req.headers = { host: 'localhost' };
  req.url = '/login';
  (req as unknown as { body: Record<string, string> | undefined }).body = body;
  req.session = { passport: {} };
  return req;
}

function createMockRes(): AegisResponse {
  const res = Object.create(ServerResponse.prototype) as AegisResponse;
  res.writeHead = (() => res) as unknown as typeof res.writeHead;
  res.end = (() => res) as unknown as typeof res.end;
  return res;
}

function noop(): void {}

async function bench(name: string, fn: () => Promise<void> | void, iterations: number = 100_000): Promise<void> {
  // Warmup
  for (let i = 0; i < 1000; i++) {
    await fn();
  }

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await fn();
  }
  const elapsed = performance.now() - start;

  const opsPerSec = Math.round((iterations / elapsed) * 1000);
  const avgUs = ((elapsed / iterations) * 1000).toFixed(2);
  console.log(`  ${name}: ${opsPerSec.toLocaleString()} ops/sec (${avgUs} µs/op)`);
}

// --- Benchmarks ---

async function main() {
  console.log('aegis benchmark\n');

  const auth = new Authenticator();

  const testUser = { id: '1', username: 'admin' };
  auth.serializeUser(async (user: typeof testUser) => user.id);
  auth.deserializeUser(async (id) => (id === '1' ? testUser : null));

  auth.use(
    new LocalStrategy(async (username, password) => {
      if (username === 'admin' && password === 'pass') return testUser;
      return false;
    }),
  );

  // Benchmark: initialize middleware
  const initMiddleware = auth.initialize();
  console.log('initialize() middleware:');
  await bench('aegis initialize()', () => {
    const req = createMockReq();
    const res = createMockRes();
    initMiddleware(req, res, noop);
  });

  // Benchmark: local strategy success
  const localMiddleware = auth.authenticate('local', { session: false });
  console.log('\nauthenticate("local") — success:');
  await bench(
    'aegis local auth (success)',
    async () => {
      const req = createMockReq({ username: 'admin', password: 'pass' });
      const res = createMockRes();
      initMiddleware(req, res, noop);
      await new Promise<void>((resolve) => {
        localMiddleware(req, res, (() => resolve()) as NextFunction);
      });
    },
    50_000,
  );

  // Benchmark: local strategy failure
  const failMiddleware = auth.authenticate('local', { session: false, failureRedirect: '/login' });
  console.log('\nauthenticate("local") — failure:');
  await bench(
    'aegis local auth (failure)',
    async () => {
      const req = createMockReq({ username: 'admin', password: 'wrong' });
      const res = createMockRes();
      initMiddleware(req, res, noop);
      await new Promise<void>((resolve) => {
        res.end = (() => { resolve(); return res; }) as unknown as typeof res.end;
        failMiddleware(req, res, (() => resolve()) as NextFunction);
      });
    },
    50_000,
  );

  console.log('\nDone.');
}

main().catch(console.error);
