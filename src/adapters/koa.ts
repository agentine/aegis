/**
 * Koa adapter for aegis.
 *
 * Wraps aegis middleware to work with Koa's context-based interface.
 * Koa uses `ctx.req` / `ctx.res` for the underlying Node.js objects.
 */
import type { AegisRequest, AegisResponse, NextFunction, Middleware } from '../types.js';

export { Authenticator } from '../authenticator.js';

export interface KoaContext {
  req: AegisRequest;
  res: AegisResponse;
  request: { body?: unknown };
  session?: Record<string, unknown>;
  state: Record<string, unknown>;
}

/**
 * Convert an aegis (Express-style) middleware into Koa-compatible middleware.
 *
 * Usage:
 *   import { toKoaMiddleware } from '@agentine/aegis/adapters/koa';
 *   app.use(toKoaMiddleware(authenticator.initialize()));
 *   app.use(toKoaMiddleware(authenticator.session()));
 */
export function toKoaMiddleware(
  middleware: Middleware,
): (ctx: KoaContext, next: () => Promise<void>) => Promise<void> {
  return (ctx: KoaContext, koaNext: () => Promise<void>): Promise<void> => {
    return new Promise<void>((resolve, reject) => {
      const req = ctx.req as AegisRequest;

      // Proxy body and session from Koa context to raw request.
      if (ctx.request.body !== undefined) {
        (req as unknown as { body: unknown }).body = ctx.request.body;
      }
      if (ctx.session) {
        (req as unknown as Record<string, unknown>).session = ctx.session;
      }

      const res = ctx.res;
      const next: NextFunction = (err?: Error | 'route') => {
        if (err) return reject(err instanceof Error ? err : new Error(String(err)));
        // Sync user from req back to ctx.state for Koa convention.
        if (req.user) {
          ctx.state.user = req.user;
        }
        koaNext().then(resolve, reject);
      };

      middleware(req, res, next);
    });
  };
}
