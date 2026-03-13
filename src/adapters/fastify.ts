/**
 * Fastify adapter for aegis.
 *
 * Wraps aegis middleware to work with Fastify's request/reply interface.
 * Fastify uses `request.raw` for the underlying Node.js IncomingMessage.
 */
import type { AegisRequest, AegisResponse, NextFunction, Middleware } from '../types.js';

export { Authenticator } from '../authenticator.js';

export interface FastifyRequest {
  raw: AegisRequest;
  body?: unknown;
  session?: Record<string, unknown>;
}

export interface FastifyReply {
  raw: AegisResponse;
  code: (statusCode: number) => FastifyReply;
  send: (payload?: unknown) => FastifyReply;
  redirect: (url: string, code?: number) => FastifyReply;
}

/**
 * Convert an aegis (Express-style) middleware into a Fastify-compatible hook.
 *
 * Usage:
 *   import { toFastifyHook } from '@agentine/aegis/adapters/fastify';
 *   fastify.addHook('preHandler', toFastifyHook(authenticator.initialize()));
 *   fastify.addHook('preHandler', toFastifyHook(authenticator.session()));
 */
export function toFastifyHook(
  middleware: Middleware,
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  return (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    return new Promise<void>((resolve, reject) => {
      const req = request.raw as AegisRequest;

      // Proxy body and session from Fastify request to raw request.
      if (request.body !== undefined) {
        (req as unknown as { body: unknown }).body = request.body;
      }
      if (request.session) {
        (req as unknown as Record<string, unknown>).session = request.session;
      }

      const res = reply.raw;
      const next: NextFunction = (err?: Error | 'route') => {
        if (err) return reject(err instanceof Error ? err : new Error(String(err)));
        resolve();
      };

      middleware(req, res, next);
    });
  };
}
