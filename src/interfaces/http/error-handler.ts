import type { FastifyError, FastifyInstance } from 'fastify';
import { ZodError } from 'zod';
import { RequestError, type RequestErrorCode } from '../../domain/errors.js';

export interface ErrorBody {
  readonly error: { readonly code: string; readonly message: string; readonly details?: readonly string[] };
}

/** HTTP status per request error code, shared by REST and GraphQL (`extensions.status`). */
export const REQUEST_ERROR_STATUS: Record<RequestErrorCode, number> = {
  INVALID_REPO_URL: 400,
  INVALID_SCAN_ID: 400,
  INVALID_CURSOR: 400,
  NOT_FOUND: 404,
  QUEUE_FULL: 429,
  NOT_READY: 503,
  TEST_RUN_ACTIVE: 409,
  INVALID_TEST_RUN: 400,
};

/**
 * One error envelope for the whole REST API: `{ "error": { "code", "message" } }`. Expected errors keep their
 * message; unexpected ones return a generic 500 and are logged with full detail server-side only.
 */
export function registerErrorHandling(app: FastifyInstance): void {
  app.setErrorHandler<FastifyError | Error>((err, request, reply) => {
    if (err instanceof RequestError) {
      const status = REQUEST_ERROR_STATUS[err.code];
      if (err.code === 'QUEUE_FULL') void reply.header('retry-after', '30');
      return reply.code(status).send(body(err.code, err.message));
    }
    if (err instanceof ZodError) {
      const details = err.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`);
      return reply.code(400).send({ error: { code: 'VALIDATION_ERROR', message: 'Request is invalid', details } } satisfies ErrorBody);
    }
    const statusCode = 'statusCode' in err && typeof err.statusCode === 'number' ? err.statusCode : 500;
    if (statusCode === 429) return reply.code(429).send(body('RATE_LIMITED', 'Too many requests; slow down'));
    if (statusCode >= 400 && statusCode < 500) {
      const code = 'code' in err && typeof err.code === 'string' ? err.code.replace(/^FST_ERR_/, '') : 'BAD_REQUEST';
      return reply.code(statusCode).send(body(code, err.message));
    }
    request.log.error({ err }, 'unhandled error');
    return reply.code(500).send(body('INTERNAL', 'Internal server error'));
  });

  app.setNotFoundHandler((request, reply) => reply.code(404).send(body('ROUTE_NOT_FOUND', `Route ${request.method} ${request.url} not found`)));
}

function body(code: string, message: string): ErrorBody {
  return { error: { code, message } };
}
