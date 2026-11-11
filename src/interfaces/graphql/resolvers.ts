import mercurius from 'mercurius';
import { encodeCursor, type ScanService } from '../../application/scan.service.js';
import { RequestError } from '../../domain/errors.js';
import type { Scan } from '../../domain/scan.js';
import type { StoredVulnerability } from '../../domain/vulnerability.js';
import { toVulnerabilityDto, type VulnerabilityDto } from '../rest/scan.dto.js';
import { REQUEST_ERROR_STATUS } from '../http/error-handler.js';

interface ScanArgs {
  readonly id: string;
}
interface StartScanArgs {
  readonly repoUrl: string;
}
interface VulnerabilityArgs {
  readonly first?: number | null;
  readonly after?: string | null;
}

type VulnerabilityNode = VulnerabilityDto & { readonly cursor: string };


/** Map domain request errors to GraphQL errors with a stable `extensions.code`. */
function graphqlError(err: unknown): unknown {
  if (err instanceof RequestError) {
    return new mercurius.ErrorWithProps(err.message, { code: err.code }, REQUEST_ERROR_STATUS[err.code]);
  }
  return err;
}

async function guard<T>(fn: () => T | Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    throw graphqlError(err);
  }
}

// A type alias (not an interface) so it carries the implicit index signature mercurius' IResolvers requires.
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type ScanResolvers = {
  readonly Query: { scan(root: unknown, args: ScanArgs): Promise<Scan | null> };
  readonly Mutation: { startScan(root: unknown, args: StartScanArgs): Promise<Scan> };
  readonly Scan: {
    attempt(scan: Scan): number;
    criticalCount(scan: Scan): number | null;
    createdAt(scan: Scan): string;
    startedAt(scan: Scan): string | null;
    finishedAt(scan: Scan): string | null;
    error(scan: Scan): Scan['error'];
    criticalVulnerabilities(scan: Scan, args: VulnerabilityArgs): Promise<VulnerabilityNode[] | null>;
  };
};

/** Thin resolvers: every one delegates to the same ScanService the REST controller uses. */
export function buildResolvers(service: ScanService): ScanResolvers {
  return {
    Query: {
      scan: (_root: unknown, args: ScanArgs): Promise<Scan | null> =>
        guard(() => {
          try {
            return service.getScan(args.id);
          } catch (err) {
            if (err instanceof RequestError && err.code === 'NOT_FOUND') return null;
            throw err;
          }
        }),
    },
    Mutation: {
      startScan: (_root: unknown, args: StartScanArgs): Promise<Scan> => guard(async () => (await service.requestScan(args.repoUrl)).scan),
    },
    Scan: {
      attempt: (scan: Scan): number => scan.attempts,
      criticalCount: (scan: Scan): number | null => scan.stats?.criticalCount ?? null,
      createdAt: (scan: Scan): string => scan.createdAt.toISOString(),
      startedAt: (scan: Scan): string | null => scan.startedAt?.toISOString() ?? null,
      finishedAt: (scan: Scan): string | null => scan.finishedAt?.toISOString() ?? null,
      error: (scan: Scan): Scan['error'] => (scan.status === 'Failed' ? scan.error : null),
      criticalVulnerabilities: (scan: Scan, args: VulnerabilityArgs): Promise<VulnerabilityNode[] | null> =>
        guard(() => {
          const page = service.listCriticalVulnerabilities(scan, { limit: args.first ?? 100, cursor: args.after });
          return page === null ? null : page.items.map(toNode);
        }),
    },
  };
}

function toNode(v: StoredVulnerability): VulnerabilityNode {
  return { ...toVulnerabilityDto(v), cursor: encodeCursor(v.rowId) };
}
