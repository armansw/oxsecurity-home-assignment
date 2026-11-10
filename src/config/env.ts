import os from 'node:os';
import path from 'node:path';
import { z } from 'zod';

const int = (def: number, min = 0) => z.coerce.number().int().min(min).default(def);

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  HOST: z.string().default('0.0.0.0'),
  PORT: int(3000, 0).pipe(z.number().max(65_535)),
  /** all = API + worker in one process (default, so `node dist/index.js` is a complete system). */
  ROLE: z.enum(['all', 'api', 'worker']).default('all'),
  /**
   * Which proxies may set X-Forwarded-For (client IP for rate limiting). `false` (default) when the port is
   * exposed directly; `true` or an address list such as `loopback` / `127.0.0.1` behind a reverse proxy.
   */
  TRUST_PROXY: z
    .string()
    .default('false')
    .transform((v): boolean | string => (v === 'true' ? true : v === 'false' ? false : v)),

  DATABASE_PATH: z.string().min(1).default('./data/code-guardian.db'),
  /** Must be disk-backed. A tmpfs workspace charges the report to the memory cgroup (docs/MEMORY.md). */
  WORK_DIR: z.string().min(1).default(path.join(os.tmpdir(), 'code-guardian')),

  SCANNER: z.enum(['trivy', 'fixture']).default('trivy'),
  TRIVY_BIN: z.string().min(1).default('trivy'),
  TRIVY_SERVER_URL: z.url().optional(),
  TRIVY_TOKEN: z.string().optional(),
  TRIVY_CACHE_DIR: z.string().optional(),
  /** Go soft heap limit for the Trivy child process. */
  TRIVY_GOMEMLIMIT: z.string().regex(/^\d+(B|KiB|MiB|GiB)$/).default('64MiB'),
  GIT_BIN: z.string().min(1).default('git'),
  CLONE_TIMEOUT_MS: int(300_000, 1000),
  SCAN_TIMEOUT_MS: int(1_200_000, 1000),
  ALLOWED_GIT_HOSTS: z
    .string()
    .default('github.com')
    .transform((s) => s.split(',').map((h) => h.trim().toLowerCase()).filter((h) => h.length > 0))
    .pipe(z.array(z.string()).min(1)),

  MAX_ATTEMPTS: int(3, 1),
  MAX_QUEUED: int(100, 1),
  /** Opt-in deduplication of identical active scans (default off: every POST creates a new Queued scan). */
  DEDUPE_ACTIVE_SCANS: z.enum(['true', 'false']).default('false').transform((v) => v === 'true'),
  WORKER_CONCURRENCY: int(1, 1),
  WORKER_POLL_MS: int(500, 10),
  HEARTBEAT_MS: int(5000, 10),
  STALE_AFTER_MS: int(60_000, 100),
  RETRY_BASE_MS: int(5000, 0),
  SHUTDOWN_GRACE_MS: int(10_000, 0),
  MIN_FREE_DISK_MB: int(1024, 0),
  BATCH_SIZE: int(500, 1),
  RESPONSE_PAGE_SIZE: int(500, 1),
  /** Upper bound for a single JSON string/number in the report — bounds parser memory on hostile input. */
  MAX_JSON_VALUE_BYTES: int(1024 * 1024, 1024),
  SCAN_TTL_HOURS: int(168, 1),
  RATE_LIMIT_PER_MIN: int(30, 1),

  FIXTURE_SIZE_MB: int(600, 1),
  FIXTURE_CRITICAL_RATIO: z.coerce.number().min(0).max(1).default(0.05),
});

export type Env = z.infer<typeof EnvSchema>;

export interface Config extends Env {
  readonly trivyCacheDir: string;
}

/** Parse and validate the environment once at boot; any invalid value aborts startup with a clear message. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration: ${issues}`);
  }
  const e = parsed.data;
  return Object.freeze({ ...e, trivyCacheDir: e.TRIVY_CACHE_DIR ?? path.join(e.WORK_DIR, '.trivy-cache') });
}
