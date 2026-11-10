import path from 'node:path';
import os from 'node:os';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/env.js';

describe('loadConfig', () => {
  it('applies safe defaults', () => {
    const c = loadConfig({});
    expect(c).toMatchObject({
      ROLE: 'all',
      PORT: 3000,
      SCANNER: 'trivy',
      MAX_ATTEMPTS: 3,
      WORKER_CONCURRENCY: 1,
      BATCH_SIZE: 500,
      ALLOWED_GIT_HOSTS: ['github.com'],
      TRIVY_GOMEMLIMIT: '64MiB',
      WORK_DIR: path.join(os.tmpdir(), 'code-guardian'),
    });
    expect(c.trivyCacheDir).toBe(path.join(c.WORK_DIR, '.trivy-cache'));
    expect(Object.isFrozen(c)).toBe(true);
  });

  it('coerces and validates values', () => {
    const c = loadConfig({
      PORT: '8080',
      ROLE: 'worker',
      ALLOWED_GIT_HOSTS: ' GitHub.com , gitlab.com ,',
      TRIVY_SERVER_URL: 'http://trivy:4954',
      TRIVY_CACHE_DIR: '/cache',
      FIXTURE_CRITICAL_RATIO: '0.5',
    });
    expect(c).toMatchObject({ PORT: 8080, ROLE: 'worker', ALLOWED_GIT_HOSTS: ['github.com', 'gitlab.com'], trivyCacheDir: '/cache', FIXTURE_CRITICAL_RATIO: 0.5 });
  });

  it.each([
    [{ PORT: '70000' }, 'PORT'],
    [{ ROLE: 'admin' }, 'ROLE'],
    [{ TRIVY_SERVER_URL: 'not a url' }, 'TRIVY_SERVER_URL'],
    [{ TRIVY_GOMEMLIMIT: '64M' }, 'TRIVY_GOMEMLIMIT'],
    [{ MAX_ATTEMPTS: '0' }, 'MAX_ATTEMPTS'],
    [{ ALLOWED_GIT_HOSTS: ' , ' }, 'ALLOWED_GIT_HOSTS'],
    [{ FIXTURE_CRITICAL_RATIO: '2' }, 'FIXTURE_CRITICAL_RATIO'],
  ])('rejects invalid configuration %o', (env, key) => {
    expect(() => loadConfig(env)).toThrow(new RegExp(`Invalid configuration: .*${key}`));
  });
});
