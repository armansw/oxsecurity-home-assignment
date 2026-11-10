import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    pool: 'forks',
    testTimeout: 20_000,
    hookTimeout: 20_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // Entry points are exercised by the OOM harness / e2e run, not unit tests.
      exclude: ['src/index.ts', 'src/scripts/**'],
      reporter: ['text', 'html', 'json-summary'],
      thresholds: { lines: 95, functions: 95, statements: 95, branches: 90 },
    },
  },
});
