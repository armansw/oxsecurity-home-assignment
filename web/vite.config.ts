import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const BACKEND = process.env.BACKEND_URL ?? 'http://localhost:3000';
const proxy = {
  '/api': { target: BACKEND, changeOrigin: true },
  '/graphql': { target: BACKEND, changeOrigin: true },
};

export default defineConfig({
  plugins: [react()],
  // Same proxy for `vite` (dev) and `vite preview` (the production build, used by ../run.sh).
  server: { proxy },
  preview: { proxy },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    restoreMocks: true,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/main.tsx', 'src/vite-env.d.ts', 'src/test/**', 'src/**/*.test.{ts,tsx}'],
      reporter: ['text', 'html'],
      thresholds: { statements: 90, branches: 90, functions: 90, lines: 90 },
    },
  },
});
