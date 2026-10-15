import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['node_modules/**', 'dist/**', 'fixtures/**'],
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
