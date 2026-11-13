import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Proving with Barretenberg's WASM build takes seconds, and each test file creates its own
    // backend. Run files one at a time so they do not compete for threads.
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
