import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Proving with Barretenberg's WASM build takes seconds and the integration tests start real
    // processes. Run files one at a time so they do not compete for threads.
    fileParallelism: false,
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
