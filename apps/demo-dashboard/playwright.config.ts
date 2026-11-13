import { defineConfig } from '@playwright/test';

/** The dashboard served from dist/ by the real host (firewall, tool server, sandboxed agent). */
export const E2E_PORT = 5199;
export const E2E_TOKEN = 'e2e-session-token-0123456789abcdef';

export default defineConfig({
  testDir: 'e2e',
  timeout: 240_000,
  expect: { timeout: 60_000 },
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: `http://localhost:${E2E_PORT}`,
    // RECORD=1 keeps a video of the run, usable as the demo recording.
    video: process.env['RECORD'] === '1' ? 'on' : 'off',
    viewport: { width: 1440, height: 1000 },
  },
  webServer: {
    command: `node src/server/main.ts --port=${E2E_PORT}`,
    url: `http://localhost:${E2E_PORT}/`,
    env: { ZKIF_SESSION_TOKEN: E2E_TOKEN },
    timeout: 120_000,
    reuseExistingServer: false,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
