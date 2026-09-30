// The browser page's test (web/test). It serves web/dist, which
// web/build.sh makes, with web/serve.mjs, and runs in Chromium.
//
//   web/build.sh && (cd web && npm ci && npx playwright install chromium && npx playwright test)
//
// SCREENSHOT_DIR names where the screenshots go (default
// web/test-results/screenshots).
import { defineConfig } from '@playwright/test';

const port = Number(process.env.PORT || 8788);

export default defineConfig({
  testDir: 'test',
  timeout: 120_000,
  reporter: 'list',
  outputDir: 'test-results/output',
  use: {
    baseURL: `http://127.0.0.1:${port}/`,
    browserName: 'chromium',
    viewport: { width: 1280, height: 900 },
  },
  webServer: {
    command: `node serve.mjs --port ${port}`,
    url: `http://127.0.0.1:${port}/`,
    reuseExistingServer: false,
  },
});
