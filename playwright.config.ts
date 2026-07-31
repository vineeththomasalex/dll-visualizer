import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  reporter: 'list',
  timeout: 60_000,
  use: {
    baseURL: 'http://localhost:4173/dll-visualizer/',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1500, height: 900 } } }],
  webServer: {
    command: 'npm run preview',
    url: 'http://localhost:4173/dll-visualizer/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
