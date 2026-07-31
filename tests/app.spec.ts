import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const systemDll = path.join(fixtures, 'shlwapi.dll');
const demoDll = path.join(fixtures, 'demo.dll');
const demoPdb = path.join(fixtures, 'demo.pdb');
const demoMap = path.join(fixtures, 'demo.map');

async function load(page: Page, files: string[]) {
  await page.goto('/');
  await page.setInputFiles('input[type=file]', files);
  await expect(page.locator('nav.tabs')).toBeVisible();
}

const tab = (page: Page, name: string) => page.locator(`nav.tabs button:has-text("${name}")`);

test.describe('landing', () => {
  test('renders the drop zone and privacy note', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'See inside a DLL' })).toBeVisible();
    await expect(page.locator('.dropzone')).toContainText('Drop your files here');
    await expect(page.locator('.privacy')).toContainText('never uploaded');
  });
});

test.describe('system DLL', () => {
  test.skip(!existsSync(systemDll), 'run `npm run fixtures` first');

  test('parses headers, sections, imports and exports', async ({ page }) => {
    await load(page, [systemDll]);

    // Overview
    await expect(page.locator('.section-title')).toContainText('shlwapi.dll');
    await expect(page.locator('.stat', { hasText: 'Architecture' })).toContainText('x64');
    await expect(page.locator('.stat', { hasText: 'Image base' })).toContainText('0x000180000000');

    // Memory map: bands for the standard sections, plus directory overlays.
    await tab(page, 'Memory Map').click();
    await expect(page.locator('.band', { hasText: '.text' })).toBeVisible();
    await expect(page.locator('.band', { hasText: '.rdata' })).toBeVisible();
    await expect(page.locator('.band', { hasText: 'PE Headers' })).toBeVisible();
    expect(await page.locator('.dirmark').count()).toBeGreaterThan(2);

    // Clicking a band pins its detail.
    await page.locator('.band', { hasText: '.rdata' }).first().click();
    await expect(page.locator('.detail-pane .section-title')).toHaveText('.rdata');
    await expect(page.locator('.detail-pane')).toContainText('Byte entropy across the section');

    // File layout exposes the signature / overlay region.
    await page.locator('.segmented button:has-text("File layout")').click();
    await expect(page.locator('.band', { hasText: '.text' })).toBeVisible();

    // Headers
    await tab(page, 'Headers').click();
    await expect(page.locator('.group-head', { hasText: 'DOS Header' })).toBeVisible();
    await expect(page.locator('.group-head', { hasText: 'Optional Header (PE32+)' })).toBeVisible();
    await expect(page.locator('.panel', { hasText: 'Data directories' })).toContainText('Import Table');

    // Imports
    await tab(page, 'Imports').click();
    await expect(page.locator('.group-head').first()).toBeVisible();
    await page.locator('.search input').first().fill('CreateFile');
    await expect(page.locator('table.grid td.mono', { hasText: 'CreateFile' }).first()).toBeVisible();

    // Exports
    await tab(page, 'Exports').click();
    await expect(page.locator('.stat', { hasText: 'Ordinal base' })).toBeVisible();
    await page.locator('.search input').first().fill('PathFindFileName');
    await expect(page.locator('table.grid td.mono').first()).toContainText('PathFindFileName');

    // Resources: version info must be fully decoded.
    await tab(page, 'Resources').click();
    await expect(page.locator('.panel', { hasText: 'Version information' })).toContainText('CompanyName');

    // Hex
    await tab(page, 'Hex').click();
    await expect(page.locator('.hex-row').first()).toBeVisible();
  });
});

test.describe('native DLL with symbols', () => {
  test.skip(!existsSync(demoDll) || !existsSync(demoPdb), 'run `npm run fixtures` first (needs MSVC)');

  test('resolves PDB symbols and disassembles x64 code', async ({ page }) => {
    await load(page, [demoDll, demoPdb]);

    // The PDB must be recognised as an exact match for this build.
    await expect(page.locator('.panel', { hasText: 'Build provenance' })).toContainText('matches this image exactly');

    await tab(page, 'Symbols').click();
    await expect(page.locator('table.grid')).toContainText('AddNumbers');
    await expect(page.locator('table.grid')).toContainText('SpinWidget');
    // C++ names are undecorated into something readable.
    await expect(page.locator('table.grid')).toContainText('demo::Widget::Spin');

    await tab(page, 'Disassembly').click();
    await expect(page.locator('.ins').first()).toBeVisible({ timeout: 30_000 });
    // x64 code must decode as x86-family mnemonics, not ARM.
    const mnemonics = await page.locator('.ins .m').allInnerTexts();
    expect(mnemonics.length).toBeGreaterThan(5);
    expect(mnemonics.some((m) => ['mov', 'push', 'sub', 'call', 'jmp', 'lea', 'ret', 'int3'].includes(m))).toBe(true);
  });

  test('accepts a linker .map file', async ({ page }) => {
    test.skip(!existsSync(demoMap), 'no .map fixture');
    await load(page, [demoDll, demoMap]);
    await tab(page, 'Symbols').click();
    await expect(page.locator('table.grid')).toContainText('AddNumbers');
  });
});

test.describe('error handling', () => {
  test('rejects a file that is not a PE image', async ({ page }) => {
    await page.goto('/');
    await page.setInputFiles('input[type=file]', {
      name: 'notes.dll',
      mimeType: 'application/octet-stream',
      buffer: Buffer.alloc(4096, 0x41),
    });
    await expect(page.locator('.banner.err')).toContainText('MZ');
  });
});
