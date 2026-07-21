import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, extname, join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const siteRoot = join(root, 'site');
const csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; script-src 'self'; connect-src 'self' https://formsubmit.co; form-action 'self' https://formsubmit.co; frame-ancestors 'none'; base-uri 'self'";
const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
};

let browser;
let origin;
let server;

function routePath(pathname) {
  if (pathname === '/') return 'index.html';
  if (pathname === '/ready/') return 'ready/index.html';
  if (pathname === '/download-form.js') return 'download-form.js';
  return null;
}

function formBodyContains(body, name, value) {
  return body.includes(`name="${name}"\r\n\r\n${value}`)
    || new URLSearchParams(body).get(name) === value;
}

function collectConsoleErrors(page) {
  const errors = [];
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  page.on('pageerror', (error) => errors.push(error.message));
  return errors;
}

async function fillLead(page, { name, email, role = '' }) {
  await page.getByLabel('Name').fill(name);
  await page.getByLabel('Work email').fill(email);
  if (role) await page.getByLabel(/Role/).selectOption(role);
}

async function fulfillNativeRedirect(route) {
  await route.fulfill({
    status: 303,
    headers: { location: `${origin}/ready/` },
  });
}

before(async () => {
  server = createServer(async (request, response) => {
    try {
      const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
      const relative = routePath(pathname);
      if (!relative) {
        response.writeHead(404).end('Not found');
        return;
      }
      const path = join(siteRoot, relative);
      const body = await readFile(path);
      response.writeHead(200, {
        'content-security-policy': csp,
        'content-type': mime[extname(path)] ?? 'application/octet-stream',
      });
      response.end(body);
    } catch {
      response.writeHead(500).end('Server error');
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  origin = `http://127.0.0.1:${address.port}`;

  const launchOptions = { headless: true };
  if (process.env.PLAYWRIGHT_EXECUTABLE_PATH) {
    launchOptions.executablePath = process.env.PLAYWRIGHT_EXECUTABLE_PATH;
  } else {
    launchOptions.channel = process.env.PLAYWRIGHT_CHANNEL ?? 'chrome';
  }
  browser = await chromium.launch(launchOptions);
});

after(async () => {
  if (browser) await browser.close();
  if (server) {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

test('native gate posts and redirects with JavaScript disabled under production CSP', async () => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  const consoleErrors = collectConsoleErrors(page);
  const scriptRequests = [];
  page.on('request', (request) => {
    if (request.url().endsWith('/download-form.js')) scriptRequests.push(request.url());
  });
  let submitted = '';
  await page.route('https://formsubmit.co/**', async (route) => {
    submitted = route.request().postData() ?? '';
    await fulfillNativeRedirect(route);
  });

  await page.goto(origin);
  const form = page.locator('#download-form');
  assert.deepEqual(scriptRequests, []);
  assert.equal(await form.getAttribute('action'), 'https://formsubmit.co/hello@powertruesystems.com');
  assert.equal(await form.getAttribute('method'), 'POST');
  assert.equal(
    await form.locator('input[name="_next"]').getAttribute('value'),
    'https://powertruesystems.com/aixray/ready/',
  );
  await fillLead(page, { name: 'No Script Admin', email: 'no-script@example.com' });
  await Promise.all([
    page.waitForURL(`${origin}/ready/`),
    page.getByLabel('Work email').press('Enter'),
  ]);

  assert.equal(formBodyContains(submitted, 'name', 'No Script Admin'), true);
  assert.equal(formBodyContains(submitted, 'email', 'no-script@example.com'), true);
  assert.equal(formBodyContains(submitted, 'role', ''), true);
  assert.equal(await page.getByRole('heading', { name: 'Request confirmed.' }).isVisible(), true);
  assert.equal(
    await page.getByRole('link', { name: 'Download aixray-aix.sh' }).getAttribute('href'),
    '../aixray-aix.sh',
  );
  assert.deepEqual(consoleErrors, []);
  await context.close();
});

test('AJAX enhancement reveals the download under production CSP', async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const consoleErrors = collectConsoleErrors(page);
  let submitted = '';
  await page.route('https://formsubmit.co/ajax/**', async (route) => {
    submitted = route.request().postData() ?? '';
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { 'access-control-allow-origin': origin },
      body: JSON.stringify({ success: true }),
    });
  });

  await page.goto(origin);
  await fillLead(page, { name: 'Ajax Admin', email: 'ajax@example.com', role: 'sysadmin' });
  await page.getByLabel('Work email').press('Enter');
  await page.getByText('Request confirmed. Your download is ready.').waitFor();

  assert.equal(page.url(), `${origin}/`);
  assert.equal(formBodyContains(submitted, 'name', 'Ajax Admin'), true);
  assert.equal(formBodyContains(submitted, 'email', 'ajax@example.com'), true);
  assert.equal(formBodyContains(submitted, 'role', 'sysadmin'), true);
  assert.equal(await page.locator('#download-ready').isVisible(), true);
  assert.deepEqual(consoleErrors, []);
  await context.close();
});

test('rejected AJAX enhancement falls back to native submit', async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  let nativeSubmission = '';
  await page.route('https://formsubmit.co/ajax/**', async (route) => {
    await route.fulfill({
      status: 503,
      contentType: 'application/json',
      headers: { 'access-control-allow-origin': origin },
      body: JSON.stringify({ success: false }),
    });
  });
  await page.route('https://formsubmit.co/hello@powertruesystems.com', async (route) => {
    nativeSubmission = route.request().postData() ?? '';
    await fulfillNativeRedirect(route);
  });

  await page.goto(origin);
  await fillLead(page, { name: 'Fallback Admin', email: 'fallback@example.com' });
  await Promise.all([
    page.waitForURL(`${origin}/ready/`),
    page.getByLabel('Work email').press('Enter'),
  ]);

  assert.equal(formBodyContains(nativeSubmission, 'name', 'Fallback Admin'), true);
  assert.equal(await page.getByRole('heading', { name: 'Request confirmed.' }).isVisible(), true);
  await context.close();
});

test('stalled AJAX enhancement times out and falls back to native submit', async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  let nativeSubmission = '';
  await page.route('https://formsubmit.co/ajax/**', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 6000));
    try {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': origin },
        body: JSON.stringify({ success: true }),
      });
    } catch {
      // The AbortController closes this intercepted request at five seconds.
    }
  });
  await page.route('https://formsubmit.co/hello@powertruesystems.com', async (route) => {
    nativeSubmission = route.request().postData() ?? '';
    await fulfillNativeRedirect(route);
  });

  await page.goto(origin);
  await fillLead(page, { name: 'Timeout Admin', email: 'timeout@example.com', role: 'it_manager' });
  await Promise.all([
    page.waitForURL(`${origin}/ready/`, { timeout: 8000 }),
    page.getByLabel('Work email').press('Enter'),
  ]);

  assert.equal(formBodyContains(nativeSubmission, 'name', 'Timeout Admin'), true);
  assert.equal(formBodyContains(nativeSubmission, 'role', 'it_manager'), true);
  assert.equal(await page.getByRole('heading', { name: 'Request confirmed.' }).isVisible(), true);
  await context.close();
});
