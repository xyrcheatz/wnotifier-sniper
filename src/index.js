import { DurableObject } from "cloudflare:workers";
import { launch } from "@cloudflare/playwright";

const MARKETPLACE_URL = "https://wnotifier.com/marketplace";
const REGION = "USA (Los Angeles)";
const DURATIONS = [60, 30, 15];
const PING_USER_ID = "1167590082878902435";

const SESSION_COOKIE = "wnc_session";
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const PASSWORD_ITERATIONS = 150000;

// Cloudflare alarms + Browser Run are not a good fit for sub-second full-page polling.
// Keep background scans bounded to a practical floor.
const MIN_SCAN_MS = 5000;
const MAX_SCAN_MS = 5 * 60 * 1000;

const enc = new TextEncoder();
const dec = new TextDecoder();

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

function cleanUsername(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}

function now() {
  return Date.now();
}

function randomBytes(length) {
  const b = new Uint8Array(length);
  crypto.getRandomValues(b);
  return b;
}

function bytesToB64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64ToBytes(value) {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a[i] ^ b[i];
  return x === 0;
}

async function sha256Bytes(data) {
  const input = typeof data === "string" ? enc.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

async function sha256B64(value) {
  return bytesToB64(await sha256Bytes(value));
}

async function derivePassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PASSWORD_ITERATIONS
    },
    key,
    256
  );

  return new Uint8Array(bits);
}

async function getVaultKey(env) {
  if (!env.CREDENTIAL_KEY_B64) {
    throw new Error("CREDENTIAL_KEY_B64 secret is not configured.");
  }

  const raw = b64ToBytes(env.CREDENTIAL_KEY_B64);
  if (raw.length !== 32) {
    throw new Error("CREDENTIAL_KEY_B64 must decode to exactly 32 bytes.");
  }

  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptSecret(env, plaintext) {
  if (!plaintext) return null;
  const key = await getVaultKey(env);
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext)
  );
  return {
    cipher: bytesToB64(new Uint8Array(cipher)),
    iv: bytesToB64(iv)
  };
}

async function decryptSecret(env, cipherB64, ivB64) {
  if (!cipherB64 || !ivB64) return "";
  const key = await getVaultKey(env);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(ivB64) },
    key,
    b64ToBytes(cipherB64)
  );
  return dec.decode(plain);
}

function parseCookies(request) {
  const raw = request.headers.get("cookie") || "";
  const out = {};
  for (const item of raw.split(";")) {
    const idx = item.indexOf("=");
    if (idx < 0) continue;
    const k = item.slice(0, idx).trim();
    const v = item.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    throw new Error("Invalid JSON body.");
  }
}

async function logActivity(env, userId, level, message) {
  // Deliberately never pass cookie or webhook plaintext into this function.
  await env.DB.prepare(
    `INSERT INTO activity (user_id, level, message, created_at)
     VALUES (?, ?, ?, ?)`
  ).bind(userId, level, String(message).slice(0, 1000), now()).run();

  // Keep only the newest 250 activity rows per user.
  await env.DB.prepare(
    `DELETE FROM activity
     WHERE user_id = ?
       AND id NOT IN (
         SELECT id FROM activity
         WHERE user_id = ?
         ORDER BY id DESC
         LIMIT 250
       )`
  ).bind(userId, userId).run();
}

async function getUserBySession(request, env) {
  const cookies = parseCookies(request);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;

  const tokenHash = await sha256B64(token);
  const row = await env.DB.prepare(
    `SELECT u.id, u.username, s.expires_at
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?`
  ).bind(tokenHash).first();

  if (!row) return null;

  if (Number(row.expires_at) <= now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(tokenHash).run();
    return null;
  }

  return { id: row.id, username: row.username };
}

async function requireUser(request, env) {
  const user = await getUserBySession(request, env);
  if (!user) throw Object.assign(new Error("Not signed in."), { status: 401 });
  return user;
}

async function ensureSettings(env, userId) {
  const existing = await env.DB.prepare(
    "SELECT * FROM settings WHERE user_id = ?"
  ).bind(userId).first();

  if (existing) return existing;

  const ts = now();
  await env.DB.prepare(
    `INSERT INTO settings (user_id, enabled, max_cost, scan_interval_ms, updated_at)
     VALUES (?, 0, 7.00, 10000, ?)`
  ).bind(userId, ts).run();

  return env.DB.prepare(
    "SELECT * FROM settings WHERE user_id = ?"
  ).bind(userId).first();
}

async function sendWebhook(env, userId, message, ping = true) {
  const row = await env.DB.prepare(
    "SELECT webhook_cipher, webhook_iv FROM vault WHERE user_id = ?"
  ).bind(userId).first();

  if (!row?.webhook_cipher) return false;

  const webhook = await decryptSecret(env, row.webhook_cipher, row.webhook_iv);
  if (!webhook) return false;

  const content = ping ? `<@${PING_USER_ID}>\n${message}` : message;
  const response = await fetch(webhook, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      content,
      allowed_mentions: ping ? { users: [PING_USER_ID] } : { parse: [] }
    })
  });

  return response.ok;
}

function parseCookieHeader(cookieHeader) {
  const cookies = [];
  for (const pair of String(cookieHeader || "").split(";")) {
    const idx = pair.indexOf("=");
    if (idx <= 0) continue;
    const name = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (!name) continue;
    cookies.push({
      name,
      value,
      domain: "wnotifier.com",
      path: "/",
      secure: true
    });
  }
  return cookies;
}

function parseSlot(text) {
  return text.match(/Slot\s*#\s*(\d+)/i)?.[1] || null;
}

function parseMinutes(text, label) {
  const m = text.match(new RegExp(`${label}\\s*(\\d+)\\s*m`, "i"));
  return m ? Number(m[1]) : null;
}

function parseHourlyPrice(text) {
  const m = text.match(/\$(\d+(?:\.\d+)?)\s*\/?\s*hr/i);
  return m ? Number(m[1]) : null;
}

function parseCost(text) {
  const m = text.match(/COST\s*\$([\d.]+)/i);
  return m ? Number(m[1]) : null;
}

function chooseDuration(available, minimum) {
  for (const d of DURATIONS) {
    if (available >= d && minimum <= d) return d;
  }
  return null;
}

async function setFastPageRoutes(page) {
  await page.route("**/*", async (route) => {
    try {
      const req = route.request();
      const type = req.resourceType();
      const url = req.url();

      if (type === "image" || type === "font" || type === "media") {
        return route.abort();
      }

      if (
        url.includes("cloudflareinsights.com") ||
        url.includes("google-analytics.com") ||
        url.includes("googletagmanager.com")
      ) {
        return route.abort();
      }

      return route.continue();
    } catch {
      try { return route.continue(); } catch {}
    }
  });
}

async function findCard(rentButton) {
  let card = rentButton.locator(
    'xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " reveal ") and contains(., "Slot #")][1]'
  );
  if (await card.count()) return card.first();

  card = rentButton.locator(
    'xpath=ancestor::div[contains(., "Slot #") and contains(., "Access")][1]'
  );
  if (await card.count()) return card.first();

  return null;
}

async function selectLosAngeles(page, card) {
  let dropdown = card.locator('button[role="combobox"]').first();
  if (!(await dropdown.count())) {
    dropdown = card.locator('button[aria-haspopup="listbox"]').first();
  }
  if (!(await dropdown.count())) {
    dropdown = card.locator("button").filter({ hasText: /USA|Los Angeles|Region/i }).first();
  }
  if (!(await dropdown.count())) {
    throw new Error("Region dropdown not found.");
  }

  const current = (await dropdown.innerText().catch(() => "")).trim();
  if (current.includes(REGION)) return;

  await dropdown.click();

  let option = page.getByRole("option", { name: REGION, exact: true });
  if (await option.count()) {
    await option.first().click();
    return;
  }

  option = page.getByText(REGION, { exact: true });
  if (await option.count()) {
    await option.last().click();
    return;
  }

  await page.keyboard.press("Escape").catch(() => {});
  throw new Error(`${REGION} was not found in the region list.`);
}

async function setRentMinutes(card, minutes) {
  let input = card.locator('input[type="number"]').first();
  if (!(await input.count())) input = card.locator('input[inputmode="numeric"]').first();
  if (!(await input.count())) input = card.locator("input").first();
  if (!(await input.count())) throw new Error("Minutes input not found.");

  await input.fill(String(minutes));
  await input.press("Tab");
  await new Promise((resolve) => setTimeout(resolve, 75));

  const actual = Number(await input.inputValue());
  if (actual !== minutes) {
    throw new Error(`Minutes field became ${actual}; expected ${minutes}.`);
  }
}

async function confirmRent(page, expectedMinutes, maxCost) {
  let dialog = page.getByRole("dialog").last();
  await dialog.waitFor({ state: "visible", timeout: 4000 }).catch(() => {});

  let text = "";
  if (await dialog.count()) {
    text = await dialog.innerText().catch(() => "");
  }

  if (text) {
    const durationMatch = text.match(/Rent\s*(\d+)\s*m/i);
    if (durationMatch && Number(durationMatch[1]) !== expectedMinutes) {
      throw new Error("Confirmation duration changed.");
    }

    const costMatch = text.match(/\$([\d.]+)/);
    if (costMatch && maxCost > 0 && Number(costMatch[1]) > maxCost) {
      throw new Error("Confirmation cost exceeds configured maximum.");
    }

    const rent = dialog.getByRole("button", { name: "Rent", exact: true });
    if (await rent.count()) {
      await rent.click();
      return text;
    }
  }

  const buttons = page.getByRole("button", { name: "Rent", exact: true });
  const count = await buttons.count();
  if (!count) throw new Error("Final Rent confirmation button was not found.");
  await buttons.nth(count - 1).click();
  return text;
}

async function runUserScan(env, userId) {
  const settings = await ensureSettings(env, userId);
  if (!Number(settings.enabled)) {
    return { matched: false, rented: false, message: "Sniper is disabled." };
  }

  const vault = await env.DB.prepare(
    `SELECT cookie_cipher, cookie_iv
     FROM vault WHERE user_id = ?`
  ).bind(userId).first();

  if (!vault?.cookie_cipher) {
    await logActivity(env, userId, "error", "No WNotifier cookie is saved.");
    return { matched: false, rented: false, message: "No WNotifier cookie saved." };
  }

  const cookieHeader = await decryptSecret(env, vault.cookie_cipher, vault.cookie_iv);
  const cookies = parseCookieHeader(cookieHeader);
  if (!cookies.length) {
    await logActivity(env, userId, "error", "Saved cookie could not be parsed.");
    return { matched: false, rented: false, message: "Saved cookie could not be parsed." };
  }

  let browser;
  try {
    browser = await launch(env.BROWSER);
    const context = await browser.newContext();
    await context.addCookies(cookies);
    const page = await context.newPage();

    await setFastPageRoutes(page);
    page.setDefaultTimeout(5000);

    await page.goto(MARKETPLACE_URL, {
      waitUntil: "domcontentloaded",
      timeout: 15000
    });

    const bodyText = await page.locator("body").innerText().catch(() => "");
    if (/login with discord|log in with discord|sign in with discord/i.test(bodyText)) {
      await logActivity(env, userId, "error", "WNotifier cookie appears expired or invalid.");
      return { matched: false, rented: false, message: "WNotifier cookie appears expired." };
    }

    const normalFilter = page.getByRole("button", { name: /Normal Access/i }).first();
    if (await normalFilter.count()) {
      const pressed = await normalFilter.getAttribute("aria-pressed");
      if (pressed !== "true") {
        await normalFilter.click();
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }

    const rentButtons = page.getByRole("button", { name: /^Rent time$/i });
    const count = await rentButtons.count();

    for (let i = 0; i < count; i++) {
      const rentButton = rentButtons.nth(i);
      if (!(await rentButton.isVisible().catch(() => false))) continue;

      const card = await findCard(rentButton);
      if (!card) continue;

      const text = await card.innerText().catch(() => "");
      if (!/\bNormal Access\b/i.test(text) || /\bPoor Access\b/i.test(text)) continue;

      const slot = parseSlot(text);
      const available = parseMinutes(text, "Available");
      const minimum = parseMinutes(text, "Min");
      if (!slot || available === null || minimum === null) continue;

      const duration = chooseDuration(available, minimum);
      if (!duration) continue;

      const hourlyPrice = parseHourlyPrice(text);
      const estimated =
        hourlyPrice === null ? null : hourlyPrice * (duration / 60);

      if (
        estimated !== null &&
        Number(settings.max_cost) > 0 &&
        estimated > Number(settings.max_cost)
      ) {
        continue;
      }

      await logActivity(
        env,
        userId,
        "match",
        `Normal Access Slot #${slot}: ${available}m available, min ${minimum}m, choosing ${duration}m.`
      );

      // Re-read immediately before acting.
      const fresh = await card.innerText();
      if (!/\bNormal Access\b/i.test(fresh) || /\bPoor Access\b/i.test(fresh)) {
        continue;
      }

      await selectLosAngeles(page, card);
      await setRentMinutes(card, duration);

      const updated = await card.innerText();
      const actualCost = parseCost(updated);

      if (
        actualCost !== null &&
        Number(settings.max_cost) > 0 &&
        actualCost > Number(settings.max_cost)
      ) {
        await logActivity(
          env,
          userId,
          "skip",
          `Slot #${slot} changed to $${actualCost.toFixed(2)}, above the maximum.`
        );
        continue;
      }

      if (await rentButton.isDisabled()) continue;

      await rentButton.click();
      const confirmation = await confirmRent(
        page,
        duration,
        Number(settings.max_cost)
      );

      // Give the site a moment to process the click.
      await new Promise((resolve) => setTimeout(resolve, 600));

      await env.DB.prepare(
        `UPDATE settings SET enabled = 0, updated_at = ? WHERE user_id = ?`
      ).bind(now(), userId).run();

      const costText =
        actualCost === null ? "unknown" : `$${actualCost.toFixed(2)}`;

      await logActivity(
        env,
        userId,
        "success",
        `Rent submitted for Normal Access Slot #${slot}: ${duration}m, ${REGION}, cost ${costText}.`
      );

      await sendWebhook(
        env,
        userId,
        [
          "✅ **WNotifier rent submitted**",
          `**Slot:** #${slot}`,
          "**Type:** Normal Access",
          `**Duration:** ${duration} minutes`,
          `**Region:** ${REGION}`,
          `**Cost:** ${costText}`
        ].join("\n"),
        true
      ).catch(() => false);

      return {
        matched: true,
        rented: true,
        slot,
        duration,
        cost: actualCost,
        confirmation
      };
    }

    return { matched: false, rented: false, message: "No rentable Normal Access listing found." };
  } catch (error) {
    await logActivity(
      env,
      userId,
      "error",
      `Scan error: ${String(error?.message || error).slice(0, 700)}`
    ).catch(() => {});
    return { matched: false, rented: false, error: String(error?.message || error) };
  } finally {
    try { if (browser) await browser.close(); } catch {}
  }
}

export class SniperController extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
  }

  async start(userId) {
    await this.ctx.storage.put("userId", userId);
    await this.ctx.storage.put("active", true);
    await this.ctx.storage.setAlarm(Date.now() + 1000);
    return { ok: true };
  }

  async stop() {
    await this.ctx.storage.put("active", false);
    await this.ctx.storage.deleteAlarm();
    return { ok: true };
  }

  async status() {
    return {
      active: Boolean(await this.ctx.storage.get("active")),
      alarm: await this.ctx.storage.getAlarm()
    };
  }

  async scanNow(userId) {
    await this.ctx.storage.put("userId", userId);
    return runUserScan(this.env, userId);
  }

  async alarm() {
    const active = Boolean(await this.ctx.storage.get("active"));
    const userId = await this.ctx.storage.get("userId");
    if (!active || !userId) return;

    const result = await runUserScan(this.env, userId);

    const settings = await ensureSettings(this.env, userId);
    if (!Number(settings.enabled) || result?.rented) {
      await this.ctx.storage.put("active", false);
      return;
    }

    const interval = Math.max(
      MIN_SCAN_MS,
      Math.min(MAX_SCAN_MS, Number(settings.scan_interval_ms) || 10000)
    );
    await this.ctx.storage.setAlarm(Date.now() + interval);
  }
}

async function routeApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/api/signup" && request.method === "POST") {
    const body = await readJson(request);
    const username = cleanUsername(body.username);
    const password = String(body.password || "");

    if (username.length < 3 || username.length > 32) {
      return json({ error: "Username must be 3-32 characters." }, 400);
    }
    if (password.length < 8 || password.length > 200) {
      return json({ error: "Password must be at least 8 characters." }, 400);
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE username = ?"
    ).bind(username).first();
    if (existing) return json({ error: "That username is already taken." }, 409);

    const userId = crypto.randomUUID();
    const salt = randomBytes(16);
    const hash = await derivePassword(password, salt);
    const ts = now();

    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO users (id, username, password_salt, password_hash, created_at)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(userId, username, bytesToB64(salt), bytesToB64(hash), ts),

      env.DB.prepare(
        `INSERT INTO settings (user_id, enabled, max_cost, scan_interval_ms, updated_at)
         VALUES (?, 0, 7.00, 10000, ?)`
      ).bind(userId, ts)
    ]);

    const token = bytesToB64(randomBytes(32)).replace(/=+$/g, "");
    const tokenHash = await sha256B64(token);

    await env.DB.prepare(
      `INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
       VALUES (?, ?, ?, ?)`
    ).bind(tokenHash, userId, ts, ts + SESSION_SECONDS * 1000).run();

    return json(
      { ok: true, user: { id: userId, username } },
      201,
      { "set-cookie": sessionCookie(token) }
    );
  }

  if (path === "/api/login" && request.method === "POST") {
    const body = await readJson(request);
    const username = cleanUsername(body.username);
    const password = String(body.password || "");

    const row = await env.DB.prepare(
      `SELECT id, username, password_salt, password_hash
       FROM users WHERE username = ?`
    ).bind(username).first();

    if (!row) return json({ error: "Invalid username or password." }, 401);

    const actual = await derivePassword(password, b64ToBytes(row.password_salt));
    const expected = b64ToBytes(row.password_hash);
    if (!constantTimeEqual(actual, expected)) {
      return json({ error: "Invalid username or password." }, 401);
    }

    const token = bytesToB64(randomBytes(32)).replace(/=+$/g, "");
    const tokenHash = await sha256B64(token);
    const ts = now();

    await env.DB.prepare(
      `INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
       VALUES (?, ?, ?, ?)`
    ).bind(tokenHash, row.id, ts, ts + SESSION_SECONDS * 1000).run();

    return json(
      { ok: true, user: { id: row.id, username: row.username } },
      200,
      { "set-cookie": sessionCookie(token) }
    );
  }

  if (path === "/api/logout" && request.method === "POST") {
    const cookies = parseCookies(request);
    const token = cookies[SESSION_COOKIE];
    if (token) {
      const tokenHash = await sha256B64(token);
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
        .bind(tokenHash).run();
    }
    return json({ ok: true }, 200, { "set-cookie": clearSessionCookie() });
  }

  const user = await requireUser(request, env);

  if (path === "/api/me" && request.method === "GET") {
    return json({ user });
  }

  if (path === "/api/vault" && request.method === "GET") {
    const row = await env.DB.prepare(
      `SELECT cookie_cipher, webhook_cipher, updated_at
       FROM vault WHERE user_id = ?`
    ).bind(user.id).first();

    return json({
      hasCookie: Boolean(row?.cookie_cipher),
      hasWebhook: Boolean(row?.webhook_cipher),
      updatedAt: row?.updated_at || null
    });
  }

  if (path === "/api/vault" && request.method === "POST") {
    const body = await readJson(request);
    const cookie = typeof body.cookie === "string" ? body.cookie.trim() : "";
    const webhook = typeof body.webhook === "string" ? body.webhook.trim() : "";

    const current = await env.DB.prepare(
      "SELECT * FROM vault WHERE user_id = ?"
    ).bind(user.id).first();

    let cookieCipher = current?.cookie_cipher || null;
    let cookieIv = current?.cookie_iv || null;
    let webhookCipher = current?.webhook_cipher || null;
    let webhookIv = current?.webhook_iv || null;

    if (cookie) {
      const encrypted = await encryptSecret(env, cookie);
      cookieCipher = encrypted.cipher;
      cookieIv = encrypted.iv;
    }

    if (webhook) {
      const encrypted = await encryptSecret(env, webhook);
      webhookCipher = encrypted.cipher;
      webhookIv = encrypted.iv;
    }

    if (body.clearCookie === true) {
      cookieCipher = null;
      cookieIv = null;
    }
    if (body.clearWebhook === true) {
      webhookCipher = null;
      webhookIv = null;
    }

    await env.DB.prepare(
      `INSERT INTO vault
       (user_id, cookie_cipher, cookie_iv, webhook_cipher, webhook_iv, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         cookie_cipher = excluded.cookie_cipher,
         cookie_iv = excluded.cookie_iv,
         webhook_cipher = excluded.webhook_cipher,
         webhook_iv = excluded.webhook_iv,
         updated_at = excluded.updated_at`
    ).bind(
      user.id,
      cookieCipher,
      cookieIv,
      webhookCipher,
      webhookIv,
      now()
    ).run();

    await logActivity(env, user.id, "info", "Secure vault settings updated.");
    return json({ ok: true });
  }

  if (path === "/api/settings" && request.method === "GET") {
    const row = await ensureSettings(env, user.id);
    return json({
      enabled: Boolean(row.enabled),
      maxCost: Number(row.max_cost),
      scanIntervalMs: Number(row.scan_interval_ms),
      minScanIntervalMs: MIN_SCAN_MS,
      region: REGION,
      durations: DURATIONS
    });
  }

  if (path === "/api/settings" && request.method === "POST") {
    const body = await readJson(request);
    const maxCost = Math.max(0, Math.min(10000, Number(body.maxCost ?? 7)));
    const interval = Math.max(
      MIN_SCAN_MS,
      Math.min(MAX_SCAN_MS, Number(body.scanIntervalMs ?? 10000))
    );

    await env.DB.prepare(
      `INSERT INTO settings (user_id, enabled, max_cost, scan_interval_ms, updated_at)
       VALUES (?, 0, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         max_cost = excluded.max_cost,
         scan_interval_ms = excluded.scan_interval_ms,
         updated_at = excluded.updated_at`
    ).bind(user.id, maxCost, interval, now()).run();

    await logActivity(
      env,
      user.id,
      "info",
      `Settings saved: max cost $${maxCost.toFixed(2)}, scan interval ${interval}ms.`
    );
    return json({ ok: true, maxCost, scanIntervalMs: interval });
  }

  if (path === "/api/sniper/start" && request.method === "POST") {
    const vault = await env.DB.prepare(
      "SELECT cookie_cipher FROM vault WHERE user_id = ?"
    ).bind(user.id).first();
    if (!vault?.cookie_cipher) {
      return json({ error: "Save your WNotifier cookie first." }, 400);
    }

    await env.DB.prepare(
      "UPDATE settings SET enabled = 1, updated_at = ? WHERE user_id = ?"
    ).bind(now(), user.id).run();

    const stub = env.SNIPER.getByName(user.id);
    await stub.start(user.id);

    await logActivity(env, user.id, "info", "Sniper started.");
    return json({ ok: true });
  }

  if (path === "/api/sniper/stop" && request.method === "POST") {
    await env.DB.prepare(
      "UPDATE settings SET enabled = 0, updated_at = ? WHERE user_id = ?"
    ).bind(now(), user.id).run();

    const stub = env.SNIPER.getByName(user.id);
    await stub.stop();

    await logActivity(env, user.id, "info", "Sniper stopped.");
    return json({ ok: true });
  }

  if (path === "/api/sniper/scan-once" && request.method === "POST") {
    const stub = env.SNIPER.getByName(user.id);
    const result = await stub.scanNow(user.id);
    return json({ ok: true, result });
  }

  if (path === "/api/status" && request.method === "GET") {
    const settings = await ensureSettings(env, user.id);
    const stub = env.SNIPER.getByName(user.id);
    const controller = await stub.status();

    return json({
      enabled: Boolean(settings.enabled),
      maxCost: Number(settings.max_cost),
      scanIntervalMs: Number(settings.scan_interval_ms),
      controller
    });
  }

  if (path === "/api/activity" && request.method === "GET") {
    const result = await env.DB.prepare(
      `SELECT id, level, message, created_at
       FROM activity
       WHERE user_id = ?
       ORDER BY id DESC
       LIMIT 100`
    ).bind(user.id).all();

    return json({ activity: result.results || [] });
  }

  if (path === "/api/webhook/test" && request.method === "POST") {
    const ok = await sendWebhook(
      env,
      user.id,
      "🔔 **WNotifier Cloud webhook test**",
      true
    );
    return json({ ok });
  }

  return json({ error: "Not found." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await routeApi(request, env);
      } catch (error) {
        const status = Number(error?.status) || 500;
        const message =
          status === 500
            ? `Server error: ${String(error?.message || error)}`
            : String(error?.message || error);
        return json({ error: message }, status);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
