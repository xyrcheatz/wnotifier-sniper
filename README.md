# WNotifier Cloudflare Sniper

A full-stack Cloudflare Worker project with:

- Static signup/login dashboard
- D1-backed user accounts and sessions
- PBKDF2 password hashing
- AES-GCM encrypted WNotifier cookie storage
- AES-GCM encrypted Discord webhook storage
- Cloudflare Browser Run / Playwright automation
- Durable Object alarms for background scanning
- **Normal Access only**
- Region forced to **USA (Los Angeles)**
- Duration preference **60m → 30m → 15m**
- Maximum total-cost check
- Final **Confirm rent → Rent** click
- Discord ping to user ID `1167590082878902435`
- Stops after a rent is submitted
- Activity log that never intentionally logs cookie/webhook plaintext

## Important security note

The cookie/webhook are encrypted at rest in D1 and the API never returns their plaintext.

However, because the Worker must decrypt the WNotifier cookie in order to use it in Browser Run, **it is impossible to guarantee that a Cloudflare account owner with permission to replace/deploy Worker code can never access the plaintext**. An owner could deploy modified code that exposes a credential while it is being used.

Do not commit any cookies, webhooks, encryption keys, `.dev.vars`, or Cloudflare API tokens to GitHub.

## 1. Install

```powershell
npm install
npx wrangler login
```

## 2. Create the D1 database

```powershell
npx wrangler d1 create wnotifier-cloud-db
```

Cloudflare prints a `database_id`. Open `wrangler.jsonc` and replace:

```text
PASTE_YOUR_D1_DATABASE_ID_HERE
```

with that ID.

## 3. Apply the database migration

```powershell
npx wrangler d1 migrations apply wnotifier-cloud-db --remote
```

Confirm the migration when Wrangler asks.

## 4. Create the encryption key

Generate a 32-byte random key:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Copy the output, then run:

```powershell
npx wrangler secret put CREDENTIAL_KEY_B64
```

Paste the generated value when prompted.

**Never place the value in `wrangler.jsonc` or GitHub.**

## 5. Deploy

```powershell
npx wrangler deploy
```

Wrangler will print the deployed `workers.dev` address.

## 6. Use the dashboard

1. Open the Worker URL.
2. Create a dashboard account.
3. Save your WNotifier **Cookie request header** in Secure Vault.
4. Optionally save a Discord webhook.
5. Choose your maximum total cost and scan interval.
6. Press **Start sniper**.

The project clamps automatic Cloudflare background scans to a minimum of **5000 ms**. A full Browser Run navigation every 100 ms is not suitable for a Durable Object alarm loop and would create overlapping/expensive browser work. `Scan once now` runs immediately.

## Getting your own WNotifier cookie

Use your own signed-in browser session. In browser DevTools, inspect a request to `wnotifier.com`, copy its `Cookie` request-header value, and paste only that value into the dashboard.

Do not use someone else's session cookie.

## GitHub

This ZIP is already repository-ready:

```powershell
git init
git add .
git commit -m "Initial Cloudflare deployment"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

The `.gitignore` excludes local Wrangler files and environment files.

## Optional GitHub Actions deployment

The included workflow expects these GitHub repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

The Worker secret `CREDENTIAL_KEY_B64` should still be created in Cloudflare with `wrangler secret put`; do not add it to the repository.

## Troubleshooting

### `HTTP 404` on signup/login

Deploy this entire project with `wrangler deploy`. Uploading only `public/index.html` through Cloudflare's static-file uploader does not create the `/api/*` Worker routes.

### `CREDENTIAL_KEY_B64 secret is not configured`

Run:

```powershell
npx wrangler secret put CREDENTIAL_KEY_B64
```

### WNotifier says logged out

The saved cookie expired. Save a fresh Cookie request-header value from your own signed-in WNotifier browser session.

### Browser Run errors / limits

Browser Run usage depends on your Cloudflare plan and current Browser Run limits. Check your Cloudflare dashboard usage if scans fail after deployment.

### The site changes its HTML

The automation selectors are based on the marketplace UI structure that includes:

- `Normal Access`
- `Available`
- `Min`
- `Rent time`
- region dropdown
- `Confirm rent`
- final exact `Rent` button

If WNotifier changes those labels/controls, update `index.js`.
