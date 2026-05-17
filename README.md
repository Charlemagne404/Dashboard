# Continental ID Dashboard

A full-stack account dashboard with hardened auth/session handling, profile and security controls, and real API-driven account settings.

## What Was Upgraded

- Hardened backend API with:
  - request IDs
  - health endpoint (`/api/health`)
  - env-driven CORS and rate-limiting
  - login brute-force throttling and temporary lockouts
  - graceful shutdown
  - safer refresh-token lifecycle (`refreshTokenVersion` invalidation + tracked refresh sessions)
- Expanded account model and endpoints for:
  - username-based identity with separate display names and login by email or username
  - richer profile fields (avatar, headline, pronouns, bio, location, website, timezone, language)
  - external profile references
  - privacy/notification preferences and appearance settings
  - security settings
  - active session management (list/revoke/revoke-all)
  - recent activity
  - account JSON export
- Safer email utility configuration (no hardcoded credentials)
- Rebuilt frontend dashboard with:
  - fully wired forms for every tab
  - auto refresh-token retry on 401
  - activity filtering, trend mini-bars, and CSV export
  - toasts, loading states, sync status, connection status, and popup fallback
  - in-memory access-token handling backed by secure refresh cookies
  - appearance themes, density controls, high-contrast/reduced-motion options
  - responsive layout and improved visual polish

## Backend Setup

1. Install dependencies:
   ```bash
   cd backend
   npm install
   ```
   Use Node 20+ for the backend so the Resend SDK installs cleanly.
2. Create env file:
   ```bash
   cp .env.example .env
   ```
3. Configure Resend for verification emails:
   ```env
   RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxx
   EMAIL_FROM=no-reply@your-domain.com
   EMAIL_FROM_NAME=Continental ID
   EMAIL_REPLY_TO=support@your-domain.com
   LOGIN_POPUP_URL=https://login.continental-hub.com/popup.html
   EMAIL_VERIFY_URL=https://login.continental-hub.com/verify.html
   ```
4. Start backend:
   ```bash
   npm run start
   ```
   Startup now runs a user-identity migration so existing accounts get usernames and the new profile shape automatically.
5. Run the migration manually if needed:
   ```bash
   npm run migrate:users
   ```
6. Run the backend verification suite:
   ```bash
   npm test
   ```

## Backend Env Reference

Required:

- `MONGO_URI`
- `JWT_SECRET`
- `REFRESH_TOKEN_SECRET`

Common production settings:

- `NODE_ENV=production`
- `HOST=0.0.0.0` unless you intentionally want loopback-only binding
- `TRUST_PROXY=1` when running behind Nginx, Caddy, or another reverse proxy
- `ALLOWED_ORIGINS=https://dashboard.example.com,https://login.example.com`
- `ALLOW_LOCALHOST_ORIGINS=false`
- `HTTPS_MODE=off` when TLS terminates at the proxy, or `HTTPS_MODE=on` for direct TLS on the Node process

Auth tuning:

- `JWT_EXPIRES_IN`
- `REFRESH_TOKEN_EXPIRES_IN`
- `RATE_LIMIT_WINDOW_MS`
- `RATE_LIMIT_MAX`
- `LOGIN_RATE_WINDOW_MS`
- `LOGIN_RATE_MAX_ATTEMPTS`
- `LOGIN_BLOCK_MS`
- `MFA_RATE_WINDOW_MS`
- `MFA_RATE_MAX_ATTEMPTS`
- `MFA_BLOCK_MS`
- `REFRESH_TOKEN_REPLAY_GRACE_MS`
- `PASSWORD_RESET_TTL_MS`
- `PASSWORD_RESET_EMAIL_COOLDOWN_MS`
- `VERIFICATION_EMAIL_COOLDOWN_MS`
- `EMAIL_VERIFICATION_TTL_MS`
- `EMAIL_DAILY_LIMIT`
- `EMAIL_MONTHLY_LIMIT`

Passkeys / WebAuthn:

- `WEBAUTHN_RP_NAME`
- `WEBAUTHN_RP_ID`

OAuth:

- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_OAUTH_CALLBACK_URL`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_OAUTH_CALLBACK_URL`
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_OAUTH_CALLBACK_URL`
- `MICROSOFT_CLIENT_ID`
- `MICROSOFT_CLIENT_SECRET`
- `MICROSOFT_TENANT_ID`
- `MICROSOFT_OAUTH_CALLBACK_URL`

Optional Vanguard integration:

- `VANGUARD_API_KEY` or `VANGUARD_API_KEYS`
- `VANGUARD_API_KEY_HEADER`
- `VANGUARD_INSTANCE_HEADER`
- `VANGUARD_LICENSE_AUTHORIZED`
- `VANGUARD_LICENSE_REASON`
- `VANGUARD_ALLOWED_GUILD_IDS`
- `VANGUARD_ENTITLEMENT_AI`
- `VANGUARD_ENTITLEMENT_ADVANCED_VOTES`
- `VANGUARD_ENTITLEMENT_GUARD_PRESETS`

## Frontend Setup

You can serve `frontend/` with any static server (for example Live Server or `python -m http.server`).

Optional runtime globals:

- `window.__API_BASE_URL__`
- `window.__LOGIN_POPUP_URL__`

Default behavior now assumes the frontend and `/api/*` are available on the same HTTPS origin. That is the preferred deployment because it avoids exposing `:5000` to browsers and reduces cross-site cookie failures on restrictive networks.
For the current hosted static domains (`dashboard.continental-hub.com`, `login.continental-hub.com`, `pulse.continental-hub.com`, `grimoire.continental-hub.com`, and `charlemagne404.github.io`), the checked-in frontend now probes the same origin plus the known Continental auth/API hosts and only keeps a candidate that exposes the expected auth `/api/health` response. Set `window.__API_BASE_URL__` when you want a deterministic backend origin.

## GitHub Pages Hosting

- A deploy workflow is included at `.github/workflows/deploy-pages.yml`.
- A backend syntax-check workflow is included at `.github/workflows/backend-check.yml`.
- It publishes the `frontend/` folder to GitHub Pages and includes `CNAME`.
- In your GitHub repo settings, set Pages to **GitHub Actions** as the source.
- If your API is on a different origin, set backend `ALLOWED_ORIGINS` to include your Pages/custom domain.
- If you proxy the API through the same public host on `443`, leave the frontend on its default same-origin `/api/*` setup instead of pointing browsers at `:5000`.
- To mirror the auth pages into the sibling `Login` repo, run `bash scripts/sync-login-popup.sh`.

## Container Setup

You can run the backend and MongoDB together with Docker Compose:

```bash
cp backend/.env.example backend/.env
docker compose up --build
```

Notes:

- `compose.yml` expects `backend/.env` to exist.
- The compose stack sets `MONGO_URI` to the bundled `mongo` service automatically.
- The checked-in compose stack is for local development: it binds the backend on `0.0.0.0`, keeps `NODE_ENV=development`, and disables direct HTTPS on the Node process.
- For a public/containerized deployment, switch to `NODE_ENV=production`, replace the placeholder secrets, set the correct `ALLOWED_ORIGINS`, and either terminate TLS at the proxy with `HTTPS_MODE=off` or run direct TLS with `HTTPS_MODE=on`.

## Production Notes

- The repo currently ships deployment automation for the static frontend and a local deploy helper for the backend at `backend/deploy-backend.sh`.
- The backend no longer auto-enables HTTPS just because cert files happen to exist on the host. Set `HTTPS_MODE=on` explicitly when you want the Node process itself to serve TLS.
- The backend workflow runs `npm run check` and `npm test`; it still does not deploy or validate production secrets.
- The dashboard and login popup now expose Microsoft alongside GitHub, Google, and Discord when the provider is configured on the backend.
- Passkeys and cross-site refresh cookies depend on your final public origins, proxy setup, and HTTPS configuration, so validate those flows in the deployed environment instead of assuming local success maps to production.
- Proxy clients such as StepCast can forward browser-originated `POST /api/auth/login`, `POST /api/auth/register`, `POST /api/auth/refresh_token`, and `GET /api/auth/me` traffic through their own backend as long as `ALLOWED_ORIGINS` includes the browser origin and the proxy passes through the refresh cookie and bearer token unchanged.

## Key API Endpoints

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/refresh_token`
- `POST /api/auth/resend-verification`
- `GET /api/auth/me`
- `PATCH /api/auth/profile`
- `PATCH /api/auth/email`
- `PATCH /api/auth/password`
- `GET/PATCH /api/auth/preferences`
- `GET/PATCH /api/auth/linked`
- `GET /api/auth/activity`
- `GET/PATCH /api/auth/security`
- `GET /api/auth/sessions`
- `DELETE /api/auth/sessions/:sessionId`
- `DELETE /api/auth/sessions`
- `GET /api/auth/export`
- `DELETE /api/auth/account`
- `GET /api/auth/verify-email?token=...`
- `GET /api/vanguard/health`
- `POST /api/vanguard/license/verify`
- `POST /api/vanguard/users/resolve`
- `POST /api/vanguard/users/flag`
- `POST /api/vanguard/users/unflag`

## Resend Verification Flow

- New registrations now create a verification token and send a verification email through Resend.
- Accounts now carry a distinct `username` for sign-in and a separate `displayName` for presentation.
- Existing users are migrated forward on backend startup, and the same migration can be run manually with `npm run migrate:users`.
- Changing an account email resets `isVerified`, issues a new token, and sends a fresh verification email.
- Signed-in users can request a new verification email with `POST /api/auth/resend-verification`.
- Set `LOGIN_POPUP_URL` to the public login page, for example `https://login.continental-hub.com/popup.html`, so verification and reset emails can derive the correct hosted auth routes automatically.
- Set `EMAIL_VERIFY_URL` to the public URL of the verification page, for example `https://login.continental-hub.com/verify.html`, that loads the token and calls `/api/auth/verify-email`.
- For local email previews, open `http://127.0.0.1:5000/api/auth/email-preview` after starting the backend. You can switch between verification, password reset, and security/login alert templates and preview different dashboard themes without sending any email.

## Notes

- `ALLOWED_ORIGINS` is comma-separated. `localhost`/`127.0.0.1` are allowed automatically only in development, or when `ALLOW_LOCALHOST_ORIGINS=true`.

## Legal

- Source code in this repository is licensed under the MIT license. See [`LICENSE`](LICENSE).
- Service terms for the deployed dashboard are documented in [`TERMS.md`](TERMS.md).
- The hosted privacy policy is maintained in [`frontend/privacy.html`](frontend/privacy.html).
- `https://mpmc.ddns.net` remains a legacy trusted candidate, but the frontend will no longer treat it as the auth API unless it exposes the expected Continental ID health payload.
- Login anti-bruteforce guardrails are configurable via `LOGIN_RATE_WINDOW_MS`, `LOGIN_RATE_MAX_ATTEMPTS`, and `LOGIN_BLOCK_MS`.
- Password updates invalidate existing refresh sessions and force re-login.
- Logout invalidates refresh sessions and clears auth cookie.
- Refresh cookies now use `SameSite=Lax` for same-origin HTTPS requests and only fall back to `SameSite=None` when the request is truly cross-site.
