# Continental ID Integration Guide

This guide explains how to integrate with Continental ID in a way that stays reliable in real browsers and real deployments.

The main point is simple:

- treat Continental ID as a session system, not just a login screen
- keep auth traffic first-party whenever possible
- support both popup messaging and redirect-based recovery
- centralize auth state in one place
- treat provider failures, origin mismatches, and refresh failures as normal cases that must be handled explicitly

For first-party Continental sites under `*.continental-hub.com`, two extra rules now apply:

- device identity is shared across first-party subdomains, so the same browser should stay recognized as the same known device
- the login popup should try `POST /api/auth/refresh_token` and then `GET /api/auth/me` before asking for credentials, so it can offer a lightweight "Continue as ..." step when a Continental session already exists on the device

## Reliability First

The most common Continental ID failures are not bad passwords or bad JWT code. They are deployment and browser-behavior failures:

- the app calls the auth backend on a different origin than the app itself
- refresh cookies are cross-site and silently blocked
- a popup succeeds but `postMessage` does not reach the opener
- the auth API is healthy, but the app points at the wrong public origin
- the app retries refresh forever and hides the real failure
- the app trusts ad hoc payloads instead of one auth contract

If you solve those issues, the login flow becomes much more stable.

## Recommended Model

Use this model unless you have a strong reason not to:

1. The app is served on its own public HTTPS origin.
2. That same public origin proxies `/api/auth/*` to Continental ID.
3. The browser talks to `/api/auth/*` on the app origin, not directly to a backend port.
4. The login popup is opened with the app origin passed as `origin`, and the app URL passed as `redirect`.
5. The frontend stores the access token in memory only.
6. The refresh token stays in an `HttpOnly` cookie.
7. The app retries once after `401`, then signs the user out or moves to a degraded state.
8. First-party popup flows should attempt session reuse through `refresh_token` plus `/me` before rendering credential entry.

Example:

- app: `https://blueprint.example.com`
- app proxy: `https://blueprint.example.com/api/auth/*`
- login popup: `https://login.continental-hub.com/popup.html`

That gives you first-party refresh behavior for the browser while keeping Continental ID as the identity authority.

## Preferred Deployment Patterns

### 1. Same-origin app proxy

This is the preferred pattern.

- browser app: `https://app.example.com`
- auth API from browser perspective: `https://app.example.com/api/auth/*`
- reverse proxy forwards `/api/auth/*` to Continental ID

Why this is best:

- refresh cookies behave like first-party cookies
- fewer silent failures in restrictive browsers
- no browser-visible `:5000` backend ports
- cleaner startup and refresh logic
- better compatibility with popup fallback and redirect recovery

### 2. Split-origin auth

Use this only if same-origin proxying is not possible.

- app: `https://app.example.com`
- login pages: `https://login.example.com`
- auth API: `https://auth.example.com`

This can work, but it is less reliable because refresh is cross-site. If you use this model, test it in restrictive browser settings, not only in a permissive local setup.

### 3. Backend proxy client

This is valid when your product already has its own backend layer.

Your backend may proxy auth requests if it preserves:

- bearer access tokens
- refresh cookies
- `Origin` and `X-Forwarded-Proto` semantics
- the public host expected by Continental ID

Do not proxy only part of the flow. Partial proxying is how you get a login that "works once" and then fails on refresh.

## Required Browser Contract

Continental ID now supports one canonical auth result contract for popup and redirect recovery.

### Popup launch parameters

When opening the login popup, pass:

- `origin`: the app origin that should receive `postMessage`
- `redirect`: the app URL to return to if opener messaging fails or the popup must recover via full-page redirect
- `apiBaseUrl`: the public auth API base the popup should use, when your deployment needs it

Example:

```text
https://login.continental-hub.com/popup.html
  ?origin=https%3A%2F%2Fapp.example.com
  &redirect=https%3A%2F%2Fapp.example.com%2Fauth%2Fcomplete
  &apiBaseUrl=https%3A%2F%2Fapp.example.com
```

### Canonical popup message payload

Apps should accept this payload:

```json
{
  "source": "continental-id",
  "type": "auth-result",
  "event": "login_success",
  "correlationId": "request-id",
  "accessToken": "token",
  "token": "token",
  "apiBaseUrl": "https://app.example.com",
  "user": {}
}
```

Supported `event` values:

- `login_success`
- `login_error`
- `oauth_linked`

Legacy `LOGIN_SUCCESS`, `LOGIN_ERROR`, and `OAUTH_LINKED` message types should still be tolerated for backward compatibility, but new integrations should use the canonical shape above.

### Redirect recovery contract

If popup messaging fails, Continental ID may redirect back to the app with auth state encoded in the URL hash.

Apps should consume:

- `continentalAuth=1`
- `authEvent`
- `accessToken`
- `token`
- `apiBaseUrl`
- `authCode`
- `authMessage`
- `correlationId`
- `provider`

Example:

```text
https://app.example.com/auth/complete
#continentalAuth=1
&authEvent=login_success
&accessToken=...
&apiBaseUrl=https%3A%2F%2Fapp.example.com
&correlationId=...
```

Important:

- read the hash once
- consume it immediately
- remove it from the URL with `history.replaceState`
- never leave access tokens sitting in the address bar longer than necessary

### First-party popup session reuse

For first-party `*.continental-hub.com` sites, the popup should do this on load:

1. probe the configured auth API base
2. call `POST /api/auth/refresh_token` with credentials
3. if refresh returns `authenticated: true`, call `GET /api/auth/me` with the returned bearer token
4. render a lightweight confirmation state such as `Continue as Alex Mercer`
5. only fall back to the full login form when there is no active session or the refresh response says the session cannot be reused

Do not log out the shared Continental session just because the user wants to switch accounts. Let the popup reveal the normal login form instead.

## Required API Behavior

Continental ID exposes a session-oriented auth API. Integrations should expect these behaviors.

### Login

`POST /api/auth/login`

Expected outcomes:

- `200` with `authenticated: true`, `accessToken`, `auth.code = "auth/ok"`
- `401` or `429` for MFA-required or throttled states
- `403` with `requiresVerification: true` when email verification is still required

### Refresh

`POST /api/auth/refresh_token`

Expected outcomes:

- `200` with `authenticated: true` and a fresh access token
- `200` with `authenticated: false` and a machine-readable auth error when no valid refresh session exists

Do not assume refresh failures always return `401`. Continental ID intentionally returns structured auth state so the frontend can downgrade gracefully instead of throwing raw transport errors.

For first-party login popups, a successful refresh should be treated as "an existing session is available for confirmation", not as an automatic full-page sign-in.

### Session profile

`GET /api/auth/me`

Use this as the current-user source of truth. Do not reconstruct identity from stale popup state or client-side guesses.

## Structured Auth Errors

Integrations should read machine-readable auth errors, not only free-form messages.

Current responses may include:

```json
{
  "authenticated": false,
  "correlationId": "request-id",
  "error": {
    "code": "auth/refresh-session-missing",
    "correlationId": "request-id",
    "message": "No active refresh session.",
    "retryable": false
  },
  "message": "No active refresh session."
}
```

Common codes you should handle explicitly:

- `auth/ok`
- `auth/access-token-missing`
- `auth/account-suspended`
- `auth/authorization-denied`
- `auth/email-unverified`
- `auth/identity-conflict`
- `auth/invalid-credentials`
- `auth/invalid-refresh-session`
- `auth/invalid-token`
- `auth/mfa-blocked`
- `auth/mfa-required`
- `auth/origin-rejected`
- `auth/refresh-session-missing`
- `auth/session-revoked`
- `auth/unavailable`
- `auth/user-not-found`

Also log the `correlationId` or `X-Request-Id` when present. That is the identifier you need when diagnosing production auth failures.

## Frontend Rules

### 1. Centralize auth state

Keep one source of truth for:

- access token
- current user
- refresh-in-flight state
- signed-in or signed-out state
- degraded-auth state

Do not duplicate these values across multiple stores.

### 2. Startup flow

Use this exact order:

1. consume redirect-hash auth result if present
2. otherwise try refresh
3. if refresh succeeds, load `/me`
4. if `/me` fails once after refresh, try one more refresh

## Manual Verification

- Sign in to one first-party Continental site on a fresh browser and confirm the first login creates one known device and one new-device alert.
- Open the login popup from another `*.continental-hub.com` site on the same browser and confirm the popup shows a `Continue as ...` confirmation instead of the credential form.
- Continue with the existing session and confirm the relying-party site completes sign-in without another new-device alert.
- Reopen the popup and choose `Use a different account`; confirm the normal login form appears without logging out the existing shared session first.
- Open the popup with no refresh session and confirm the normal login/register flow still appears.
5. if refresh still fails, move to signed-out or degraded state

This prevents "signed in, but no session" dead ends.

### 3. Retry once on `401`

For authenticated API calls:

1. send bearer token
2. if response is `401`, try refresh once
3. if refresh succeeds, retry the original request once
4. if refresh fails, clear local auth state

Do not loop forever.

### 4. Handle popup lifecycle explicitly

Treat these as first-class outcomes:

- popup blocked
- popup closed before completion
- popup message from untrusted origin
- popup success with no access token
- popup success but local session exchange failed

That is not edge-case behavior. It is normal browser behavior.

### 5. Keep a degraded mode

If auth is unavailable:

- show cached state where it is safe
- disable write actions
- explain whether the failure is login, refresh, policy, or service availability

Do not hard-crash the whole app if auth is temporarily down.

## Backend Proxy Rules

If your app proxies Continental ID through Nginx, Caddy, Cloudflare, or another edge:

- preserve `Host`
- preserve `X-Forwarded-Proto`
- preserve cookies unchanged
- do not strip `HttpOnly`, `Secure`, `SameSite`, or `Path`
- do not make the browser call a backend port directly after login
- keep the public app origin and the proxy origin aligned

If those are wrong, the symptom is usually:

- login works
- refresh silently fails later
- users report "random logout"

That is almost always a deployment problem, not an auth-controller bug.

## Trusted Origins

Origin configuration must be explicit.

At minimum, allow:

- the public app origin
- the public login origin
- any real staging origin
- localhost only in development

If you add a new frontend domain and forget to update trusted origins, the failure mode is often:

- popup opens
- provider login succeeds
- final app handoff is rejected

Treat origin updates as part of every deployment change, not a separate cleanup task.

## Cookie Rules

Continental ID uses short-lived access tokens plus refresh cookies.

Integration requirements:

- access token in memory only
- refresh token in `HttpOnly` cookie
- HTTPS in production
- same-origin proxying whenever possible

Do not put the refresh token in JavaScript storage.

Do not assume localhost cookie behavior matches production.

## Email Verification and MFA

Do not flatten these into generic "login failed" errors.

If login returns:

- `requiresVerification: true`
- `mfaRequired: true`
- `retryAfterSec`

your UI should expose those exact states:

- verification pending with resend path
- MFA challenge required
- cooldown in progress

That is the difference between diagnosable auth and support nightmares.

## Minimal Integration Patterns

### Popup open

```ts
const popupUrl = new URL(LOGIN_POPUP_URL)
popupUrl.searchParams.set("origin", window.location.origin)
popupUrl.searchParams.set("redirect", `${window.location.origin}/auth/complete`)
popupUrl.searchParams.set("apiBaseUrl", window.location.origin)

window.open(popupUrl.toString(), "continental-id-login", "popup=yes,width=520,height=760")
```

### Auth result parsing

```ts
function parseAuthResult(data: unknown) {
  if (!data || typeof data !== "object") return null
  if (data.source !== "continental-id") return null
  if (data.type !== "auth-result") return null
  return data
}
```

### Authenticated request

```ts
async function authorizedFetch(input: RequestInfo, init: RequestInit = {}) {
  let response = await fetch(input, withBearer(init))
  if (response.status !== 401) return response

  const refreshed = await refreshSession()
  if (!refreshed.ok) {
    clearAuthState()
    return response
  }

  response = await fetch(input, withBearer(init))
  return response
}
```

## Integration Checklist

Before release, verify all of this on the real deployed origin:

- login works from the public app domain
- refresh works after the original access token expires
- popup blocked state is user-visible
- popup close state is user-visible
- redirect-hash recovery works if opener messaging is disrupted
- `/api/auth/*` is first-party from the app origin
- `/me` mismatch forces logout or degraded mode cleanly
- verification-required and MFA-required states are distinct in the UI
- all apps reject untrusted popup origins
- logs capture the correlation ID for auth failures

## Common Bad Integrations

Do not do these:

- browser calls `https://host:5000` directly in production
- app stores long-lived auth in `localStorage`
- app retries refresh indefinitely
- app assumes popup success means session success
- app ignores redirect-based recovery
- app uses display name as identity
- app derives Discord link state on its own instead of reading the Continental ID payload

## If You Need App-local Sessions

Some apps, such as control centers, exchange a Continental ID access token into an app-local session.

If you do that:

1. validate the Continental ID access token on the server
2. load `/api/auth/me` server-side
3. apply your app policy checks there
4. return machine-readable auth errors to the client
5. set your app-local cookie only after all policy checks pass

Do not split those checks between popup JS, frontend JS, and app-local backend logic in inconsistent ways.

## Summary

The reliable Continental ID integration is:

- same-origin `/api/auth/*` proxying
- popup plus redirect-hash recovery
- canonical `auth-result` payloads
- one retry on `401`
- one centralized auth store
- explicit handling for verification, MFA, popup failure, and refresh failure

If you keep those rules, the integration is stable. If you skip them, auth will fail in ways that look random but are actually deterministic deployment mistakes.
