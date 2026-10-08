# Continental ID integration contract

## Trust model

Continental ID's login/dashboard hosts are highly trusted credential and account-management surfaces. An ordinary Continental application is a relying party, not an identity administrator. CORS permission does not grant account-management permission.

`ALLOWED_ORIGINS` contains exact HTTPS browser origins in production. `IDENTITY_MANAGEMENT_ORIGINS` is a smaller subset containing only canonical login/dashboard hosts. Registered `AuthApp` records contain active/disabled status, allowed browser origins, allowed redirect origins and provider requirements. Do not register wildcards or arbitrary callbacks.

A reverse proxy that receives passwords, provider callbacks or refresh cookies becomes part of the identity trust boundary. Do not distribute the canonical management cookie across application hosts or rewrite its Domain. Production refresh cookies are host-only; a cookie issued at an app proxy is not a cross-host shared identity session. The signed shared device cookie is a recognition hint, not authentication.

The current system is not an OIDC authorization server. It has no public discovery/JWKS, standards-based client credentials, authorization codes for relying parties or audience-isolated external access-token ecosystem. Do not give applications the JWT signing secrets. Use server-side identity verification and enforce application policy.

## Canonical flow

1. Open the canonical login popup with registered `appId`, exact receiving `origin` and a return URL on an allowed redirect origin.
2. The popup authenticates against the canonical identity API. Password and passkey requests include the intended `targetOrigin`; OAuth binds it in signed, one-time browser-bound state.
3. The popup may reuse a central cookie via `POST /api/auth/refresh_token`, passing `targetOrigin`, then load `GET /api/auth/me`.
4. Receive the result only from the exact trusted popup origin AND the exact window returned by `window.open`.
5. Keep the access token in memory. For registered app bootstrap call `POST /api/auth/bootstrap` with JSON `{ appId, accessToken }`, a permitted Origin and no token in the URL.
6. Apply `requirements` and `appAccess` policy before creating any app-local session.

Tokens handed to applications lack account-management authority. A non-management session remains bound to its application origin through refresh. Bootstrap cannot exchange an application's token/session into another application's identity. Grimoire also checks the token's target against its active registered origins, then qualifies all deck operations by authenticated owner ID.

Management sessions can deliberately obtain app-scoped tokens. Never use `/me` or a role displayed in client state as authorization for an app's own privileged operations.

## Popup result

The canonical message shape remains:

```json
{
  "source": "continental-id",
  "type": "auth-result",
  "event": "login_success",
  "correlationId": "request-id",
  "accessToken": "short-lived-token",
  "token": "short-lived-token",
  "user": {}
}
```

Retain the popup window reference. A matching message shape is not a security check:

```js
const popup = window.open(loginUrl, 'continental-id-login', 'popup=yes,width=520,height=760');
window.addEventListener('message', (event) => {
  if (event.origin !== LOGIN_ORIGIN || event.source !== popup) return;
  if (event.data?.source !== 'continental-id' || event.data?.type !== 'auth-result') return;
  // Validate the payload, then use accessToken for server-side bootstrap.
});
```

Legacy result shapes and redirect-hash fallback still exist for compatibility. Consume a fallback hash once and immediately remove it with `history.replaceState`. Never send it to telemetry, log it, or leave it in the address bar. A future one-time-code/BFF handoff is safer than exposing bearer tokens in fragments.

`apiBaseUrl` is an endpoint-selection hint, not authority to send credentials to any URL. The frontend filters known trusted hosts, but deployments should explicitly pin their canonical host and retire obsolete trusted candidates.

## API behavior

- Login: `200` with an access token after successful authentication; wrong credentials share a generic response. MFA challenge, suspension, verification and throttling are explicit states.
- Refresh: `200 authenticated:false` means the session cannot be reused. `503` means temporary failure; preserve cookies and retry with bounded backoff. `409` may indicate concurrent state changes; do not retry forever.
- Logout: revokes the server-side session and clears the cookie. Failure returns a retryable error rather than claiming revocation succeeded.
- `/me`: checks the current database/session state. Application responses are limited to identity/display fields; management responses include account settings.
- Sensitive account operations require a management token; password/MFA reauthentication is additionally required for credential-changing flows.
- OAuth link/unlink requires current password and MFA when enabled. Removing an identity/passkey forces fresh login.

Read `error.code`, `retryAfterSec`, `reauthenticationRequired` and `correlationId`. Recognize `auth/insufficient-scope`, `auth/session-revoked`, `auth/account-suspended`, `auth/email-unverified`, `auth/mfa-required` and `auth/unavailable`.

## Browser and proxy requirements

Cookie-authenticated browser mutations require trusted Origin (or validated Referer fallback); bodies must be JSON. CORS is credentialed and allowlisted, not wildcard. Bearer-only APIs do not accept cookies as authorization.

Passkeys require correct RP ID, HTTPS origin and user verification. Cross-site refresh cookies use SameSite=None and Secure and may still be blocked by browser privacy policy; same-site cookies use Lax. Host-only cookies deliberately change old shared-domain session behavior.

Proxies must preserve intended public origin, bearer headers, cookie attributes and TLS semantics, and strip untrusted forwarding headers. `TRUST_PROXY=1` is safe only when exactly one trusted hop is guaranteed and the backend cannot be reached directly.

Use one refresh-in-flight promise, retry a failed authenticated call once after refresh, and enter signed-out/degraded mode after bounded retries. Do not automatically replay non-idempotent writes unless their contract supports it.

## Privacy and service boundaries

Use stable `userId`/`continentalId` for identity, never mutable email, username or display name. IDs are not authorization. Bootstrap retains primary email for existing integration compatibility, but omits login IP/history and unnecessary provider details. Linked providers normally expose a linked boolean; apps requiring a provider may receive its provider identifier.

Vanguard uses separate timing-safe shared API keys for its limited resolve/flag/license surface. Do not expose those keys to browsers or treat them as owner credentials. Rotate using overlapping `VANGUARD_API_KEYS`, then retire old keys.

A compromised app receiving a password or a signing secret is outside the protection offered by down-scoped bearer tokens. Centralize credential entry; a full OIDC/BFF relying-party flow remains the highest-value next architecture improvement.

## Automated verification

Run `npm test` in `backend/`. Disposable Mongo fixtures exercise refresh, bootstrap, cross-app denial, revocation, cookies, password/MFA recovery and provider mocks without production credentials. Local tests do not establish deployed browser compatibility, DNS/TLS correctness or upstream client registration.
