# Continental ID identity security audit

Audit and local hardening: September 30, 2026. This documents repository behavior and local verification, not an assertion that the deployed infrastructure is secure. No production deployment or destructive production operation was performed.

## 1. Original architecture

The backend was an Express 4 application with Mongoose/MongoDB and a large authentication controller. Static dashboard and login JavaScript held access JWTs in memory and refreshed through cookies. User documents combined identity, password, embedded sessions, OAuth links, MFA/passkeys, settings, known devices, bounded login history and audit events. AuthApp records represented relying-party origins/policies. Grimoire decks shared the backend/database but were owner-qualified. Vanguard used separate shared API keys for its limited service interface.

Passwords used bcrypt; tokens used HS256 with issuer/audience/type hardening plus a legacy fallback. Refresh sessions stored sid, current jti and previous jti with a short overlap. Protected requests consulted the user database for role/status and revocation. Recovery and verification stored SHA-256 hashes of random tokens. MFA secret encryption and protected backup-code hashes were already present. SimpleWebAuthn performed credential verification.

External authentication was OAuth for GitHub/Discord and OIDC-capable Google/Microsoft login. Continental ID was the client, not an authorization server. Signed state, email-collision rejection and explicit linking were useful existing mechanisms. However, state lacked browser binding and consumption, OIDC ID tokens were decoded rather than verified, and mutable owner-email configuration/first-registration bootstrap undermined privilege boundaries.

Startup also ran broad identity/passkey maintenance and index synchronization after traffic could begin. Deployment examples exposed local Mongo/API ports more broadly than necessary. Existing tests covered integration contracts but did not comprehensively exercise concurrency or isolate inherited email credentials.

## 2. Threat model and boundaries

| Attacker / failure | Boundary and implemented protection | Residual assumption |
| --- | --- | --- |
| Anonymous attacker, malformed automation | Strict token types/lifetimes, JSON/origin checks, body bounds, indexed atomic IP admission limits | Edge connection/body limits and capacity remain necessary |
| Credential stuffing/password spraying | Cost-12 bcrypt, dummy comparisons, atomic failure counters, endpoint admission, IPv6 /64 grouping, IP budget survives successful login | Distributed attacks require adaptive detection; IP is not an identity |
| Malicious authenticated user | DB-backed authorization, allowlisted mutation fields, ownership-qualified app queries | IDs are never permission; new routes need the same checks |
| Compromised Continental app | Management scope is separate; session/app target binding, no cross-app bootstrap, Grimoire target enforcement, minimal identity payload | Credential proxies and shared signing secrets are still high-trust infrastructure |
| OAuth redirect/confused deputy | Exact allowed origins, signed app/provider state, host cookie binding, PKCE, nonce, single-use DB transaction, fixed provider URLs | Provider registrations and hosted login integrity must match configuration |
| CSRF/session fixation | Trusted origin/Referer and JSON on cookie mutations; fresh sid/jti at sign-in; host-only refresh cookie | Browser compromise/XSS can act as the user despite HttpOnly |
| Session theft/replay | Short-lived access, active Mongo session required, rotation, bounded overlap, server revocation and expiry | Stolen current credentials remain usable until detection/revocation |
| Recovery abuse/email compromise | Hashed random expiring single-use reset/verification tokens, generic recovery response, atomic consumption, MFA retained after reset | Mailbox possession remains recovery authority; email alone must not remove MFA |
| Administrative mistake/stale privilege | No automatic owner grant, explicit CLI assignment, DB role checks, privilege-change revocation, production owner MFA and fresh admin session | Concurrent multi-owner removal still needs a serialized control plane |
| Database leak | Cost-12 password hashes, encrypted MFA secrets, HMAC backup hashes, hashed recovery tokens | Full DB write compromise can alter authority; secret theft defeats encryption |
| Dependency/database/mail outage | Fail-closed authorization, bounded provider/mail/DB transport waits, sanitized errors, startup index gate, durable deletion cleanup | Transport bounds are not a complete end-to-end request deadline |
| Compromised browser/client | Minimal app data and down-scoping limit blast radius | No server control can make an actively compromised browser trustworthy |

The browser-to-edge, edge-to-identity API, identity API-to-Mongo, identity API-to-email/provider, identity-to-relying-app and operator-to-admin boundaries are distinct. CORS is browser policy, not authorization. Origin checks cannot authenticate an arbitrary server client; cryptographic session/app claims must carry that responsibility.

## 3. Significant original weaknesses

These are severity assessments of observed code weaknesses, not claims of confirmed exploitation.

### Critical

- First public registration could obtain owner authority; reads could restore owner privilege based on mutable configured email. Removed all automatic grants, including dormant helpers.
- Application bearer tokens were accepted by central account-management endpoints, including owner capabilities for an owner account. Management session/claim and application target boundaries now restrict those tokens.

### High

- OAuth state was not bound to the initiating browser or consumed once, lacked PKCE/nonce, and OIDC ID tokens were unverified. Microsoft could infer verified email without explicit evidence.
- Refresh/reset/verification/MFA code processing depended on stale read-then-save snapshots, permitting competing operations to undo security state or reuse one-time material.
- Suspension checks were inconsistent across alternate sign-in paths; access authentication accepted sessionless/legacy forms; sessions lacked independent absolute/idle expiration.
- Refresh cookies shared a parent domain, increasing sibling-application compromise exposure. Bootstrap omitted cookie-CSRF protection, and production relied on broad built-in origin assumptions.
- bcrypt input length was not bounded in UTF-8 bytes, allowing silent truncation ambiguity; lower work-factor hashes lacked a safe upgrade path.
- MFA secret decryption failure could undermine enrollment checks; TOTP/backup codes lacked atomic one-use enforcement.

### Medium / reliability

- Rate counters lost increments; IPv6 textual/address variants bypassed IP dimensions; successful login could erase an IP stuffing budget. Account-only blocking also enabled attacker-induced victim lockout.
- Privilege/credential transitions did not consistently revoke sessions. Unlink/removal could leave previously issued sessions alive.
- Inline OAuth result JSON could close its script with attacker-controlled profile text. Popup consumers did not consistently require the exact opened window.
- Raw parser/database/provider errors could disclose submitted values. Express 4 async rejection handling was inconsistent.
- Background migrations/index synchronization could race traffic or mutate credentials unexpectedly; deletion left dependent app data; mail/provider waits were insufficiently bounded.
- Local infrastructure exposure, root container execution, incomplete startup validation and test dotenv inheritance increased deployment risk.

Registration still intentionally reports a conflicting email/username; verification and known-account challenge states also reveal limited information. This is a usability tradeoff, not a promise of perfect account-enumeration resistance.

## 4. Implemented authentication and recovery model

Registration uses explicit fields, database unique constraints and a random 32-byte verification token stored only as its hash. New accounts are unverified ordinary users. Verification atomically consumes a nonexpired token. Email changes require password/MFA, clear verification and revoke all sessions; mail failure cannot silently retain the old verified state.

Password login checks account state, generic credential errors, failure budgets and MFA when enabled. Unknown-account comparison performs bcrypt work. Existing bcrypt hashes below cost 12 upgrade on successful comparison through compare-and-set, without saving a stale account snapshot. New passwords preserve exact Unicode input, reject NUL and exceed neither 72 UTF-8 bytes nor bcrypt's input boundary. The existing minimum-eight-character/composition policy is retained; moving to longer passphrases, breached-password screening and Argon2id needs a deliberate compatibility plan. Legacy overlength passwords may require recovery.

Recovery generates 32 random bytes, stores SHA-256 plus expiry, and gives the same public request response for existing/missing accounts and delivery failure. Password reset hashes the new password first, then atomically matches account version, token hash and expiry; only one competitor succeeds. It clears the token, increments revocation/version, removes sessions and retains MFA. Mailbox compromise alone must not disable existing MFA. Verification/reset issuance and other settings saves use optimistic concurrency; a losing concurrent operation can fail and require retry rather than overwrite newer security state.

TOTP uses OTPAuth, not a custom implementation. MFA enrollment is determined by the enabled flag and fails closed if the secret cannot decrypt. Pending setup expires in ten minutes. Accepted TOTP steps and backup-code removal are compare-and-set single-use operations; backup codes contain 64 bits of randomness and are stored as keyed protected hashes. Secrets use established AES-GCM primitives with distinct scoped keys; production requires an explicit distinct encryption key. UV-required passkeys use SimpleWebAuthn, registered RP/origin checks and DB-backed one-use challenges. Suspension/verification checks apply to every session-issuing path.

## 5. Session and authorization architecture

Access JWTs default to 15 minutes; refresh JWTs default to seven days. Both require HS256, issuer, distinct audience/type, iat/exp, user ID, sid and integer revocation version; refresh requires jti. Mongo holds at most twelve embedded sessions, with random UUID identifiers, creation/last-refresh time and current/previous refresh IDs. Rotation converges concurrent requests onto one winner. The previous token is accepted for a bounded default 15-second overlap without another rotation or idle extension; replay outside that overlap revokes its session.

Mongo independently enforces seven-day absolute and 24-hour idle lifetimes by default. Idle activity means successful refresh, not every data request. JWT lifetimes cannot extend absolute session age. Restart preserves valid sessions/challenges/rate buckets because state is persisted; no process-memory-only revocation mechanism is used.

Production refresh cookies are host-only __Host-continentalRefresh, Path=/, Secure, HttpOnly, Lax for same-site traffic and None only for cross-site use. Device cookies remain signed shared recognition hints: forging/reusing one does not bypass credentials or MFA. OAuth binding cookies are host-only Secure HttpOnly Lax. Logout invalidates the server session before claiming success; failures preserve retry state. Legacy domain refresh cookies are retired, not accepted as a compatibility authentication bypass.

The model save hook revokes all sessions on password, role, suspension, email, unverify or MFA-secret/enrollment transitions unless explicit revocation already occurred. Password reset uses an equivalent atomic update. Provider unlink and passkey removal also revoke all sessions. Single/device/all-session revocation is server-side and checked on the next protected request, including access-token requests.

There are two roles, user and owner; no new enterprise RBAC framework was introduced. Middleware reads the authoritative DB role/status. Identity management additionally requires both a session flag and token claim, issued only through management origins. Down-scoped app tokens cannot reacquire it. Non-management sessions and JWTs carry a server-derived application origin; refresh cannot change it, and bootstrap cannot exchange it for another app. Grimoire validates the registered active target and document ownership. Production owner administration requires enrolled MFA; mutations require an interactive session younger than ten minutes, not a refreshed token masquerading as reauthentication.

The Mongo ObjectId/continentalId is a stable public account reference, not a secret; email and username are mutable login identifiers, display name is presentation only, provider sub/ID is a link key, and sid/jti are security-sensitive token/session references. No route should authorize using guessed-ID difficulty.

## 6. OAuth/OIDC and internal-service authentication

OAuth transactions store hashed random transaction/browser identifiers, server-side PKCE verifier, nonce and expiry. Signed state carries provider/app/redirect context and transaction ID, not the verifier. Callback atomically deletes the matching unexpired browser-bound transaction before contacting the provider. Linking also binds the authorizing sid/version and requires password/MFA. There is no email-based automatic linking; collisions require authentication to the existing account.

Google/Microsoft ID tokens are verified by jose against fixed provider JWKS with RS256, issuer, client audience, required claims, maximum age, nonce, userinfo sub and authorized-party checks. Microsoft tenant and issuer must agree; a configured concrete tenant is enforced. Email verification is not inferred from missing Microsoft claims. Provider calls have cancellation bounds and reject redirects. Provider refresh tokens are not used as a Continental session or general API authority.

Continental ID does not implement an OIDC authorization server. Application integration uses scoped JWT/bootstrap and popup contracts. HS256 signing material must remain inside identity infrastructure: giving it to a relying party grants minting power. Vanguard uses timing-safe distinct shared service keys with optional overlapping rotation; these authorize only its service routes, not owner administration. There is no general user-created API-token framework.

## 7. Security regression verification

New tests use disposable real Mongo databases with required indexes, controlled keys, forbidden external fetches except explicit mocks, actual signed WebAuthn assertions and signed RSA OIDC tokens. They verify mass-assignment/owner denial; management and cross-app denial; CSRF/content type/size/origin rejection; production cookie attributes; logout/session revocation; concurrent refresh convergence; stale-snapshot denial; role/status/verification revocation; expiry/legacy/type/audience rejection; concurrent reset/verification/registration; MFA fail-closed/TOTP and backup replay; UTF-8 truncation and rehash; generic recovery; atomic/IPv6/nonresettable IP budgets; browser-bound OAuth single use/provider failure; suspension across OAuth/passkeys; unique indexes; deletion recovery; sanitized outage handling; configuration validation; inline JSON escaping and bounded mail transport.

Run from backend: npm run check, npm run lint, npm run typecheck, npm test, npm run audit. The final handoff records actual results. Type checking is explicitly limited to selected security utilities; the full legacy controller/frontend is not statically typed. Real-provider registrations, browser privacy behavior, deployed proxy topology and capacity were not certified by local tests. The original baseline accidentally inherited developer mail configuration and made fixture Resend calls, rejected by the provider; dotenv/email isolation now prevents recurrence.

## 8. Operations that code cannot establish

- TLS, trusted proxy topology and network isolation: strip untrusted forwarding headers, prohibit direct public backend access, protect Mongo with least-privilege authentication/TLS/firewalls, and configure edge connection/body/time limits. Loopback local Compose is not a production deployment.
- Backups: encrypt, restrict access, define retention/RPO/RTO and routinely restore to an isolated environment with mail/provider egress disabled. Validate required indexes and identity collisions before cutover.
- Restore/rollback: restoring Mongo can resurrect revoked sessions, reset tokens, MFA codes and deletion jobs. Before serving restored data, rotate access/refresh signing keys, clear active sessions/challenges/recovery material through a reviewed migration, preserve/reconcile deletions and disable outgoing mail until validation. Do not roll back to code accepting legacy tokens or unverified OIDC.
- Signing rotation: current JWT keys have no key ring. Coordinate identity instances and consumers; replace distinct access/refresh keys to invalidate all sessions, OAuth state and device signatures. A rolling mixed-key deployment causes transient failures; use maintenance/controlled cutover until a supported key ring exists.
- MFA key changes: the dedicated production MFA key must be distinct from access and refresh signing keys. The reader tries the dedicated key first and then legacy key material so rollout can add the dedicated key without immediately locking out existing TOTP or backup codes. Keep the old refresh key unchanged until encrypted TOTP secrets are migrated and users have replaced old backup codes; blind key replacement or premature removal of the fallback can lock users out. Do not disable MFA to conceal decryption failure.
- Service/provider/mail secret rotation: overlap Vanguard keys, deploy consumers, then retire old keys. Rotate provider/mail credentials with coordinated configuration and restart; mail client credentials are cached for process lifetime.
- Incident response: suspend compromised accounts, revoke all sessions, reset passwords and inspect bounded audit events. For compromised providers/passkeys, unlink/remove and reauthenticate. For signing/DB write compromise, assume issuer-wide compromise, contain ingress/egress, rotate appropriate secrets and investigate immutable external evidence without collecting raw credentials.
- Define private security contact, alerts for authentication failure/outage/deletion backlog, database index failures, mail delivery failures and unusual owner actions. Audit history is bounded operational evidence, not a tamper-proof forensic ledger.

Startup waits for required indexes and pending deletion cleanup before listening, with no index-dropping synchronization or silent credential deduplication. Duplicate legacy data can block rollout and must be reconciled under backup/change control. Explicit identity/passkey migrations are operator actions, not surprise startup work. Account deletion records durable intent before deleting the user; failed dependent deck cleanup remains retryable on restart. Failed deletion intents for still-live users never delete their app data and may remain until reviewed/retried.

## 9. Remaining known risks and privacy limitations

- Concurrent removal of different last owners uses a count guard, not a multi-document serialized transaction. Two simultaneous removals can violate owner availability; use operational serialization until a transaction/control record is designed.
- Application integrations outside this repository must honor target binding, issuer/audience, DB/session revocation and app-local policies. A full standardized audience-isolated OIDC/BFF integration and asymmetric verification key distribution are absent.
- Trusted credential proxies, frontend third-party scripts/CDNs, stale trusted API candidates and a compromised management browser remain high-impact. This work does not eliminate supply-chain/XSS/browser threats.
- Distributed credential attacks, shared-NAT collateral throttling and recovery-response timing remain. Recovery/email counters/settings conflicts prioritize safe failure, not guaranteed concurrent success. Rate admission is Mongo-dependent; outage fails closed and can deny availability.
- Existing public-profile defaults expose opted-in/default-public fields; they were not silently changed. Primary email remains in app identity payloads for compatibility. Audit/login/device records contain IP and user-agent data. Login history is capped at 50 and audit at 120; count caps are not time-based retention. Operators must define retention for DB backups, logs, throttles and deleted-account data.
- Deletion cleanup runs at startup and can be explicitly retried; there is not yet a continuously supervised worker or backlog SLA. No reliable transactional email outbox or full request deadline/capacity certification exists.
- Legacy controller size and partial static typing remain maintenance hazards. Mongo uniqueness covers cross-account OAuth/passkey collisions, not every embedded-array or last-owner invariant. No blanket production-readiness guarantee is warranted.

## 10. Highest-value next improvements

1. Central-only credential entry and standards-based one-time-code OIDC/BFF relying-party flows, with per-client audience/scope, asymmetric verification and supported key rotation.
2. Serialize owner-authority transitions, add supervised deletion/email outbox processing, idempotency and bounded operation deadlines; test failover with a real replica set and multiple identity instances.
3. Capacity/adversarial load tests for cost-12 bcrypt, pool sizing and Mongo-backed limits; add privacy-conscious distributed abuse detection and operational alerts.
4. Explicit time-based privacy retention, app consent/minimal email disclosure, public-profile default review and tested deletion/restore reconciliation.
5. Gradually extract session/recovery/provider/authorization services from the large controller, extend static typing and browser automation, and constrain/pin frontend dependencies and canonical endpoints.

Design references: [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [OAuth security BCP RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html). These informed controls; they do not certify this deployment.
