# Continental ID

Continental ID is identity infrastructure, not an ordinary account CRUD API. It serves password, MFA, passkey and external-provider authentication, revocable sessions, account management, owner administration and application handoff.

Read [identity architecture, threat model and security audit](docs/identity-security.md), [integration contract](docs/continental-id-integration.md) and [security policy](SECURITY.md) before changing authentication or deploying.

## Local development

Use Node 22.13+ and MongoDB 7+. From `backend/`:

```bash
npm ci
cp .env.example .env
npm start
```

Replace development JWT secrets; production rejects placeholders. Never copy production credentials into test fixtures. Tests ignore developer dotenv files, disable email in test mode, and use disposable MongoDB instances.

Serve `frontend/` with a local static server. Login pages live in `frontend/login/`. Runtime globals `window.__API_BASE_URL__` and `window.__LOGIN_POPUP_URL__` select deployment endpoints. Production should pin the canonical identity endpoint; a healthy-looking endpoint is not proof of trust.

The checked-in Compose stack is local development only. Mongo and API ports are loopback-bound; it is not a production Mongo authentication, TLS, backup or replica-set configuration.

```bash
docker compose up --build
```

## Verification

```bash
cd backend
npm run check
npm run lint
npm run typecheck
npm test
npm run audit
```

Type checking currently covers selected security utilities, not the entire legacy controller or frontend. Tests cover Mongo-backed concurrency, real signed WebAuthn assertions, signed OIDC tokens, production cookie configuration and mocked provider failures. They do not certify deployed DNS, TLS, browser cookie policy, provider configuration or production capacity.

## Production requirements

Production startup validates strong distinct access/refresh/MFA secrets, exact HTTPS browser and management origins, canonical public API origin, mail configuration and fixed OAuth callbacks. Use `backend/.env.example` as a development template, not a production manifest.

- Set `NODE_ENV=production`, `PUBLIC_API_ORIGIN`, `ALLOWED_ORIGINS`, `IDENTITY_MANAGEMENT_ORIGINS`, `MFA_SECRET_ENCRYPTION_KEY`, `RESEND_API_KEY`, `EMAIL_FROM` and `LOGIN_POPUP_URL`. With the local Caddy TLS proxy, explicitly set `TRUST_PROXY=1`.
- Terminate TLS at a specifically trusted proxy, with the backend inaccessible directly, or use `HTTPS_MODE=on` with readable certificate files. Never trust every proxy peer.
- On rollout, keep the existing refresh signing key unchanged while the new dedicated MFA key is introduced. The backend can still read MFA secrets and backup codes encrypted with the previous key; rotate signing keys and retire old key material only after an explicit MFA migration.
- Distinguish identity-management hosts from application hosts. Do not place an ordinary application in `IDENTITY_MANAGEMENT_ORIGINS`.
- Required unique/TTL indexes are created before listening. Conflicting data causes startup failure; indexes are not automatically dropped or duplicate credentials deleted.
- Bulk identity migration is an explicit, backed-up operation: `npm run migrate:users`. Startup no longer runs a full-user migration.
- Owner roles are assigned deliberately using `npm run owner:set -- user@example.com`; public registration and owner-email environment lists cannot grant them. Promotion requires a verified active account; production administration requires MFA.
- Existing legacy/domain-cookie sessions may require fresh login after this security rollout. Coordinate the change across applications; do not reintroduce legacy authentication fallback.

Deployment helpers and Caddy login hosting remain under `deploy/` and `backend/`. Read the restore, rollback and incident requirements in the security audit before using them against production.

After pushing a reviewed commit, run `./backend/deploy-backend.sh` from the checkout to deploy the backend version into the user systemd service's configured working directory. It preserves the deployment `.env`, validates production configuration before stopping the service, runs the backend checks, installs locked production dependencies, keeps a source backup, and verifies database and startup-maintenance health before reporting success. Configure the production variables listed above first; the helper intentionally refuses to stop the current service when they are missing or invalid.

## Authentication contract

Access JWTs are short-lived and kept in frontend memory. Production refresh cookies are host-only `__Host-continentalRefresh`, HttpOnly and Secure; sessions are checked in Mongo on every protected request. Password, role, suspension, email and MFA changes revoke sessions. Unlinking an identity or removing a passkey revokes all sessions.

Application handoffs are down-scoped: account management requires a management session and claim; application tokens carry a target origin. Grimoire enforces its registered application boundary and document ownership. Continental ID is an OAuth/OIDC client, not a standards-compliant OIDC authorization server.

See [the integration guide](docs/continental-id-integration.md) for popup source checks, refresh retry behavior, app bootstrap and trust limitations.

The local multi-service harness, contract inventory, checked boundaries, and explicit-ref CI workflow are described in [the Continental ecosystem integration guide](docs/continental-ecosystem-integration.md).

## Legal and reporting

See [LICENSE](LICENSE), [TERMS.md](TERMS.md), [privacy policy](frontend/privacy.html), and [private vulnerability reporting](SECURITY.md).
