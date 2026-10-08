# Security Policy

## Reporting a Vulnerability

Do not open public issues for security problems in the authentication or account system.

Report vulnerabilities privately to the project maintainer with:

- a short description of the issue
- affected routes or files
- reproduction steps
- impact assessment
- any proof-of-concept material needed to verify the report

If email reporting is available for your deployment, use the same support/security contact that is
configured for account and login notifications. If there is no dedicated contact yet, establish one
before treating the dashboard as production-ready.

## Scope

This project contains a live authentication surface, including:

- password login and refresh sessions
- email verification and password reset
- MFA and backup codes
- passkeys / WebAuthn
- OAuth account linking and sign-in
- public profile discovery endpoints

Treat changes in those areas as security-sensitive by default.

## Production security contract

- Keep `JWT_SECRET` and `REFRESH_TOKEN_SECRET` strong and unique per environment.
- Run the backend only behind HTTPS in production.
- Set `TRUST_PROXY` correctly when the service is behind a reverse proxy.
- Restrict `ALLOWED_ORIGINS` to exact trusted browser origins; keep `IDENTITY_MANAGEMENT_ORIGINS` limited to canonical login/dashboard hosts.
- Review login, reset, OAuth, MFA, and passkey flows after any auth-related change.
- Avoid logging secrets, reset tokens, verification tokens, backup codes, or raw cookies.
- Keep JWT signing secrets inside identity infrastructure; never distribute them to relying applications.
- Set a distinct `MFA_SECRET_ENCRYPTION_KEY`; blind key replacement can lock MFA accounts out.
- During rollout, keep legacy MFA key material available until encrypted TOTP secrets and backup codes have been migrated or replaced.
- Required indexes and startup maintenance must succeed before traffic is served. Reconcile legacy conflicts through backed-up explicit migrations, not index drops or automatic credential deletion.
- Do not deploy the local-development Compose configuration as production infrastructure.

The current architecture, threat model, implemented controls, limitations and incident/restore procedures are documented in [the identity security audit](docs/identity-security.md). Application teams must follow [the integration contract](docs/continental-id-integration.md), including exact popup-window validation, target-bound tokens and database-aware session revocation.

## Change verification

Run `npm run check`, `npm run lint`, `npm run typecheck`, `npm test` and `npm run audit` in `backend/`. Add regression tests for changed security properties, including concurrent requests and alternate authentication routes. Tests use disposable Mongo and fixtures, not production credentials or outbound mail. Type checking currently covers selected security utilities only.

No passing test suite establishes production TLS/proxy topology, provider registrations, backup integrity, privacy retention or incident readiness. Those remain explicit operational responsibilities.
