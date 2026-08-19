# Design review checklist

Sweep the finalised design against each heading. Report only what is absent or
undecided — not what you would have done differently.

## Assets and boundaries
- What data is handled; which of it is sensitive (credentials, personal, financial,
  health, secrets, proprietary)?
- Where does untrusted input enter (users, uploads, webhooks, queues, third-party
  responses, LLM outputs)?
- Where does data leave (third parties, logs, exports, LLM providers)?

## Identity and access
- How are callers authenticated for each new surface (endpoint, page, job, CLI, admin)?
- Authorisation model: per object? per tenant? per role? Where is it enforced?
- Session/token: storage, lifetime, revocation.

## Secrets
- Every secret named: where it lives, how it gets there, how it rotates.
- Nothing in source, config in VCS, build args, or client bundles.

## Data protection
- At rest: what is encrypted, with what key, who holds the key.
- In transit: TLS everywhere internal traffic crosses a host boundary.
- Retention and deletion: is there a path to delete, and does it reach backups/logs?
- Caching: keys include principal/tenant where content differs by them.

## Input handling
- Parsing untrusted formats (XML, YAML, serialised objects, archives) — safe parser
  settings, size limits.
- Anything used in a query, shell, path, URL, template, or header — parameterised /
  allowlisted at the boundary.
- File uploads: type, size, storage location outside web root, no execution.

## Third parties and integrations
- Least data shared; contract for what they do with it.
- Inbound: signature verification, replay protection, idempotency.
- Outbound: timeouts, no user-controlled destinations without allowlist (SSRF).

## LLM / AI features (if any)
- Untrusted content and instructions are separated; model output treated as untrusted.
- Tools available to the model are the minimum, and destructive ones require
  confirmation.
- Prompts/logs do not capture secrets or full user data unnecessarily.

## Multi-tenancy (if any)
- Tenant id is part of every key, query, path, and cache entry by construction.

## Operations
- Logging: what is logged, what is excluded (tokens, PII, bodies), where it goes.
- Failure modes: what happens when a dependency is down — fail closed for auth.
- Rate limiting / abuse on public surfaces.
- Monitoring for the abuse cases that matter here.

## Availability of a rollback / kill switch
- Can the feature be disabled without a deploy if it misbehaves?
