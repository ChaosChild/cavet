# Decision points — when a design flag is warranted

The rule: **flag when a decision changes who can do what to which data.** Everything
below is worked instances of that rule. Skim the category you are in.

## Secrets and keys
- Where credentials, API keys, signing keys, tokens live (DB column, env, secret
  store, config file, browser storage) → **flag**.
- Rotation: is there a path to revoke/rotate without a deploy → flag if none.
- Key names, env var naming, config schema → quiet.

## Data at rest
- New store containing personal data, credentials, payment data, health data → flag:
  encryption, retention, who can query it.
- Caching a response that contains one user's data → flag: cache key must include the
  principal or the cache leaks across users.
- Table naming, index choice, ORM vs raw SQL (absent injection difference) → quiet.

## Trust boundaries and input
- Anything read from a request, file upload, webhook, message queue, or third-party
  response that will be parsed, executed, templated, or used in a query/path/URL →
  flag once, at the boundary.
- User-supplied URL that the server will fetch → flag: SSRF.
- User-supplied file name or path → flag: traversal, type confusion.
- Internal function refactor with no boundary change → quiet.

## Identity, authentication, authorisation
- New endpoint, page, job, or CLI action: who is allowed → flag if unspecified.
- Object access by id ("GET /invoices/{id}") → flag: ownership check, or IDOR.
- Session/token lifetime, where the token is stored client-side → flag.
- Login form layout, button copy → quiet.

## Third parties, webhooks, LLMs
- What data leaves the system, to whom, and whether it is required → flag.
- Inbound webhook: signature verification and replay → flag.
- LLM feature that combines operator instructions with untrusted content (documents,
  emails, web pages, user text) → flag: prompt injection; separate roles, constrain
  tools, treat model output as untrusted input.
- BYOK: whose key, where it lives, what the app logs about requests → flag.
- Choice of vendor with equivalent posture → quiet.

## Multi-tenancy
- Any query, cache, queue, file path, or index that is not tenant-scoped by
  construction → flag once, at the pattern level.

## Logging, telemetry, errors
- What appears in logs/analytics/error reports (tokens, PII, request bodies) → flag.
- Log format, level names → quiet.

## Background jobs, queues, cron
- How the job authenticates and what it can reach; whether a poisoned message can
  block or crash the worker → flag.
- Scheduling library choice → quiet.

## Explicit negatives (do not flag)
Naming, directory structure, code style, test framework, colour/typography, REST vs
RPC when auth is unchanged, monorepo vs polyrepo, ORM choice, language choice,
pagination style, sorting, most performance decisions, refactors that move code
without moving a boundary, "should we write tests for this".
