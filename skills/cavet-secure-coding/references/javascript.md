# JavaScript / TypeScript — secure idioms

## Queries
- Parameterised drivers: `pool.query("... $1", [id])` (pg), `?` placeholders
  (mysql2), Prisma/Drizzle/Knex builders. Template-literal SQL is a finding unless
  the library tags it for parameterisation (`sql\`...\`` from a known helper).
- Mongo: never build query objects from raw request JSON (`{ $gt: "" }` injection);
  validate types with zod/joi first.

## Child processes
- `execFile`/`spawn` with an argument array; `exec` (spawns a shell) only with fully
  trusted strings. Never interpolate request data into a command.

## Paths and files
- `const p = path.resolve(base, user); if (!p.startsWith(base + path.sep)) reject`.
- Serve static via the framework's static handler, not `res.sendFile(userPath)`.
- Archive extraction: validate each entry path the same way (zip slip).

## Serialisation and parsing
- `JSON.parse` is fine; `eval`, `new Function`, `vm.runInContext` on input is not.
- Prototype pollution: don't deep-merge untrusted objects into config; use
  `Object.create(null)` maps or a merge that rejects `__proto__`/`constructor`.
- Watch `qs`-style nested query parsing when validating.

## Crypto and randomness
- Passwords: `argon2` or `bcrypt` package. Tokens: `crypto.randomBytes(32)` /
  `crypto.randomUUID()`. Compare with `crypto.timingSafeEqual` (equal-length buffers).
- `Math.random()` never for security. Browser: `crypto.getRandomValues`.

## Web (Node)
- Express: `helmet`, explicit CORS origin list, cookie `httpOnly; secure; sameSite`.
  Rate limit auth endpoints. Validate body with a schema before touching it.
- Redirects: allow relative paths or an allowlist; `res.redirect(req.query.next)`
  is a finding.
- Fetching user URLs: resolve host, block private ranges, set timeouts, cap size.
- JWT: `jsonwebtoken.verify(token, key, { algorithms: ["RS256"], audience, issuer })`
  — always pass `algorithms`.
- Next/React server: never put secrets in `NEXT_PUBLIC_*`; server actions need auth
  checks like any endpoint.

## Web (browser)
- React escapes by default; `dangerouslySetInnerHTML` and `innerHTML` are the places
  to look — sanitise with DOMPurify if unavoidable.
- No tokens in `localStorage` for high-value sessions; prefer httpOnly cookies.
- `postMessage`: check `event.origin`. `window.open` with `noopener`.

## Ecosystem
- Lockfile committed; `npm ci` in CI; avoid `postinstall` scripts from new packages;
  check the exact name (typosquats). `npm audit` output → `cavet lookup` for triage.
