# Go — secure idioms

## Queries
- `db.QueryContext(ctx, "... WHERE id = $1", id)`; `fmt.Sprintf` into SQL is a
  finding. sqlc/squirrel/GORM parameterise for you — `gorm.Raw` still needs `?`.

## Processes
- `exec.Command(bin, args...)` — no shell, no `sh -c` with interpolated input.

## Paths and files
- `filepath.Clean` + `strings.HasPrefix(abs, base+string(os.PathSeparator))` after
  `filepath.Abs`; or `filepath.Rel` and reject `..`. Use `os.Root` (1.24+) or
  `os.DirFS` where possible.
- `http.FileServer` for static, with a scoped `http.Dir`/`fs.FS`.
- Archives: validate each `Header.Name` against the destination (zip slip).

## Crypto and randomness
- `crypto/rand` always; `math/rand` never for security.
- Passwords: `golang.org/x/crypto/argon2` or `bcrypt`. Tokens: 32 bytes from
  `crypto/rand`, base64url. Compare with `subtle.ConstantTimeCompare`.
- TLS: never `InsecureSkipVerify: true` outside a test with a comment saying so.

## HTTP
- Servers: set `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`; cap body with
  `http.MaxBytesReader`.
- Clients: custom `http.Client{Timeout: ...}`; the default client has none. Fetching
  user URLs: parse, resolve, block private/link-local (169.254.169.254) before dial
  via a custom `DialContext`.
- Redirects: validate `Location` against allowlist or require relative.
- Templates: `html/template` for HTML, never `text/template`. `template.HTML` is the
  place to look.
- JWT: `jwt.ParseWithClaims` with `WithValidMethods([]string{"RS256"})` and audience/
  issuer checks.

## Serialisation
- `encoding/json` fine; `encoding/gob` on untrusted input can be abused via
  resource exhaustion — cap size. YAML: `yaml.v3` `KnownFields(true)` for config.
- Untrusted XML: standard library is fine for XXE (no external entities) but cap size.

## Common gotchas
- Errors returned to clients: `http.Error(w, "internal error", 500)` and log the
  real error with a request id.
- `unsafe`, `reflect`-driven field setting from request data → mass assignment.
- Goroutine per request without limits on user-controlled work → DoS.
