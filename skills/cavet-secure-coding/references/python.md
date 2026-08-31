# Python — secure idioms

## Queries
- DB-API: `cur.execute("... WHERE id = %s", (id,))` — never `%` or f-string into SQL.
- Django ORM: `.filter(id=x)`; `.raw()` and `.extra()` take params, use them.
  `RawSQL` with interpolation is a finding.
- SQLAlchemy: `text("... :id").bindparams(id=x)`; ORM query methods.

## Subprocess
- `subprocess.run([bin, arg1, arg2], shell=False)`; never `shell=True` with any
  untrusted component. `shlex.split` on trusted templates only.
- Prefer library calls to shelling out (`shutil`, `pathlib`, `zipfile`).

## Paths and files
- `base = Path(root).resolve(); p = (base / user).resolve(); p.relative_to(base)`
  raises if it escaped — that raise is the check.
- `tarfile.extractall(..., filter="data")` (3.12+) or member validation; zip slip
  needs the same resolve check per member.
- `tempfile.NamedTemporaryFile` / `mkstemp`, never `mktemp`.

## Serialisation
- `pickle`, `marshal`, `shelve`, `yaml.load` without `SafeLoader`, `jsonpickle` on
  untrusted input → no. `json`, `yaml.safe_load`, `pydantic` schemas.

## Crypto and randomness
- Passwords: `argon2-cffi` or `bcrypt`, or Django's default hasher.
- Tokens: `secrets.token_urlsafe(32)`. Compare with `hmac.compare_digest`.
- `random` is not for security. `hashlib.md5/sha1` only for non-security checksums —
  and say so in a comment, the scanner will flag it.

## Web
- Django: keep CSRF middleware; `mark_safe`/`|safe` only on data you constructed.
  `ALLOWED_HOSTS`, `SECURE_*` settings in prod. `is_safe_url` → `url_has_allowed_host_and_scheme` for redirects.
- Flask/Jinja: autoescape is on for `.html` templates; `Markup()`/`|safe` is the
  place to look. `send_from_directory` for user paths, not `send_file`.
- FastAPI: pydantic models as the allowlist for input; `Depends` for auth on every
  route, not per-handler if-checks.
- `requests`: always pass `timeout=`; never `verify=False`; validate host before
  fetching user-supplied URLs (resolve, block RFC1918/link-local/loopback).

## XML
- `defusedxml` for anything untrusted; stdlib parsers are XXE-prone by default.
  Parsing is the risk: string helpers like `xml.sax.saxutils.escape` never parse,
  so they are not XXE-relevant — `html.escape` is the idiomatic markup escaper.
  A flag on a non-parsing stdlib import gets a read-the-code adjudication, not
  an automatic rewrite.

## Common gotchas
- `assert` for validation is stripped under `-O`.
- `eval`/`exec` on anything with an untrusted component; `literal_eval` for data.
- `os.system` — no. `os.popen` — no.
