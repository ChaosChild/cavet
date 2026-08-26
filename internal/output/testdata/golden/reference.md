scan: staged · scanners: gitleaks,trivy · phase: build · engine: cavet-engine@sha256:4f2a…
2 confirmed (1 high, 1 medium) · 14 dismissed · 0 new suppressions · baseline 347

| id     | sev    | rule              | location          | description                        |
|--------|--------|-------------------|-------------------|------------------------------------|
| a3f9c2 | high   | py.sql-injection  | api/users.py:88   | user input concatenated into query |
| 7b1e04 | medium | generic.weak-hash | auth/tokens.py:23 | MD5 used for token derivation      |

next:
  cavet finding a3f9c2 --full
  cavet log --fingerprint 7b1e04
