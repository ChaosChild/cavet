---
name: cavet-supply-chain
description: Adding, upgrading, replacing, or removing dependencies — packages, libraries, plugins, SDKs, GitHub Actions and other CI steps, container base images, lockfiles, package manifests. Use whenever a manifest or lockfile changes, whenever a library is proposed or compared, whenever `install`/`add`/`update` is about to run, and when the operator asks which library to use.
---

# cavet-supply-chain

A dependency is code you run with your privileges, written by someone you have not
met, updated on their schedule. The questions below take thirty seconds and are
cheaper than the incident.

## Before adding

1. **Is it needed?** Standard library or an existing dependency first. A
   dependency for a ten-line function is a liability, not a saving.
2. **Is it the right name?** Exact spelling against the canonical source. Typosquats
   are one character away and this is the moment to catch them.
3. **What is its posture?** Run `cavet lookup` on the package coordinate
   (`pkg:<ecosystem>/<name>@<version>`). You get advisories, deprecation, and
   registry status without leaving the terminal. Also worth a glance: last release
   date, maintainer count, whether it runs install scripts.
4. **What scope?** Dev-only dependencies do not ship. Put them there.
5. **Pin it.** Exact version in the lockfile; commit the lockfile; CI installs from
   the lockfile (`npm ci`, `pip install -r` with hashes, `go mod verify`).
6. **Licence** — one line if it is anything other than permissive; the operator
   decides.

Report the decision as one line per package: name, version, why this one, anything
notable from lookup. No table for a single package.

## Upgrading

- `cavet lookup` the advisory first: the **fixed version** is what you upgrade to,
  not "latest" by reflex.
- Read the changelog for breaking changes between installed and target. Say what
  changes in one line.
- Upgrade the lockfile and manifest together; run tests; then scan.

## Actions, CI steps, base images

- GitHub Actions and equivalents: pin to a full commit SHA, not a tag. Tags move.
- Base images: pin by digest for anything that must be reproducible; otherwise a
  specific version tag, never `latest`. Prefer minimal images (distroless, slim).
- Both are dependencies with the same questions as above.

## After

Run a scan with `cavet-triage` (SCA is in the default scanner set) so the change is
recorded and any advisory on the new tree is triaged now, not found later.

## When to leave a trace

Ordinary additions need no design item. Raise one (`cavet raise`, kind: design) when
the choice has lasting consequence: a dependency that handles auth, crypto, parsing
of untrusted input, or that requires elevated permissions or install scripts.
