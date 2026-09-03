# Security policy

cavet is a security tool; reports about cavet itself get the same care it
asks of the code it scans. Thank you for handling them privately.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

Older releases do not receive security fixes; upgrade to the latest patch
release.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting**:
<https://github.com/ChaosChild/cavet/security/advisories/new>.

Do not open a public issue, pull request, or discussion for a vulnerability.

Please include:

- cavet version (`cavet version`) and the install channel
- platform (OS/arch) and, for engine issues, the image digest pinned in
  `.cavet/config.yaml`
- steps to reproduce, or a proof of concept
- relevant output, with secrets, keys, and session artefacts redacted. Never
  paste real findings that contain credentials. cavet's logs live in
  `.cavet/log/` inside your repository and never need to leave it.

## Scope

In scope:

- the `cavet` CLI
- the engine image (`ghcr.io/chaoschild/cavet-engine`) and its scanner
  configuration
- the installers (`installers/binary.sh`, `binary.ps1`) and the release
  checksum and Sigstore verification
- the install one-liner supply chain, including pinned CI actions
- the shipped skills, subagents, and `AGENTS.md` guidance, from an injection
  or abuse standpoint

Out of scope:

- vulnerabilities in the bundled upstream scanners themselves (Opengrep,
  Gitleaks, Trivy, Checkov) – report those to the upstream projects; cavet
  will help coordinate a pin or bump when a fix affects the engine image
- findings, or the lack of findings, in repositories that cavet scans. cavet
  advises and never blocks; a missed finding is a baseline question, not a
  vulnerability in cavet, unless the scan pipeline itself is at fault
- social engineering of harnesses that consume cavet's advisory output

## What happens next

Expect an acknowledgement within five business days, on a best-effort basis –
cavet is not the maintainer's primary focus, and reports are handled as time
allows alongside it. You will get an honest assessment, a fix or a recorded
decision, and credit in the release notes unless you would rather not.
