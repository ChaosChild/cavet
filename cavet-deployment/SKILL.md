---
name: cavet-deployment
description: Infrastructure and deployment work — Terraform, CloudFormation, Pulumi, Bicep, Kubernetes manifests, Helm charts, Dockerfiles, Compose files, CI/CD pipelines and workflows, environment and runtime configuration, secrets management, TLS, networking and exposure, deploy scripts. Use whenever such files are written or changed and whenever how something will be deployed or hosted is being decided.
---

# cavet-deployment

Deployment is where a correct application meets a misconfigured world. Most of what
goes wrong here is a default that was never changed. Check the defaults.

## While writing

Apply these as you write; mention only what the operator will notice.

**Secrets.** Never in IaC source, Dockerfiles, `ENV`, build args, CI variables
printed in logs, or committed `.env`. Runtime injection from the platform secret
store; least-privilege access to that store; rotation path known.

**Identity and permissions.** One identity per service, scoped to what it uses.
Wildcards in IAM policies are a finding. CI: short-lived OIDC federation over
long-lived cloud keys; workflow `permissions:` set to minimum, not default.

**Exposure.** Nothing public that need not be: storage buckets, databases, admin
ports, management endpoints, metrics. Security groups / network policies default
deny. Public ingress terminates TLS with a real certificate; internal hops still
TLS where they cross a host.

**Containers.** Non-root user; pinned, minimal base image; no secrets in layers;
read-only root filesystem where possible; drop capabilities; resource limits;
health checks. Kubernetes: no `privileged`, no host namespaces, no
`automountServiceAccountToken` unless used, `securityContext` set.

**Storage and data.** Encryption at rest on; versioning/backups on for anything
that matters; public access blocked at the account level, not per bucket.

**Logging and audit.** Platform audit logging on; application logs shipped without
secrets; retention set deliberately.

**Rollback.** Know how this deploy is undone before it goes out.

Depth per platform: `references/containers.md`, `references/ci-cd.md`,
`references/cloud.md`. Read the one that matches.

## Then scan

Run `cavet-triage` with phase deploy. IaC scanning is in the default scanner set
(Trivy). If the operator has enabled Checkov, it runs too.

**Container image scanning is opt-in** because it mounts the Docker socket into the
engine — a real privilege escalation. Do not enable it on your own; tell the operator
it exists, what it costs, and let them decide in `config.yaml`. Filesystem and
config scanning need no such access and are always on.

## Leave a trace

Deployment decisions with lasting consequence — accepting a public endpoint,
choosing not to encrypt something, granting a broad permission for a stated reason —
go through `cavet raise` / `cavet resolve` like design items, so the reason survives
the person who made it.
