# Cloud IaC (AWS / GCP / Azure — provider-neutral)

## Identity
- One role/service account per workload; policies name resources, not `*`.
- No long-lived user keys for services; instance/workload identity instead.
- MFA and no root/owner use for day-to-day; break-glass documented.

## Network
- Default-deny security groups / firewall rules; ingress only from where it must.
- Databases, caches, queues in private subnets; no public IPs.
- Management ports (22, 3389, 5432, 6379, 27017…) never open to `0.0.0.0/0`.
- Egress restricted where feasible; VPC endpoints / private service connect for
  cloud APIs.

## Storage
- Block public access at the account/project level; per-bucket policies as well.
- Encryption at rest with a managed or customer key; TLS-only bucket policies.
- Versioning and lifecycle rules for anything you would miss.

## Data services
- Encryption at rest and in transit on; automated backups on; deletion protection
  on for production; no public accessibility flag.
- Credentials via the platform secret manager with rotation, not in IaC.

## Compute and serverless
- IMDSv2 / metadata protection required; least-privilege instance profiles.
- Functions: minimum runtime permissions, environment variables are not a secret
  store, timeouts and concurrency limits set.

## Logging and monitoring
- Account-level audit logging (CloudTrail / Audit Logs / Activity Log) on and
  protected from deletion.
- Alerts on the handful of events that matter: root use, policy changes, public
  exposure changes.

## IaC hygiene
- State files contain secrets: remote backend, encrypted, access-controlled, never
  committed.
- Provider and module versions pinned; modules from trusted registries by version.
- Plan output reviewed for `destroy` and permission widening before apply.
