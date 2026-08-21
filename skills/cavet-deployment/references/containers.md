# Containers and Kubernetes

## Dockerfile
- `FROM image:specific-tag` or `@sha256:...`; minimal base (distroless, alpine,
  slim). Multi-stage: build tools do not ship.
- `USER nonroot` (create it) before `CMD`. Writable dirs owned by that user.
- No `ADD` from URLs; `COPY` explicit paths, `.dockerignore` excludes `.git`, `.env`,
  keys, node_modules.
- No secrets in `ENV`, `ARG`, or layers — a deleted file in a later layer is still in
  the image. BuildKit `--mount=type=secret` for build-time secrets.
- `HEALTHCHECK` defined. `EXPOSE` only what is served.
- Pin package versions inside `RUN apt-get install …` where reproducibility matters.

## Compose
- No `privileged: true`; no host network unless justified; no Docker socket mounts
  unless the service is a container manager (and then say so in a decision record).
- Secrets via `secrets:` or env files that are gitignored, not inline.
- Named volumes over host bind mounts for data; read-only where possible.

## Kubernetes
- Pod `securityContext`: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`,
  `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, seccomp
  `RuntimeDefault`.
- Never `privileged`, `hostPID`, `hostNetwork`, `hostIPC`, or `hostPath` for
  application pods.
- `automountServiceAccountToken: false` unless the pod calls the API; RBAC per
  service account, no cluster-admin bindings for workloads.
- Resource `requests`/`limits` on every container.
- `NetworkPolicy` default-deny per namespace, allow explicitly.
- Secrets: external secret operator / CSI, not plaintext manifests in git; RBAC on
  `secrets` resources; consider encryption at rest for etcd.
- Ingress: TLS, no wildcard hosts, annotations reviewed (auth, rate limits).
- Image pull policy and digest pinning for production; admission policy for
  signature verification if the platform supports it.
- Helm: values files for secrets are gitignored; `--set` secrets leak into shell
  history — prefer secret references.
