# Rationale — the "why" behind common flags

Read the entry that matches when the operator asks *why*. Each is threat, likelihood,
what breaks. Keep the spoken answer to the length of the entry, not longer.

**Encrypt keys/secrets at rest even on an intranet.** Threat: any read primitive
(SQL injection, backup exposure, misconfigured replica, an admin's laptop) becomes
credential theft. Likelihood: backup and replica exposure is common and rarely
noticed. What breaks: every downstream account those keys open, and the incident is
invisible until the keys are used elsewhere.

**Server-side, not browser storage, for third-party API keys.** Threat: XSS or a
malicious extension reads localStorage. Likelihood: XSS is among the most common web
bugs. What breaks: the user's key and their bill.

**Ownership check on object-by-id.** Threat: change the id, read someone else's data
(IDOR). Likelihood: very high; ids are guessable or enumerable. What breaks:
confidentiality across every user, and it is one HTTP request to exploit.

**Verify webhook signatures and reject replays.** Threat: forged events (fake
"payment succeeded"). Likelihood: endpoints are discoverable. What breaks: business
logic that trusts the event.

**SSRF from user-supplied URLs.** Threat: the server is made to fetch internal
addresses — cloud metadata endpoints, admin panels. Likelihood: high in cloud
environments. What breaks: instance credentials, then everything they can reach.

**Prompt injection in LLM features.** Threat: untrusted content contains instructions
the model follows — exfiltrate data via a tool, take an action, misreport. Likelihood:
certain if the model can act and reads untrusted text. What breaks: whatever tools
the model has; treat model output as untrusted and constrain tools accordingly.

**Tenant scoping by construction.** Threat: one missed WHERE clause leaks another
customer's data. Likelihood: grows with every new query. What breaks: the contract
with every customer at once.

**No tokens or PII in logs.** Threat: logs are shipped, indexed, and shared with
tools that were never in the threat model. Likelihood: high. What breaks: session
takeover from a log search; regulatory exposure.

**Rotation path for secrets.** Threat: a leaked key with no rotation path stays valid
while the fix is deployed. Likelihood: leaks happen. What breaks: time-to-contain.

**Least privilege for jobs and services.** Threat: a compromised worker with broad
credentials is a full compromise. Likelihood: workers process untrusted input.
What breaks: blast radius.
