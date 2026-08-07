# Security Policy

Agentwall is a security tool, so a vulnerability here can cost an operator the exact thing they
installed it to protect. Reports are welcome and are treated as the highest-priority work in
the project.

## Reporting a vulnerability

Report privately, not in a public issue.

- Preferred: open a private security advisory on GitHub. This is the path that is verifiably
  monitored and it is the one to use if you want certainty that a human sees it.
- Alternative: email `security@agentwall.dev`.

Please include:
- affected version or commit
- reproduction steps, ideally a command or test that shows the failure
- impact assessment
- any suggested mitigation

A working reproduction is worth more than a severity rating. If you can express the issue as a
failing test against this repository, that is the most useful form a report can take.

## Response targets

Agentwall is maintained by a small team, so these are honest targets rather than a contractual
SLA:

- initial acknowledgement: within 72 hours
- triage decision: within 7 days
- fix or mitigation timeline: shared after triage, based on severity

If a report goes unacknowledged past those windows, it is an oversight rather than a decision.
Send a follow-up.

## In scope

Anything that breaks a property the project claims. Concretely:

- bypassing operator authentication, or any route reachable without a valid token that is not
  documented as public
- causing the policy engine to return a less restrictive decision than its rules specify, or
  breaking the `deny` > `approve` > `redact` > `allow` precedence
- forging, truncating, reordering, or silently rewriting audit records without `agentwall
  verify` reporting it
- forging an Ed25519 checkpoint, or making a checkpoint verify against a key that did not sign
  it
- causing the audit chain's single-writer lock to admit a second concurrent writer
- SSRF or egress-allowlist bypass, including private-range, loopback, link-local, or cloud
  metadata targets
- DLP bypass that lets a supported secret type through unredacted
- crashing or hanging the forward proxy in a way that takes down egress for every client

## Out of scope

These are documented limits, not defects. They are listed in [docs/limits.md](docs/limits.md).
Reporting them is not a vulnerability, though arguments about how they should change are
welcome as normal issues.

- The forward proxy records and allows. It does not block. Monitor-first is the shipped
  posture.
- Proxy capture is cooperative. A process that ignores proxy environment variables egresses
  unobserved, and nothing here installs iptables or nftables redirection.
- There is no TLS interception, so CONNECT traffic is visible at hostname and port level only.
- Process attribution reads `/proc` and works on Linux only.
- An OpenTimestamps anchor is `pending` until a Bitcoin block confirms it. Pending is not
  proof, and the tool says so.
- Anchoring shows that records were not altered after the fact. It does not show that the log
  is complete. Silent omission at write time is a known unsolved problem, not a bug report.
- A signature proves a key holder vouched. On a host where the audited principal can read the
  signing key, that is insufficient by design, which is why off-box anchoring exists.
- `AGENTWALL_ALLOW_LOOPBACK_DEV=1` intentionally accepts unauthenticated loopback callers. It
  is documented as local development only.

If you believe one of these limits is worse than the README admits, that is a documentation bug
and a legitimate report. Say so and it will be fixed.

## Disclosure policy

Please do not disclose publicly until a fix or mitigation is released. Credit is given in the
changelog unless you ask otherwise.

## Scope of this policy

This policy covers this repository. Vulnerabilities in third-party dependencies should go to
that project first; tell us as well if Agentwall's use of it makes the impact worse.
