# Contributing to Agentwall

Contributions are welcome, including ones that prove a claim in the README is wrong. Agentwall
is a security tool, so the bar is evidence rather than plausibility.

## Local setup

```bash
npm install
npm run build
npm test
```

## Development workflow

1. Create a feature branch.
2. Add or update tests for behavior changes.
3. Run:

```bash
npm run lint
npm test
npm run build
```

4. Open a pull request using the PR template.

## The evidence standard

This is the rule that matters most here, because a security tool that overstates itself is
worse than no tool.

- A capability described in the README or docs MUST be demonstrable by a command a stranger can
  run. If it is implemented but not yet reachable, document it as not yet wired, not as
  present.
- Do not soften a documented limit to make the project look better. The
  [Limits](README.md#limits) table and the out-of-scope list in [SECURITY.md](SECURITY.md) are
  load-bearing, not marketing hedges. If a limit stops being true because you fixed it, move it
  out and say what closed it.
- Cite file and line when a doc claim depends on specific code, so the next person can check it
  rather than trust it.
- Verification output must report failure honestly. Code that prints a pass when it did not
  actually check something will be rejected.

## Dependencies

Runtime dependencies are deliberately four: `fastify`, `js-yaml`, `pino`, `zod`. Adding a fifth
needs a reason in the pull request.

The audit, signing, and anchoring paths use Node's own `crypto` and plain HTTP with no
third-party clients. Do not add a dependency there. A supply-chain compromise inside the
component whose entire job is being trustworthy defeats the point of it.

## Code style

- Keep changes focused and small.
- Prefer explicit policy and risk semantics over implicit behavior.
- Comments explain why, not what. Record the reasoning behind a non-obvious decision, and the
  failure that motivated it, so it is not undone by someone who does not know the history.
- Include docs updates for user-visible behavior.

## Commit guidance

Use clear commit messages describing *why* the change exists, not just *what* changed.

## Security-sensitive contributions

For changes affecting policy enforcement, egress controls, approvals, or DLP logic, include:
- threat scenario addressed
- expected false-positive/false-negative tradeoffs
- test coverage for edge cases


## Sign your commits (DCO)

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/).
It is a statement that you wrote the change, or have the right to submit it under the
project's license. No corporate paperwork, no copyright assignment.

Add the sign-off with `-s`:

```bash
git commit -s -m "your message"
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

If you forget on the last commit: `git commit --amend -s --no-edit`.

Why this and not a CLA: a DCO keeps copyright with you, which is the lighter ask and is
what most OSS security projects settle on.
