# Contributions to AgentWall

AgentWall accepts contributions that add features, fix defects, or correct public claims.
Security claims require evidence.

## Local setup

```bash
npm install
npm run build
npm test
```

## Development workflow

1. Create a feature branch.
2. Add or update tests for each behavior change.
3. Run the required checks.

```bash
npm run lint
npm test
npm run build
```

4. Open a pull request with the pull request template.

## Evidence standard

Follow these rules for every capability claim:

- Give a command that another person can run.
- Document an unreachable implementation as unavailable.
- Keep each documented limit beside its capability.
- Update [Limits](README.md#limits) and [SECURITY.md](SECURITY.md) when a limit changes.
- Cite the file and line when a claim depends on specific code.
- Make verification output report every failure accurately.

Do not weaken a documented limit for promotional copy.
A security control must produce evidence that another person can verify.

## Dependencies

AgentWall has three runtime dependencies: `fastify`, `js-yaml`, and `zod`.
Explain any fourth runtime dependency in the pull request.
Declare only dependencies that the code imports.

The audit, signature, and anchor paths use Node `crypto` and plain HTTP.
Do not add a third-party client dependency to these paths.
This rule limits the supply-chain attack surface of trust-critical code.

## Code style

- Keep each change focused.
- Use explicit policy and risk semantics.
- Write comments that explain a reason or a non-obvious tradeoff.
- Update documentation for user-visible behavior.

## Commit guidance

Write a clear commit message that explains why the change exists.

## Security-sensitive contributions

For policy, egress, approval, or DLP changes, include:

- the threat scenario
- expected false positives and false negatives
- edge-case test coverage

Report a vulnerability through [SECURITY.md](SECURITY.md).
Do not put undisclosed vulnerability details in a public pull request.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin](https://developercertificate.org/).
The sign-off confirms that you wrote the change or can submit it under the project license.
The project does not require a copyright assignment.

Add a sign-off with `-s`:

```bash
git commit -s -m "Document monitor mode"
```

Git uses your configured name and email for the `Signed-off-by` line.

Add the sign-off to the last commit with `git commit --amend -s --no-edit`.
