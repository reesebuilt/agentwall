import { FastifyInstance } from "fastify";
import { fleetState } from "../runtime/enforcement";
import { credentialState } from "../fleet/credentials";

/**
 * Operator HTTP surface for the declared fleet.
 *
 * Read-only, and deliberately so. Editing an agent's allowlist or budget over HTTP would
 * mean an operator token could quietly widen what an agent may reach without leaving a trace
 * in the file that is supposed to be the record of that decision. The fleet is declared in
 * config and reloaded with the process; this route reports what is in force.
 *
 * Behind the operator bearer token like every non-health route: the response names each
 * declared agent, the uid it is bound to, and how much of its budget is left, which is a map
 * of the fleet and a live measure of which agent is closest to being throttled.
 */

export async function fleetRoutes(app: FastifyInstance): Promise<void> {
  app.get("/api/fleet", async (_req, reply) => {
    const { registry, budgets } = fleetState();

    if (!registry) {
      // Not an error, and not an empty list either. "No fleet is declared" and "a fleet is
      // declared and it is empty" would render identically as `agents: []`, and only the
      // first of those is the default single-agent deployment.
      return reply.send({
        declared: false,
        scope: "single-host",
        unmatched: "global",
        agents: [],
        detail:
          "No fleet is declared. Egress records carry the process comm as the agentId and the " +
          "process-wide egress allowlist judges every connection.",
      });
    }

    const usage = budgets?.snapshot(registry.list()) ?? [];
    const now = Date.now();
    return reply.send({
      declared: true,
      // Stated in the payload, not just the docs. A dashboard that renders this without
      // saying so is one screenshot away from being read as a fleet-wide view.
      //
      // This is the scope of GOVERNANCE, and it is unchanged: this instance judges this
      // host's traffic against its own allowlists, budgets, and chain. It is deliberately not
      // a claim about identity, which an issued credential does carry across hosts; `detail`
      // spells out the difference rather than leaving one word to imply both.
      scope: "single-host",
      detail:
        "Allowlists and budgets are per-agent within this instance. There is no shared budget: " +
        "another AgentWall instance enforces its own copy of these limits against its own traffic. " +
        "An issued credential is the exception: it is presented on the proxy connection, so the same " +
        "credential binds the same agent on every host that runs an instance.",
      unmatched: registry.unmatched,
      minimumMatchTier: registry.minimumMatchTier,
      // Declared agents that cannot bind under the floor, so an operator hitting refusals can
      // see the cause on the same screen as the fleet rather than in a boot log that scrolled.
      unbindable: registry.unbindable(),
      agents: registry.list().map((agent) => ({
        id: agent.id,
        label: agent.label,
        match: {
          uid: agent.uid ?? null,
          comm: [...agent.comm],
          // Never the digest itself. A digest of a shared secret in a JSON response is an
          // offline cracking target handed out by the tool that is supposed to protect it.
          // Which SOURCE pins it is safe and is the thing an operator needs: only an issued
          // credential can be rotated or revoked from the CLI.
          credential: agent.credentialDigest !== null || agent.credentialFromStore,
          credentialSource: agent.credentialDigest !== null ? "config" : agent.credentialFromStore ? "issued" : null,
        },
        // Issued credentials, by id and state. The id is random and unrelated to the digest,
        // so naming it here identifies the credential for a revoke without describing it.
        credentials: registry.credentialsFor(agent.id).map((credential) => ({
          credentialId: credential.credentialId,
          state: credentialState(credential, now),
          issuedAt: credential.issuedAt,
          expiresAt: credential.expiresAt,
          revokedAt: credential.revokedAt,
          revokedReason: credential.revokedReason,
        })),
        egress: agent.egress
          ? {
              allowedHosts: agent.egress.allowedHosts ? [...agent.egress.allowedHosts] : null,
              allowedPorts: agent.egress.allowedPorts ? [...agent.egress.allowedPorts] : null,
            }
          : null,
        budget: usage.find((row) => row.agentId === agent.id) ?? null,
      })),
    });
  });
}
