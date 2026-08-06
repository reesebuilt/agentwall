import { FastifyInstance } from "fastify";
import { fleetState } from "../runtime/enforcement";

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
    return reply.send({
      declared: true,
      // Stated in the payload, not just the docs. A dashboard that renders this without
      // saying so is one screenshot away from being read as a fleet-wide view.
      scope: "single-host",
      detail:
        "Identity, allowlists, and budgets are per-agent within this instance. There is no " +
        "cross-instance identity and no shared budget: another AgentWall instance enforces its " +
        "own copy of these limits against its own traffic.",
      unmatched: registry.unmatched,
      agents: registry.list().map((agent) => ({
        id: agent.id,
        label: agent.label,
        match: {
          uid: agent.uid ?? null,
          comm: [...agent.comm],
          // Never the digest itself. A digest of a shared secret in a JSON response is an
          // offline cracking target handed out by the tool that is supposed to protect it.
          credential: agent.credentialDigest !== null,
        },
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
