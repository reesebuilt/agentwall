import { FastifyInstance } from "fastify";
import { z } from "zod";
import { activateKillSwitch, deactivateKillSwitch, killSwitchState } from "../runtime/kill-switch";

/**
 * Operator HTTP surface for the emergency stop.
 *
 * These routes drive exactly one of the four activation sources, `api`. They cannot engage
 * or release the other three, which is the point: an HTTP caller must not be able to lift a
 * stop that an operator engaged from a shell or that a box was configured to boot with.
 *
 * Not in the auth allowlist in src/auth/operator.ts, and must not be added to it. The
 * allowlist is `/health` and `/api/health` only, so these are behind the operator bearer
 * token by default. An unauthenticated caller who could engage the stop would have a
 * one-request denial of service against every agent on the host.
 */

/**
 * A reason is optional but bounded. It goes into the audit record and into every subsequent
 * state response, so an unbounded string is a cheap way to bloat the evidence stream.
 */
const ActivateBodySchema = z.object({
  reason: z.string().trim().min(1).max(512).optional(),
});

/** No fields: the route releases the `api` source and nothing else, so there is nothing to name. */
const DeactivateBodySchema = z.object({}).strict();

export async function killSwitchRoutes(app: FastifyInstance): Promise<void> {
  app.post("/killswitch/activate", async (req, reply) => {
    const parsed = ActivateBodySchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return reply.status(400).send({
        error: "Invalid kill switch activation request",
        details: parsed.error.issues,
      });
    }

    activateKillSwitch("api", parsed.data.reason);
    const state = killSwitchState();

    return reply.send({
      engaged: "api",
      active: state.active,
      sources: state.sources,
      since: state.since,
      reason: state.reason,
      detail: `Kill switch is ACTIVE, held by: ${state.sources.join(", ")}.`,
    });
  });

  app.post("/killswitch/deactivate", async (req, reply) => {
    const parsed = DeactivateBodySchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return reply.status(400).send({
        error: "Invalid kill switch deactivation request",
        details: parsed.error.issues,
      });
    }

    deactivateKillSwitch("api");
    const state = killSwitchState();

    // Deliberately no `ok: true`. Release is per source, so this call routinely succeeds at
    // what it was asked to do while the stop stays engaged by config, signal, or the
    // sentinel file. A success flag here would read as "traffic is flowing again" and send
    // an operator away from a machine that is still stopped.
    return reply.send({
      released: "api",
      active: state.active,
      sources: state.sources,
      since: state.since,
      reason: state.reason,
      detail: state.active
        ? `Released the 'api' hold, but the kill switch remains ACTIVE, held by: ${state.sources.join(", ")}. Each source must be released through the channel that engaged it.`
        : "Released the 'api' hold. No source holds the kill switch; it is inactive.",
    });
  });

  app.get("/killswitch", async (_req, reply) => {
    const state = killSwitchState();
    return reply.send({
      active: state.active,
      sources: state.sources,
      since: state.since,
      reason: state.reason,
    });
  });
}
