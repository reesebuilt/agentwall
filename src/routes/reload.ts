import { FastifyInstance } from "fastify";
import { z } from "zod";
import { ReloadCoordinator } from "../runtime/reload";

/**
 * Operator HTTP surface for config and policy reload.
 *
 * Not in the auth allowlist in src/auth/operator.ts, and must not be added to it. The allowlist
 * is `/health` and `/api/health` only, so these sit behind the operator bearer token by default
 * and `req.operator.id` is the principal the auth layer established. That id is what lands on
 * the audit chain: an unauthenticated caller who could reload policy would be able to swap the
 * ruleset governing every agent on the host and leave a record naming nobody.
 *
 * There is no route parameter selecting which file to reload. Both files are re-read as one
 * action because the atomicity guarantee is defined across both of them; letting a caller ask
 * for half of it would hand out the partial outcome the coordinator exists to prevent.
 */

/**
 * Strict, so a field this route does not implement is an error rather than a silent no-op. An
 * operator who sends `{"policy": true}` expecting a selective reload needs to be told that it
 * did something else, not to have it dropped and receive a 200.
 */
const ReloadBodySchema = z
  .object({
    /** Bounded: it goes into the audit record, so an unbounded string bloats the evidence stream. */
    reason: z.string().trim().min(1).max(512).optional(),
  })
  .strict();

export async function reloadRoutes(app: FastifyInstance, coordinator: ReloadCoordinator): Promise<void> {
  app.post("/reload", async (req, reply) => {
    const parsed = ReloadBodySchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return reply.status(400).send({
        error: "Invalid reload request",
        details: parsed.error.issues,
      });
    }

    const report = coordinator.reload({
      source: "api",
      operatorId: req.operator?.id,
      reason: parsed.data.reason,
    });

    // 400 on a refused reload, matching the existing dashboard reload control. The request was
    // well formed; the file on disk was not, and the body names which file and why. The report
    // is returned whole in both cases so a caller never has to make a second call to find out
    // whether the previous policy is still the one enforcing.
    return reply.status(report.ok ? 200 : 400).send(report);
  });

  app.get("/reload", async (_req, reply) => {
    return reply.send(coordinator.state());
  });
}
