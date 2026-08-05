import { FastifyInstance } from "fastify";
import { auditDropStats } from "../audit/logger";

export async function healthRoutes(app: FastifyInstance): Promise<void> {
  app.get("/health", async (_req, reply) => {
    // A process whose audit records are not reaching storage has lost the property this
    // product sells, and the chain itself cannot say so: it stays contiguous across the loss
    // by design. The counters are reported here because that is the only live surface an
    // operator polls. `status` deliberately stays "ok": the container healthcheck restarts
    // on anything else, and restarting does not empty a full disk.
    const audit = auditDropStats();
    return reply.send({
      status: "ok",
      service: "agentwall",
      version: "0.1.0",
      timestamp: new Date().toISOString(),
      auditDropped: audit.dropped,
      auditUndeclaredDrops: audit.undeclared,
      auditDropSince: audit.since,
      auditDropReason: audit.reason,
    });
  });

  app.get("/ready", async (_req, reply) => {
    return reply.send({ ready: true });
  });
}
