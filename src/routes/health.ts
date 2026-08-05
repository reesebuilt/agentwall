import { FastifyInstance } from "fastify";

export async function healthRoutes(app: FastifyInstance): Promise<void> {
  app.get("/health", async (_req, reply) => {
    return reply.send({
      status: "ok",
      service: "agentwall",
      version: "0.1.0",
      timestamp: new Date().toISOString(),
    });
  });

  app.get("/ready", async (_req, reply) => {
    return reply.send({ ready: true });
  });
}
