import { FastifyInstance, RouteHandlerMethod } from "fastify";
import { buildEvidenceReport, type EvidenceReport, type SessionScorecard } from "../evidence/scorecard";
import { esc, renderEvidenceIndex, renderSessionScorecard } from "../evidence/render";

/**
 * The operator evidence viewer: a read-only console over the audit chain that is already
 * being written.
 *
 * WHY THIS EXISTS. The evidence was complete and unreadable. A reviewer asking "what did this
 * agent do, what was blocked, and can I trust the record" had to open JSONL by hand, count
 * decisions, and run the verifier separately to learn whether the file had been touched. The
 * data model is unchanged: everything here is a projection of what src/audit already writes
 * and what docs/audit-format.md specifies. Nothing new is recorded to serve this view.
 *
 * READ ONLY, and enforced rather than promised:
 *
 *   1. Only GET handlers are registered. Every mutating method against these paths is answered
 *      405 by the block below, so the refusal is a stated contract rather than a 404 that
 *      happens to be the same thing today.
 *   2. The HTML serves no script, so there is no client that could be pointed at a control
 *      route. The server's Content-Security-Policy would refuse an inline one anyway.
 *   3. Nothing this module imports opens a file for writing.
 *
 * Evidence you can edit from the console that reviews it is not evidence.
 *
 * AUTH. Nothing here is in the public allowlist in src/auth/operator.ts, so these paths sit
 * behind the operator bearer token like every other non-health route. A browser cannot send a
 * bearer header by typing a URL, which is what AGENTWALL_ALLOW_LOOPBACK_DEV=1 is for: it
 * accepts a loopback caller as an operator for local review. That switch is a development
 * convenience and the compliance report scores it as a finding, which is the correct
 * treatment. No second credential scheme was invented for this surface.
 */

/** Mutating methods, answered explicitly so the read-only stance is a contract, not a gap. */
const MUTATING = ["POST", "PUT", "PATCH", "DELETE"] as const;

const READ_ONLY_REFUSAL = {
  error: "The evidence viewer is read only",
  detail:
    "This surface renders records that were already written and hashed. It has no approve, " +
    "deny, or edit path by design: evidence the console reviewing it can change is not " +
    "evidence. Use the operational routes or the CLI to act on a decision.",
};

const NOT_CONFIGURED = {
  error: "No durable audit evidence to review",
  detail:
    "AGENTWALL_AUDIT_FILE is unset, so decisions are hash-chained in memory and written to " +
    "stdout only. There is no file for a verifier to walk and nothing here to review. Set " +
    "AGENTWALL_AUDIT_FILE to the path the service should append its chain to.",
};

const PAGE_STYLE =
  "body{background:#0b0e13;color:#dfe6f1;font:14px/1.6 ui-monospace,Menlo,Consolas,monospace;" +
  "padding:3rem 1.5rem;max-width:44rem;margin:0 auto}b{color:#e3a008}a{color:#7cb7ff}";

const NOT_CONFIGURED_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AgentWall evidence</title>
<style>${PAGE_STYLE}</style>
</head><body>
<h1>No durable audit evidence to review</h1>
<p><b>AGENTWALL_AUDIT_FILE is unset.</b> Decisions are still hash-chained and still written to
stdout, but nothing is appended to a file, so there is no chain for a verifier to walk and
nothing here for a reviewer to check.</p>
<p>Set <code>AGENTWALL_AUDIT_FILE</code> to the path the service should append its chain to.
There is deliberately no default: a service must not invent a location for security-critical
data.</p>
</body></html>`;

/**
 * The body for a session id that is not in the evidence.
 *
 * Says what it means: absence from the chain, not a broken link. A reviewer handed a session id
 * that produces nothing needs to know whether they mistyped it or whether the decisions it
 * covers were never recorded, because those are different findings and only one of them is a
 * mistake they can fix.
 */
function notFoundPage(label: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Not in the evidence</title>
<style>${PAGE_STYLE}</style>
</head><body>
<h1>Not in the evidence</h1>
<p>No record in the chain carries the session <code>${esc(label)}</code>. Either that is not the
id the agent ran under, or no decision for it was ever written. An absent record is not a
detectable one: no verifier finds a decision that was never recorded.</p>
<p><a href="/evidence">Back to the evidence viewer</a></p>
</body></html>`;
}

/**
 * The index JSON without the per-record arrays.
 *
 * A chain can hold a hundred thousand records, and shipping all of them on the overview is how
 * a review tool becomes something an operator avoids opening. The per-session endpoint carries
 * the records for the one session being read.
 */
function indexPayload(report: EvidenceReport): Record<string, unknown> {
  const { sessions, offline, ...rest } = report;
  return {
    ...rest,
    // The session extractor is a function of the session id, so it cannot be serialized. The
    // per-session endpoint carries the command for the session it returns.
    offline: {
      bundled: offline.bundled,
      bundledJson: offline.bundledJson,
      independent: offline.independent,
      pinned: offline.pinned,
    },
    sessions: sessions.map(({ chainRecords, ...summary }) => summary),
  };
}

export async function evidenceRoutes(app: FastifyInstance, auditPath?: string): Promise<void> {
  for (const url of ["/evidence", "/evidence/*", "/api/evidence", "/api/evidence/*"]) {
    app.route({
      method: [...MUTATING],
      url,
      handler: async (_req, reply) => reply.code(405).send(READ_ONLY_REFUSAL),
    });
  }

  if (!auditPath) {
    // Registered even with no file, so the surface answers the same way at every URL instead of
    // 404ing and leaving an operator to guess whether the feature exists at all.
    const notConfigured: RouteHandlerMethod = async (_req, reply) =>
      reply.code(503).type("text/html; charset=utf-8").send(NOT_CONFIGURED_PAGE);
    app.get("/evidence", notConfigured);
    app.get("/evidence/unattributed", notConfigured);
    app.get("/evidence/session/:sessionId", notConfigured);
    app.get("/api/evidence", async (_req, reply) => reply.code(503).send(NOT_CONFIGURED));
    app.get("/api/evidence/unattributed", async (_req, reply) => reply.code(503).send(NOT_CONFIGURED));
    app.get("/api/evidence/session/:sessionId", async (_req, reply) => reply.code(503).send(NOT_CONFIGURED));
    return;
  }

  // Built per request, never cached. The chain grows while an operator reads it, and a cached
  // verdict is a verdict about a file that no longer exists: showing "chained PASS" from before
  // a break was appended is precisely the failure this view exists to prevent. The cost of the
  // read is bounded by READ_LIMITS in src/evidence/collect.ts instead.
  const build = (): EvidenceReport => buildEvidenceReport({ auditPath });

  // Compared verbatim. No prefix or fuzzy match: a reviewer asking about one session must not
  // be shown another one's records because two ids share a prefix.
  const sessionOf = (report: EvidenceReport, sessionId: string | null): SessionScorecard | undefined =>
    report.sessions.find((s) => s.sessionId === sessionId);

  app.get("/evidence", async (_req, reply) =>
    reply.type("text/html; charset=utf-8").send(renderEvidenceIndex(build()))
  );

  app.get("/evidence/unattributed", async (_req, reply) => {
    const report = build();
    const session = sessionOf(report, null);
    if (!session) {
      return reply.code(404).type("text/html; charset=utf-8").send(notFoundPage("records with no session"));
    }
    return reply.type("text/html; charset=utf-8").send(renderSessionScorecard(report, session));
  });

  app.get("/evidence/session/:sessionId", async (req, reply) => {
    const { sessionId } = req.params as { sessionId: string };
    const report = build();
    const session = sessionOf(report, sessionId);
    if (!session) {
      return reply.code(404).type("text/html; charset=utf-8").send(notFoundPage(sessionId));
    }
    return reply.type("text/html; charset=utf-8").send(renderSessionScorecard(report, session));
  });

  app.get("/api/evidence", async (_req, reply) => reply.send(indexPayload(build())));

  app.get("/api/evidence/unattributed", async (_req, reply) => {
    const report = build();
    const session = sessionOf(report, null);
    if (!session) {
      return reply.code(404).send({ error: "No records in the chain are without a session" });
    }
    return reply.send({ session, offline: report.offline.session(null) });
  });

  app.get("/api/evidence/session/:sessionId", async (req, reply) => {
    const { sessionId } = req.params as { sessionId: string };
    const report = build();
    const session = sessionOf(report, sessionId);
    if (!session) {
      return reply.code(404).send({ error: "No record in the chain carries this session", sessionId });
    }
    return reply.send({ session, offline: report.offline.session(sessionId) });
  });

  app.log.info({ auditPath }, "Evidence viewer at /evidence, read only, over the audit chain");
}
