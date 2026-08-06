import { FastifyInstance, RouteHandlerMethod } from "fastify";
import {
	buildFleetEvidenceReport,
	loadFleetEvidenceSources,
	type FleetEvidenceReport,
	type FleetEvidenceSources,
	type HostEvidence,
} from "../evidence/fleet";
import { renderFleetHost, renderFleetIndex } from "../evidence/fleet-render";
import { esc } from "../evidence/render";

/**
 * The fleet evidence aggregator: a read-only console over several hosts' chains at once.
 *
 * This is the single-host viewer's shape one level up. Each host's chain is read, verified
 * independently by the same `runVerify()`, and shown beside the others. Nothing is merged and
 * nothing is decided centrally; see src/evidence/fleet.ts for why both of those are refusals
 * rather than omissions.
 *
 * READ ONLY, by the same three mechanisms as /evidence:
 *
 *   1. Only GET handlers are registered here, and every mutating method against these paths is
 *      answered 405 by the block below. The refusal is a stated contract rather than a 404 that
 *      happens to look the same today.
 *   2. The HTML serves no script, so there is no client that could be pointed at a control
 *      route. The server's Content-Security-Policy would refuse an inline one anyway.
 *   3. Nothing this module imports opens a file for writing, and nothing here opens a socket to
 *      any host. The aggregator holds no credential on any agent host and cannot reach one.
 *
 * AUTH. Nothing here is in the public allowlist in src/auth/operator.ts, so these paths sit
 * behind the operator bearer token like every other non-health route. No second credential
 * scheme was invented for this surface.
 */

const MUTATING = ["POST", "PUT", "PATCH", "DELETE"] as const;

const READ_ONLY_REFUSAL = {
	error: "The fleet evidence view is read only",
	detail:
		"This surface renders records that were already written and hashed on other hosts. It has no approve, " +
		"deny, or edit path by design: evidence the console reviewing it can change is not evidence. It also " +
		"has no path back to any host. Act on a decision on the host that owns it.",
};

const NOT_CONFIGURED = {
	error: "No fleet evidence sources are declared",
	detail:
		"AGENTWALL_FLEET_EVIDENCE is unset, so this process has not been told where any host's evidence landed. " +
		"Point it at a sources file listing each host and the audit file its evidence was delivered to. See " +
		"docs/fleet-evidence.md.",
};

const PAGE_STYLE =
	"body{background:#0b0e13;color:#dfe6f1;font:14px/1.6 ui-monospace,Menlo,Consolas,monospace;" +
	"padding:3rem 1.5rem;max-width:44rem;margin:0 auto}b{color:#e3a008}a{color:#7cb7ff}.fail{color:#e5484d}";

function shell(title: string, body: string): string {
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>${esc(title)}</title>
<style>${PAGE_STYLE}</style>
</head><body>${body}</body></html>`;
}

const NOT_CONFIGURED_PAGE = shell(
	"AgentWall fleet evidence",
	`<h1>No fleet evidence sources are declared</h1>
<p><b>AGENTWALL_FLEET_EVIDENCE is unset.</b> This process has not been told where any host's
evidence landed, so there is nothing to read and nothing to verify.</p>
<p>Point it at a sources file naming each host and the audit file its evidence was delivered to.
The transport is yours: rsync over ssh, an object-store sync, a read-only mount. This process
reads paths and opens no socket to any host.</p>
<p>See <code>docs/fleet-evidence.md</code>.</p>`,
);

/**
 * The body for a sources file this process cannot load.
 *
 * A 500 with a stack would be the wrong answer twice: it tells an operator nothing actionable,
 * and it invites the reading that the evidence is broken when what is broken is the list of
 * where to find it. Named as configuration, with the parse error, and no host rendered at all,
 * because a partial fleet is the one output this surface must never produce.
 */
function badSourcesPage(message: string): string {
	return shell(
		"AgentWall fleet evidence",
		`<h1>The fleet evidence sources could not be loaded</h1>
<p class="fail">${esc(message)}</p>
<p>No host is shown, deliberately. A sources file that half-parses would render a fleet missing
whichever host had the typo, and a green page with a member missing is the worst output a tool
whose job is saying what it could not see can produce.</p>`,
	);
}

function notFoundPage(hostId: string): string {
	return shell(
		"Not in the fleet",
		`<h1>Not in the fleet</h1>
<p>No host named <code>${esc(hostId)}</code> is declared in the sources file this process read.
This surface reads exactly where it is told to look, so a host that is not listed is invisible
here rather than absent from the world.</p>
<p><a href="/evidence/fleet">Back to the fleet evidence view</a></p>`,
	);
}

/**
 * The index JSON without the per-host record arrays.
 *
 * A fleet of twenty hosts holding a hundred thousand records each is not a payload; it is a
 * denial of service against the reviewer's browser. The per-host endpoint carries the full
 * single-host report for the one host being read, which is exactly the shape /api/evidence
 * serves for a local chain.
 */
function indexPayload(report: FleetEvidenceReport): Record<string, unknown> {
	const { hosts, ...rest } = report;
	return {
		...rest,
		hosts: hosts.map((host) => {
			const { report: hostReport, ...summary } = host;
			return {
				...summary,
				verify:
					hostReport === null
						? null
						: {
								ok: hostReport.verify.ok,
								layers: hostReport.layers,
								anchors: hostReport.anchors.length,
								totals: hostReport.totals,
								truncated: hostReport.truncated,
							},
			};
		}),
	};
}

/** The per-host payload, with the session scorecards but without every record body. */
function hostPayload(host: HostEvidence): Record<string, unknown> {
	const { report, ...summary } = host;
	return {
		...summary,
		verify: report === null ? null : report.verify,
		layers: report === null ? null : report.layers,
		anchors: report === null ? null : report.anchors,
		files: report === null ? null : report.files,
		totals: report === null ? null : report.totals,
		notes: report === null ? [] : report.notes,
		sessions: report === null ? [] : report.sessions.map(({ chainRecords, ...card }) => card),
	};
}

export async function fleetEvidenceRoutes(app: FastifyInstance, sourcesPath?: string): Promise<void> {
	for (const url of ["/evidence/fleet", "/evidence/fleet/*", "/api/evidence/fleet", "/api/evidence/fleet/*"]) {
		app.route({
			method: [...MUTATING],
			url,
			handler: async (_req, reply) => reply.code(405).send(READ_ONLY_REFUSAL),
		});
	}

	if (!sourcesPath) {
		// Registered even with no sources, so the surface answers the same way at every URL
		// instead of 404ing and leaving an operator to guess whether the feature exists.
		const notConfigured: RouteHandlerMethod = async (_req, reply) =>
			reply.code(503).type("text/html; charset=utf-8").send(NOT_CONFIGURED_PAGE);
		app.get("/evidence/fleet", notConfigured);
		app.get("/evidence/fleet/host/:hostId", notConfigured);
		app.get("/api/evidence/fleet", async (_req, reply) => reply.code(503).send(NOT_CONFIGURED));
		app.get("/api/evidence/fleet/host/:hostId", async (_req, reply) => reply.code(503).send(NOT_CONFIGURED));
		return;
	}

	/**
	 * Read per request, never cached, and that includes the sources file.
	 *
	 * The chains grow while an operator reads them and hosts are added and removed while the
	 * process runs. A cached verdict is a verdict about files that no longer exist: showing a
	 * verified fleet from before a break arrived is exactly the failure this view exists to
	 * prevent. Each host read is bounded by READ_LIMITS in src/evidence/collect.ts.
	 */
	const build = (): { report: FleetEvidenceReport } | { error: string } => {
		let sources: FleetEvidenceSources;
		try {
			sources = loadFleetEvidenceSources(sourcesPath);
		} catch (err) {
			return { error: (err as Error).message };
		}
		return { report: buildFleetEvidenceReport(sources) };
	};

	app.get("/evidence/fleet", async (_req, reply) => {
		const built = build();
		if ("error" in built) {
			return reply.code(503).type("text/html; charset=utf-8").send(badSourcesPage(built.error));
		}
		return reply.type("text/html; charset=utf-8").send(renderFleetIndex(built.report));
	});

	app.get("/evidence/fleet/host/:hostId", async (req, reply) => {
		const { hostId } = req.params as { hostId: string };
		const built = build();
		if ("error" in built) {
			return reply.code(503).type("text/html; charset=utf-8").send(badSourcesPage(built.error));
		}
		// Compared verbatim. No prefix or fuzzy match: a reviewer asking about one host must
		// not be shown another one's evidence because two ids share a prefix.
		const host = built.report.hosts.find((h) => h.id === hostId);
		if (!host) return reply.code(404).type("text/html; charset=utf-8").send(notFoundPage(hostId));
		return reply.type("text/html; charset=utf-8").send(renderFleetHost(host));
	});

	app.get("/api/evidence/fleet", async (_req, reply) => {
		const built = build();
		if ("error" in built) return reply.code(503).send({ error: "The fleet evidence sources could not be loaded", detail: built.error });
		return reply.send(indexPayload(built.report));
	});

	app.get("/api/evidence/fleet/host/:hostId", async (req, reply) => {
		const { hostId } = req.params as { hostId: string };
		const built = build();
		if ("error" in built) return reply.code(503).send({ error: "The fleet evidence sources could not be loaded", detail: built.error });
		const host = built.report.hosts.find((h) => h.id === hostId);
		if (!host) return reply.code(404).send({ error: "No host with this id is declared in the sources file", hostId });
		return reply.send(hostPayload(host));
	});

	app.log.info(
		{ sourcesPath },
		"Fleet evidence at /evidence/fleet, read only, one independently verified chain per host",
	);
}
