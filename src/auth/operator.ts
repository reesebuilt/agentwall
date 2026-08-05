import { timingSafeEqual } from "crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

/**
 * Operator authentication.
 *
 * Loopback binding alone is not a posture a security product can ship. `/evaluate`,
 * `/approval/:id/respond`, and the dashboard control endpoints all mutate security
 * state, so anything able to reach the port could otherwise drive them.
 *
 * Deliberately a bearer token rather than OIDC/mTLS to start. A token that actually
 * works today beats an identity framework that lands next quarter, and the principal
 * shape below is what a later OIDC or mTLS provider slots into without touching call
 * sites.
 */

export interface OperatorPrincipal {
	/** Stable id recorded in audit and approval records. Never taken from a request body. */
	id: string;
	/** How this principal was established. Widens as providers are added. */
	method: "token" | "loopback-dev";
}

declare module "fastify" {
	interface FastifyRequest {
		operator?: OperatorPrincipal;
	}
}

export interface OperatorAuthConfig {
	/** Env var holding the shared token. Defaults to AGENTWALL_OPERATOR_TOKEN. */
	tokenEnv?: string;
	/**
	 * Permit unauthenticated loopback callers. Development escape hatch ONLY.
	 * Off by default: a dev convenience that defaults to on is how prod ends up open.
	 */
	allowLoopbackDev?: boolean;
}

const DEFAULT_TOKEN_ENV = "AGENTWALL_OPERATOR_TOKEN";

/** Constant-time compare that does not leak length through early return. */
function tokensMatch(a: string, b: string): boolean {
	const ab = Buffer.from(a, "utf8");
	const bb = Buffer.from(b, "utf8");
	if (ab.length !== bb.length) {
		// Still burn a comparison so timing does not distinguish "wrong length" from
		// "wrong bytes". Compare ab against itself to keep the work equivalent.
		timingSafeEqual(ab, ab);
		return false;
	}
	return timingSafeEqual(ab, bb);
}

function isLoopback(req: FastifyRequest): boolean {
	const ip = req.ip;
	return ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1";
}

/**
 * Resolve the caller to a principal, or null if unauthenticated.
 *
 * Note this trusts `req.ip` for the loopback-dev path only, and Fastify derives that
 * from the socket unless trustProxy is enabled. Do NOT enable trustProxy without
 * revisiting this: an X-Forwarded-For header would then be able to forge loopback.
 */
export function resolveOperator(
	req: FastifyRequest,
	cfg: OperatorAuthConfig = {},
): OperatorPrincipal | null {
	const expected = process.env[cfg.tokenEnv ?? DEFAULT_TOKEN_ENV]?.trim();

	const header = req.headers.authorization;
	if (expected && typeof header === "string" && header.startsWith("Bearer ")) {
		const presented = header.slice(7).trim();
		if (presented && tokensMatch(presented, expected)) {
			return { id: "operator", method: "token" };
		}
		// A wrong token is an explicit failure. Do not fall through to loopback-dev,
		// or a bad token would silently succeed on the very host that matters most.
		return null;
	}

	if (cfg.allowLoopbackDev && isLoopback(req)) {
		return { id: "loopback-dev", method: "loopback-dev" };
	}

	return null;
}

/**
 * Fastify preHandler enforcing authentication.
 *
 * Fails CLOSED when no token is configured and loopback-dev is off: with no way to
 * authenticate anyone, the correct answer is to admit no one. An unconfigured
 * security control must not default to open.
 */
export function requireOperator(cfg: OperatorAuthConfig = {}) {
	return async function operatorGuard(req: FastifyRequest, reply: FastifyReply): Promise<void> {
		const principal = resolveOperator(req, cfg);
		if (!principal) {
			await reply.status(401).send({
				error: "Unauthorized",
				detail: `Provide 'Authorization: Bearer <token>' matching $${cfg.tokenEnv ?? DEFAULT_TOKEN_ENV}.`,
			});
			return;
		}
		req.operator = principal;
	};
}

/** True when some authentication method is actually usable. Surfaced by /health. */
export function operatorAuthConfigured(cfg: OperatorAuthConfig = {}): boolean {
	const tokenSet = Boolean(process.env[cfg.tokenEnv ?? DEFAULT_TOKEN_ENV]?.trim());
	return tokenSet || cfg.allowLoopbackDev === true;
}

/**
 * Register the guard across the instance.
 *
 * Allowlist rather than denylist: routes are protected unless explicitly public, so a
 * new route added later is guarded by default. The opposite ordering means every new
 * endpoint is an unauthenticated endpoint until somebody remembers otherwise.
 */
export function registerOperatorAuth(
	app: FastifyInstance,
	cfg: OperatorAuthConfig = {},
	publicPaths: readonly string[] = ["/health", "/api/health"],
): void {
	const guard = requireOperator(cfg);
	app.addHook("onRequest", async (req, reply) => {
		const path = req.url.split("?")[0];
		if (publicPaths.some((p) => path === p)) return;
		await guard(req, reply);
	});
}
