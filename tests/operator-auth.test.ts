import { afterEach, describe, expect, it } from "@jest/globals";
import { resolveOperator, requireOperator, operatorAuthConfigured } from "../src/auth/operator";
import type { FastifyReply, FastifyRequest } from "fastify";

/**
 * Regression guard for two Phase 0 findings (2026-08-04).
 *
 * 1. Every HTTP route was unauthenticated; loopback binding was the only control.
 * 2. `/approval/:id/respond` took `approvedBy` from the request body, so any reachable
 *    caller could approve as anyone and the audit recorded the name they supplied.
 *
 * These tests pin the properties that make those bugs impossible to reintroduce
 * silently: unconfigured auth denies, a wrong token does not fall through to a weaker
 * method, and the principal comes from the request context rather than its body.
 */

const ENV = "AGENTWALL_OPERATOR_TOKEN_TEST";

function req(headers: Record<string, string> = {}, ip = "203.0.113.10"): FastifyRequest {
	// Only the fields resolveOperator reads. Narrow cast at a test boundary where the
	// full Fastify request is neither available nor relevant.
	return { headers, ip } as unknown as FastifyRequest;
}

function reply() {
	const sent: { code?: number; body?: unknown } = {};
	const r = {
		status(code: number) {
			sent.code = code;
			return r;
		},
		async send(body: unknown) {
			sent.body = body;
			return r;
		},
	};
	return { reply: r as unknown as FastifyReply, sent };
}

afterEach(() => {
	delete process.env[ENV];
});

describe("operator auth", () => {
	it("denies when nothing is configured", () => {
		// The important direction: an unconfigured security control must not default open.
		expect(operatorAuthConfigured({ tokenEnv: ENV })).toBe(false);
		expect(resolveOperator(req(), { tokenEnv: ENV })).toBeNull();
	});

	it("accepts a correct bearer token and names the principal", () => {
		process.env[ENV] = "s3cret-token-value";
		const p = resolveOperator(req({ authorization: "Bearer s3cret-token-value" }), { tokenEnv: ENV });
		expect(p).toEqual({ id: "operator", method: "token" });
	});

	it("rejects a wrong token", () => {
		process.env[ENV] = "s3cret-token-value";
		expect(resolveOperator(req({ authorization: "Bearer wrong" }), { tokenEnv: ENV })).toBeNull();
	});

	it("a wrong token does NOT fall through to loopback-dev", () => {
		// Otherwise a bad credential would silently succeed on the one host that matters.
		process.env[ENV] = "s3cret-token-value";
		const p = resolveOperator(req({ authorization: "Bearer wrong" }, "127.0.0.1"), {
			tokenEnv: ENV,
			allowLoopbackDev: true,
		});
		expect(p).toBeNull();
	});

	it("loopback-dev is opt-in and never applies to a remote address", () => {
		expect(resolveOperator(req({}, "127.0.0.1"), { tokenEnv: ENV })).toBeNull();
		expect(
			resolveOperator(req({}, "127.0.0.1"), { tokenEnv: ENV, allowLoopbackDev: true }),
		).toEqual({ id: "loopback-dev", method: "loopback-dev" });
		expect(
			resolveOperator(req({}, "203.0.113.20"), { tokenEnv: ENV, allowLoopbackDev: true }),
		).toBeNull();
	});

	it("the guard 401s and attaches no principal when unauthenticated", async () => {
		const guard = requireOperator({ tokenEnv: ENV });
		const r = req();
		const { reply: rep, sent } = reply();
		await guard(r, rep);
		expect(sent.code).toBe(401);
		expect(r.operator).toBeUndefined();
	});

	it("the guard attaches the principal when authenticated", async () => {
		process.env[ENV] = "s3cret-token-value";
		const guard = requireOperator({ tokenEnv: ENV });
		const r = req({ authorization: "Bearer s3cret-token-value" });
		const { reply: rep, sent } = reply();
		await guard(r, rep);
		expect(sent.code).toBeUndefined();
		expect(r.operator).toEqual({ id: "operator", method: "token" });
	});
});
