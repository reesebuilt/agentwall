import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { buildServer } from "../src/server";
import type { AgentwallConfig } from "../src/config";

/**
 * Proves the auth gate actually protects routes.
 *
 * tests/setup-env.ts sets AGENTWALL_ALLOW_LOOPBACK_DEV=1 so the other suites can inject
 * without carrying a token fixture. That convenience would be worthless if nothing ever
 * checked the protected case, so this suite turns the escape hatch OFF and asserts the
 * doors are actually shut.
 *
 * Before 2026-08-04 there was no auth at all: /evaluate, /approval/:id/respond and the
 * dashboard control endpoints were reachable by anything that could open the port.
 */

const config: AgentwallConfig = {
  port: 0,
  host: "127.0.0.1",
  logLevel: "silent",
  dashboard: {},
  approval: {
    mode: "always",
    timeoutMs: 30_000,
    backend: "memory",
  },
  policy: {
    defaultDecision: "deny",
  },
  dlp: {
    enabled: true,
    redactSecrets: true,
  },
  egress: {
    enabled: true,
    defaultDeny: true,
    allowPrivateRanges: false,
    allowedHosts: ["api.openai.com"],
    allowedSchemes: ["https"],
    allowedPorts: [443],
  },
  manifestIntegrity: {
    enabled: true,
  },
  watchdog: {
    enabled: true,
    staleAfterMs: 15_000,
    timeoutMs: 30_000,
    killSwitchMode: "deny_all",
  },
};

const PROTECTED = [
	{ method: "POST" as const, url: "/evaluate" },
	{ method: "POST" as const, url: "/approval/some-id/respond" },
	{ method: "GET" as const, url: "/api/dashboard/state" },
	// An unauthenticated caller who could reload policy could swap the ruleset governing every
	// agent on the host, and the audit record would name nobody.
	{ method: "POST" as const, url: "/reload" },
];

describe("route authentication", () => {
	let savedLoopback: string | undefined;
	let savedToken: string | undefined;

	beforeEach(() => {
		savedLoopback = process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
		savedToken = process.env.AGENTWALL_OPERATOR_TOKEN;
		delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
		delete process.env.AGENTWALL_OPERATOR_TOKEN;
	});

	afterEach(() => {
		if (savedLoopback === undefined) delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
		else process.env.AGENTWALL_ALLOW_LOOPBACK_DEV = savedLoopback;
		if (savedToken === undefined) delete process.env.AGENTWALL_OPERATOR_TOKEN;
		else process.env.AGENTWALL_OPERATOR_TOKEN = savedToken;
	});

	it("rejects unauthenticated calls to state-bearing routes", async () => {
		const { app } = await buildServer(config);
		try {
			for (const route of PROTECTED) {
				const res = await app.inject({ method: route.method, url: route.url, payload: {} });
				expect({ url: route.url, status: res.statusCode }).toEqual({ url: route.url, status: 401 });
			}
		} finally {
			await app.close();
		}
	});

	it("keeps health public so a liveness probe needs no credential", async () => {
		const { app } = await buildServer(config);
		try {
			const res = await app.inject({ method: "GET", url: "/health" });
			expect(res.statusCode).not.toBe(401);
		} finally {
			await app.close();
		}
	});

	it("admits a correct bearer token", async () => {
		process.env.AGENTWALL_OPERATOR_TOKEN = "test-token-abc123";
		const { app } = await buildServer(config);
		try {
			const res = await app.inject({
				method: "GET",
				url: "/api/dashboard/state",
				headers: { authorization: "Bearer test-token-abc123" },
			});
			expect(res.statusCode).not.toBe(401);
		} finally {
			await app.close();
		}
	});

	it("rejects a wrong bearer token", async () => {
		process.env.AGENTWALL_OPERATOR_TOKEN = "test-token-abc123";
		const { app } = await buildServer(config);
		try {
			const res = await app.inject({
				method: "GET",
				url: "/api/dashboard/state",
				headers: { authorization: "Bearer not-the-token" },
			});
			expect(res.statusCode).toBe(401);
		} finally {
			await app.close();
		}
	});
});
