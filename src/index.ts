import { loadConfig } from "./config";
import { buildServer } from "./server";
import { createForwardProxy } from "./proxy/forward-proxy";
import { emit } from "./audit/logger";

async function main() {
  const config = loadConfig();
  const { app, runtime } = await buildServer(config);

  try {
    await app.listen({ port: config.port, host: config.host });

    // Forward proxy: the insertion mechanism. Opt-in via env so it never starts
    // unexpectedly, and bound to loopback like everything else on this host.
    // Monitor mode: records every destination, denies nothing.
    const proxyPort = Number(process.env.AGENTWALL_PROXY_PORT ?? 0);
    if (proxyPort > 0) {
      const { appendFileSync, mkdirSync } = await import("fs");
      const { dirname } = await import("path");
      // No default, matching the audit file. A security tool must not invent a write
      // location in $HOME: a process that picks its own path can collide with an
      // operator's real data. Unset means the proxy runs without a flat ledger; the
      // audit chain is the record regardless.
      const ledger = process.env.AGENTWALL_PROXY_LEDGER;
      if (ledger) mkdirSync(dirname(ledger), { recursive: true });
      createForwardProxy({
        port: proxyPort,
        host: process.env.AGENTWALL_PROXY_HOST ?? "127.0.0.1",
        decide: () => "allow", // Monitor mode observes; it does not gate.
        record: (r) => {
          // Egress evidence has to be tamper-evident, not merely present. An
          // unchained append can be edited away with a single `sed -i` while
          // verifyChainFile() still passes, so egress joins the same hash chain as
          // every other decision. The flat ledger below is a convenience view for
          // allowlist analysis, not the record.
          try {
            const auditEvent = emit(
              {
                agentId: r.client.comm ?? "unattributed",
                plane: "network",
                action: `egress:${r.scheme}`,
                payload: {},
                metadata: {
                  host: r.host,
                  port: String(r.port),
                  scheme: r.scheme,
                  method: r.method,
                  pid: r.client.pid == null ? "unknown" : String(r.client.pid),
                  comm: r.client.comm ?? "unknown",
                  durationMs: String(r.durationMs ?? 0),
                  bytesUp: String(r.bytesUp ?? 0),
                  bytesDown: String(r.bytesDown ?? 0),
                },
              },
              {
                decision: r.decision ?? "allow",
                riskLevel: "low",
                matchedRules: [],
                reasons: ["monitor-first: observed, not gated"],
                requiresApproval: false,
                highRiskFlow: false,
                detections: [],
              }
            );
            // The five route handlers already feed the dashboard directly; the
            // proxy is the one producer that bypasses them, which is why the
            // console read "Awaiting first live agent activity" while the proxy
            // was handling real traffic. Wire only this path: a global audit
            // sink would double-record every routed event.
            runtime.recordAuditEvent(auditEvent);
          } catch {
            /* neither the chain nor the dashboard may break egress */
          }
          if (ledger) {
            try {
              appendFileSync(ledger, JSON.stringify({ ts: new Date().toISOString(), ...r }) + "\n");
            } catch {
              /* the ledger must never break egress */
            }
          }
        },
        onError: () => {
          /* upstream failures are the client's to see, not ours to crash on */
        },
      });
      app.log.info({ proxyPort, ledger }, "forward proxy listening (monitor mode, allow-all)");
    }
    console.log(`Agentwall running on http://${config.host}:${config.port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

main();
