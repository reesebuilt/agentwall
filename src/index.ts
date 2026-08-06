import { loadConfig } from "./config";
import { buildServer } from "./server";
import { createForwardProxy } from "./proxy/forward-proxy";
import { emit } from "./audit/logger";
import { detectionsForRules } from "./policy/detections";
import { decideEgress, setEgressAllowlist } from "./runtime/enforcement";
import type { EnforcementMode } from "./runtime/enforcement";

/**
 * What each mode does, in the startup log, in words an operator can act on.
 *
 * A boot line that says only `mode: strict` tells someone reading logs at 3am nothing about
 * why every outbound call started failing. Naming the behaviour costs one line and answers
 * the question before it is asked.
 */
const MODE_SUMMARY: Record<EnforcementMode, string> = {
  monitor: "recording every destination and blocking nothing",
  guarded: "blocking destinations a policy rule denies",
  strict: "blocking every destination outside the egress allowlist",
};

async function main() {
  const config = loadConfig();
  const { app, engine, runtime } = await buildServer(config);

  try {
    await app.listen({ port: config.port, host: config.host });

    // Forward proxy: the insertion mechanism. Opt-in via env so it never starts
    // unexpectedly, and bound to loopback like everything else on this host.
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

      // Mode and allowlist are read once, here, rather than per connection: decideEgress
      // runs inside a socket handler that has no view of configuration, and re-reading
      // config on the egress hot path would put file I/O in front of every model API call.
      // The consequence is that changing either needs a restart, which is the correct
      // ceremony for a change that can take an agent fleet offline. Policy RULES are not
      // in that bargain: the engine is held by reference and reloads mutate it in place, so
      // a hot-reloaded rule takes effect on the next connection.
      const mode = config.enforcement?.mode ?? "monitor";
      setEgressAllowlist(config.egress.allowedHosts);

      createForwardProxy({
        port: proxyPort,
        host: process.env.AGENTWALL_PROXY_HOST ?? "127.0.0.1",
        decide: (event) => {
          const verdict = decideEgress(
            {
              host: event.host,
              port: event.port,
              scheme: event.scheme,
              method: event.method,
              comm: event.client.comm,
              pid: event.client.pid,
            },
            mode,
            engine
          );
          // Narrowed on "allow", not on "deny", so the connection is refused unless
          // something explicitly permitted it. decideEgress only ever returns allow or deny
          // today; if that ever changes, this fails closed rather than treating an
          // unrecognised decision as permission.
          return {
            decision: verdict.decision === "allow" ? "allow" : "deny",
            reasons: verdict.reasons,
            matchedRules: verdict.matchedRules,
            riskLevel: verdict.riskLevel,
          };
        },
        record: (r) => {
          // Egress evidence has to be tamper-evident, not merely present. An
          // unchained append can be edited away with a single `sed -i` while
          // verifyChainFile() still passes, so egress joins the same hash chain as
          // every other decision. The flat ledger below is a convenience view for
          // allowlist analysis, not the record.
          try {
            const matchedRules = [...r.matchedRules];
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
                  // The mode is part of the evidence. "Allowed" means something different
                  // in monitor than in strict, and a ledger that omits which one was
                  // running cannot be read back a month later.
                  enforcementMode: mode,
                },
              },
              {
                // The real verdict, not a fixed string. Monitor mode still records
                // "allow" here because the connection really was made; what monitor
                // would have done instead is spelled out in the reasons.
                decision: r.decision,
                riskLevel: r.riskLevel ?? "low",
                matchedRules,
                reasons: [...r.reasons],
                requiresApproval: false,
                highRiskFlow: r.riskLevel === "high" || r.riskLevel === "critical",
                detections: detectionsForRules(matchedRules),
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
      app.log.info(
        { proxyPort, ledger, mode, allowlistSize: config.egress.allowedHosts.length },
        `forward proxy listening in ${mode} mode: ${MODE_SUMMARY[mode]}`
      );
    }
    console.log(`Agentwall running on http://${config.host}:${config.port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

main();
