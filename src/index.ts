import { loadConfig } from "./config";
import { buildServer } from "./server";
import { createForwardProxy } from "./proxy/forward-proxy";
import type { ProxyRecord } from "./proxy/forward-proxy";
import { createTransparentProxy } from "./proxy/transparent";
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

  /**
   * File one egress connection on the audit chain and the dashboard.
   *
   * Egress evidence has to be tamper-evident, not merely present. An unchained append can be
   * edited away with a single `sed -i` while verifyChainFile() still passes, so egress joins
   * the same hash chain as every other decision.
   *
   * Shared by both transports on purpose. The forward proxy and the transparent listener are
   * two ways into the same control, and two copies of this would eventually disagree about
   * what an egress record contains — leaving an operator to reconcile two ledger shapes for
   * one kind of event. `transportMode` is the only thing that differs, and it is recorded
   * rather than inferred from an absent field: "the client cooperated with the proxy
   * environment" and "the kernel redirected this whether the client liked it or not" are
   * materially different claims about how much the evidence can be trusted.
   */
  const recordEgress = (r: ProxyRecord, mode: EnforcementMode, transportMode: "forward" | "transparent"): void => {
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
            // The mode is part of the evidence. "Allowed" means something different in
            // monitor than in strict, and a ledger that omits which one was running cannot
            // be read back a month later.
            enforcementMode: mode,
            transportMode,
          },
        },
        {
          // The real verdict, not a fixed string. Monitor mode still records "allow" here
          // because the connection really was made; what monitor would have done instead is
          // spelled out in the reasons.
          decision: r.decision,
          riskLevel: r.riskLevel ?? "low",
          matchedRules,
          reasons: [...r.reasons],
          requiresApproval: false,
          highRiskFlow: r.riskLevel === "high" || r.riskLevel === "critical",
          detections: detectionsForRules(matchedRules),
        }
      );
      // The five route handlers already feed the dashboard directly; the proxies are the
      // producers that bypass them, which is why the console read "Awaiting first live agent
      // activity" while the proxy was handling real traffic. Wire only this path: a global
      // audit sink would double-record every routed event.
      runtime.recordAuditEvent(auditEvent);
    } catch {
      /* neither the chain nor the dashboard may break egress */
    }
  };

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
          recordEgress(r, mode, "forward");
          // The flat ledger is a convenience view for allowlist analysis, not the record;
          // the hash chain above is.
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

    // Transparent listener: the same control, without the cooperation.
    //
    // The forward proxy above only sees traffic from a client that read HTTPS_PROXY and
    // chose to use it. This one is fed by the kernel: nftables owner-matches the agent's
    // dedicated UID and redirects its outbound TCP here, so a process that ignores every
    // proxy environment variable arrives anyway. Configured rather than env-gated, because
    // it is only meaningful alongside the nftables rules that point at it, and those are
    // installed deliberately rather than by exporting a variable.
    const transparent = config.transparent;
    if (transparent && transparent.port > 0) {
      const transparentHost = transparent.host ?? "127.0.0.1";
      // 443 unless the ruleset says otherwise. A captured TLS connection carries no port, so
      // this is the listener's only statement of one; it has to match what nftables redirects
      // or an allowed connection lands on the wrong service of the right host.
      const transparentTlsPort = transparent.tlsPort ?? 443;
      // Read once for the same reason the forward proxy reads it once: decideEgress runs
      // inside a socket handler with no view of configuration.
      const mode = config.enforcement?.mode ?? "monitor";
      setEgressAllowlist(config.egress.allowedHosts);

      createTransparentProxy({
        port: transparent.port,
        host: transparentHost,
        defaultTlsPort: transparentTlsPort,
        decide: (attempt) => {
          const verdict = decideEgress(
            {
              host: attempt.host,
              port: attempt.port,
              scheme: attempt.scheme,
              // No method and no /proc attribution on this path: a redirected connection
              // carries neither, and decideEgress treats them as optional. An enforcing
              // policy therefore sees a null client here and can fail closed on its own
              // terms rather than being handed a guess.
              method: attempt.scheme === "https" ? "CONNECT" : undefined,
              comm: null,
              pid: null,
            },
            mode,
            engine
          );
          // Narrowed on "allow" for the same reason as the forward proxy: anything that is
          // not an explicit permission is a refusal.
          return {
            decision: verdict.decision === "allow" ? "allow" : "deny",
            reasons: verdict.reasons,
            matchedRules: verdict.matchedRules,
            riskLevel: verdict.riskLevel,
          };
        },
        record: (r) => recordEgress(r, mode, "transparent"),
        onError: () => {
          /* upstream failures are the client's to see, not ours to crash on */
        },
      });
      app.log.info(
        {
          transparentPort: transparent.port,
          transparentHost,
          transparentTlsPort,
          mode,
          allowlistSize: config.egress.allowedHosts.length,
        },
        `transparent proxy listening on ${transparentHost}:${transparent.port} in ${mode} mode: ` +
          `${MODE_SUMMARY[mode]}. It expects kernel redirection — nothing reaches it unless nftables ` +
          `redirects the agent UID's outbound TCP to this port. A destination it cannot name from SNI ` +
          `or a Host header is denied, and a TLS destination is opened on port ${transparentTlsPort}, ` +
          `which must be a port the ruleset actually redirects.`
      );
    }
    console.log(`Agentwall running on http://${config.host}:${config.port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

main();
