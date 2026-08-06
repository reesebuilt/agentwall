import { loadConfig } from "./config";
import { buildServer } from "./server";
import { createForwardProxy } from "./proxy/forward-proxy";
import type { ProxyRecord } from "./proxy/forward-proxy";
import { createTransparentProxy } from "./proxy/transparent";
import { emit } from "./audit/logger";
import { detectionsForRules } from "./policy/detections";
import { decideEgress, setEgressPolicy, setFleet } from "./runtime/enforcement";
import type { EnforcementMode, EgressVerdict } from "./runtime/enforcement";
import { AgentRegistry } from "./fleet/registry";
import { AgentBudgetLedger } from "./fleet/budget";

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
  const { app, engine, runtime, reloadCoordinator } = await buildServer(config);

  // SIGHUP reloads policy.yaml and agentwall.config.yaml. Installed HERE and not in
  // buildServer, because signals belong to the process: buildServer is a library function that
  // the test suite and embedding callers invoke many times in one process, and installing from
  // there would stack one listener per instance and make a single signal reload N times.
  reloadCoordinator.installSignalHandler();

  /**
   * Install the declared fleet before either proxy starts.
   *
   * Constructed once, here, rather than per proxy block: both transports call the same
   * decideEgress, and two registries would mean two budget ledgers and an agent that gets
   * its whole allowance twice by using both paths. Absent config leaves the fleet null,
   * which is the single-agent deployment and behaves exactly as it did before agents existed.
   *
   * The constructor throws on a fleet that cannot resolve deterministically (two agents
   * matching the same connection, a credential in a form that would put a secret in the
   * config file). Letting that reach the operator as a boot failure is the point.
   */
  const fleet = config.fleet && config.fleet.agents.length > 0 ? new AgentRegistry(config.fleet) : null;
  const budgets = fleet ? new AgentBudgetLedger() : null;
  setFleet(fleet, budgets);
  if (fleet) {
    app.log.info(
      {
        agents: fleet.list().map((agent) => agent.id),
        unmatched: fleet.unmatched,
        scopedAllowlists: fleet.list().filter((agent) => agent.egress).length,
        budgeted: fleet.list().filter((agent) => agent.budget).length,
      },
      `fleet: ${fleet.size} declared agent(s) on this host. Governance is per-agent and single-host: ` +
        `there is no cross-instance identity and no shared budget.`
    );
  }

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
          // The attribution the decision actually enforced, echoed back through the record.
          // Re-resolving here could disagree with the identity that was gated, and a ledger
          // whose agentId was computed by a different code path than the allow is a ledger
          // that cannot be used to answer "which agent did this".
          agentId: r.attribution?.agentId ?? r.client.comm ?? "unattributed",
          plane: "network",
          action: `egress:${r.scheme}`,
          metadata: {
            host: r.host,
            port: String(r.port),
            scheme: r.scheme,
            method: r.method,
            // Present only when a ClientHello was actually read, so an https record with no
            // `sni` key means no name was recovered rather than "the name was empty". The
            // mismatch flag is written as its own field rather than left to be recomputed
            // from host vs sni: the comparison was made at decision time and the ledger
            // should carry the answer, not the ingredients.
            ...(r.sni ? { sni: r.sni } : {}),
            ...(r.sniMismatch ? { sniMismatch: "true" } : {}),
            pid: r.client.pid == null ? "unknown" : String(r.client.pid),
            comm: r.client.comm ?? "unknown",
            uid: r.client.uid == null ? "unknown" : String(r.client.uid),
            durationMs: String(r.durationMs ?? 0),
            bytesUp: String(r.bytesUp ?? 0),
            bytesDown: String(r.bytesDown ?? 0),
            // The mode is part of the evidence. "Allowed" means something different in
            // monitor than in strict, and a ledger that omits which one was running cannot
            // be read back a month later.
            enforcementMode: mode,
            transportMode,
            // How much of this exchange was actually readable. Without it a row with no
            // findings is ambiguous between "nothing was there" and "we could not look",
            // and the second one reads exactly like the first to anyone skimming.
            bodyVisibility: r.bodyVisibility,
            // The content scan's evidence, already namespaced by direction: what class of
            // thing was found and where. Never the matched value. A DLP record that carries
            // the secret it detected hands anyone with log access the thing the detection
            // existed to protect, and this record goes to a SIEM and an incident ticket.
            //
            // Spread last so a content key can never shadow one of the fixed fields above;
            // every key it produces is `content`-prefixed, so today it cannot, and this keeps
            // that true if one is ever renamed.
            ...(r.metadata ?? {}),
            // The resource, pathname only. `ProxyRecord.path` has already had its query
            // string removed by the proxy, because a query is attacker-chosen content and is
            // one of the places the scan finds credentials; recording it here would put the
            // detected secret in the record that reports the detection. How large the query
            // was travels instead, in `pathQueryBytes` from the same source.
            ...(r.path === undefined ? {} : { path: r.path }),
            // Which agent, on what evidence, judged against whose allowlist, and where its
            // budget stood. Spread last so the decision's own account of the connection wins
            // over anything assembled here.
            ...r.attribution,
          },
          // Empty on purpose, and `emit` does not copy it either way. Nothing derived from
          // request content belongs in a field whose name invites someone to put it there.
          payload: {},
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

    // Charge the bytes this connection actually moved, after the record is filed. Separate
    // from the try above on purpose: an audit sink failure must not also lose the accounting,
    // or an agent could hold its budget open by making the chain fail.
    const agentId = r.attribution?.agentId;
    if (budgets && agentId && r.budgetTicket != null) {
      budgets.settle(agentId, r.budgetTicket, (r.bytesUp ?? 0) + (r.bytesDown ?? 0));
    }
  };

  /**
   * The metadata fragment a verdict contributes to its record.
   *
   * Built here rather than inside decideEgress because it is a presentation concern: the
   * verdict already carries these as typed fields, and only the audit record needs them
   * flattened to strings.
   */
  const attributionOf = (verdict: EgressVerdict): Record<string, string> => {
    const fields: Record<string, string> = {
      agentId: verdict.agent.id,
      agentLabel: verdict.agent.label,
      agentMatchedOn: verdict.agent.matchedOn,
      agentDeclared: verdict.agent.declared ? "true" : "false",
      egressAllowlistSource: verdict.agent.allowlistSource,
    };
    if (verdict.budget) {
      fields["budgetWindowSeconds"] = String(verdict.budget.windowSeconds);
      fields["budgetRequests"] = String(verdict.budget.requests);
      fields["budgetBytes"] = String(verdict.budget.bytes);
      if (verdict.budget.maxRequests !== null) fields["budgetMaxRequests"] = String(verdict.budget.maxRequests);
      if (verdict.budget.maxBytes !== null) fields["budgetMaxBytes"] = String(verdict.budget.maxBytes);
    }
    return fields;
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
      // ceremony for a change that can take an agent fleet offline. A reload reports both
      // keys as restart-required rather than pretending to apply them.
      //
      // Policy RULES are not in that bargain: the engine is held by reference, a reload swaps
      // the immutable snapshot it points at, and a hot-reloaded rule takes effect on the next
      // connection. This comment used to say reloads "mutate it in place", which was wrong in a
      // way worth correcting: replaceRules builds a NEW frozen snapshot rather than editing the
      // live one, which is exactly why a connection already being decided cannot observe a
      // half-applied ruleset.
      const mode = config.enforcement?.mode ?? "monitor";
      setEgressPolicy({ hosts: config.egress.allowedHosts, ports: config.egress.allowedPorts });

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
              // Everything the plaintext HTTP path could read, passed straight through. All
              // three are absent on CONNECT and on the connection-level call the proxy makes
              // before any body exists, so `decideEgress` scans exactly when there is
              // something to scan and the tunnel path costs nothing it did not cost before.
              path: event.path,
              headers: event.headers,
              body: event.body,
              uid: event.client.uid,
              credential: event.credential,
              // A later look at one connection, so the budget reports the window and charges
              // nothing. Set by the proxy, which is the only place that knows which call is
              // the first one.
              reDecision: event.reDecision,
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
            metadata: verdict.metadata,
            attribution: attributionOf(verdict),
            budgetTicket: verdict.budgetTicket,
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
        // Both allowlists, because strict now gates on host AND port. A boot line that names
        // only the hosts leaves an operator whose calls all started failing on a port grep
        // through config for the half that is actually denying them.
        { proxyPort, ledger, mode, allowedHosts: config.egress.allowedHosts.length, allowedPorts: config.egress.allowedPorts },
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
      setEgressPolicy({ hosts: config.egress.allowedHosts, ports: config.egress.allowedPorts });

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
              // No method, no /proc attribution, and no presented credential on this path: a
              // redirected connection carries none of them, and decideEgress treats them all
              // as optional. An enforcing policy therefore sees a null client here and can
              // fail closed on its own terms rather than being handed a guess. In fleet terms
              // that means a redirected connection resolves to the undeclared agent, which
              // `fleet.unmatched: "deny"` will refuse; docs/fleet.md states the interaction.
              method: attempt.scheme === "https" ? "CONNECT" : undefined,
              comm: null,
              pid: null,
              uid: null,
              credential: null,
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
            attribution: attributionOf(verdict),
            budgetTicket: verdict.budgetTicket,
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
          allowedHosts: config.egress.allowedHosts.length,
          allowedPorts: config.egress.allowedPorts,
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
