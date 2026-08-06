import { esc } from "./render";
import { LAYER_MEANING, LAYER_STATE_MEANING, type EvidenceLayer } from "./scorecard";
import {
	HOST_STATE_MEANING,
	type CoverageGap,
	type FleetEvidenceReport,
	type HostAgentRollup,
	type HostEvidence,
	type HostState,
} from "./fleet";

/**
 * The fleet evidence view's HTML.
 *
 * Same construction as the single-host viewer and for the same reasons: no script at all, so
 * the page cannot mutate anything, cannot hold state a reviewer did not see, and renders the
 * same bytes for everyone who loads it. Every interpolated value goes through `esc()`, because
 * the values are audit records carrying agent-supplied strings and an evidence viewer that
 * executes what it is reviewing is the last place that should happen.
 *
 * The one thing this page does that the single-host page does not have to: it must never let a
 * host that could not be read look like a host with nothing to report. Every table below
 * carries the state chip, and the unreachable rows are styled as findings rather than as
 * blanks.
 */

const STYLES = `
:root {
	color-scheme: dark;
	--bg: #0b0e13;
	--panel: #131821;
	--edge: #232b39;
	--ink: #dfe6f1;
	--dim: #8d9aae;
	--pass: #3fb96b;
	--fail: #e5484d;
	--pending: #e3a008;
	--absent: #6b7a90;
}
* { box-sizing: border-box; }
body {
	margin: 0;
	padding: 2rem 1.5rem 4rem;
	background: var(--bg);
	color: var(--ink);
	font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
main { max-width: 1240px; margin: 0 auto; }
h1 { font-size: 1.35rem; margin: 0 0 .25rem; letter-spacing: .01em; }
h2 { font-size: 1rem; margin: 2.25rem 0 .6rem; text-transform: uppercase; letter-spacing: .1em; color: var(--dim); }
h3 { font-size: .9rem; margin: 1.4rem 0 .5rem; }
p { margin: .4rem 0; }
a { color: #7cb7ff; }
.sub { color: var(--dim); margin: 0 0 1.25rem; }
.banner {
	border: 1px solid var(--edge);
	border-left: 3px solid var(--pass);
	background: var(--panel);
	padding: .7rem .9rem;
	margin: 0 0 1.5rem;
}
.banner.broken { border-left-color: var(--fail); }
.banner.incomplete { border-left-color: var(--pending); }
.panel { border: 1px solid var(--edge); background: var(--panel); padding: .9rem 1rem; margin: 0 0 1rem; }
table { width: 100%; border-collapse: collapse; margin: .3rem 0 1rem; }
th, td { text-align: left; padding: .42rem .6rem; border-bottom: 1px solid var(--edge); vertical-align: top; }
th { color: var(--dim); font-weight: 600; text-transform: uppercase; font-size: .72rem; letter-spacing: .07em; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
tr.broken td { background: rgba(229, 72, 77, .11); }
tr.note td { background: rgba(227, 160, 8, .09); }
code, pre { font-family: inherit; }
pre {
	background: #090c11;
	border: 1px solid var(--edge);
	padding: .7rem .8rem;
	margin: .35rem 0 .8rem;
	overflow-x: auto;
	white-space: pre;
}
.chip {
	display: inline-block;
	padding: .05rem .45rem;
	border: 1px solid currentColor;
	font-size: .72rem;
	letter-spacing: .08em;
	text-transform: uppercase;
}
.chip.pass, .chip.verified { color: var(--pass); }
.chip.fail, .chip.broken, .chip.unreachable { color: var(--fail); }
.chip.pending, .chip.stale, .chip.incomplete, .chip.inconclusive { color: var(--pending); }
.chip.absent, .chip.empty { color: var(--absent); }
.dim { color: var(--dim); }
.fail { color: var(--fail); }
ul.problems { margin: .35rem 0 0; padding-left: 1.1rem; color: var(--fail); }
ul.notes { margin: .35rem 0 0; padding-left: 1.1rem; color: var(--pending); }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: .75rem; }
.stat { border: 1px solid var(--edge); padding: .55rem .7rem; }
.stat b { display: block; font-size: 1.35rem; font-weight: 600; font-variant-numeric: tabular-nums; }
.stat span { color: var(--dim); font-size: .74rem; text-transform: uppercase; letter-spacing: .07em; }
.stat.bad b { color: var(--fail); }
.stat.warn b { color: var(--pending); }
.wrap { word-break: break-all; }
footer { color: var(--dim); margin-top: 2.5rem; border-top: 1px solid var(--edge); padding-top: 1rem; }
`;

const READ_ONLY_BANNER = `<div class="banner">
<b>Read only.</b> This surface has no approve, deny, or edit path, serves no script, makes no
network request, and holds no credential on any agent host. It reads evidence that was already written and hashed somewhere else
and re-derives every hash from those bytes. Evidence you can edit from the console reviewing it
is not evidence. To act on a decision, use the operational dashboard or the CLI on the host that
owns it.
</div>`;

const NOT_A_CONTROL_PLANE = `<div class="panel">
<b>This is not a control plane, and that is the design.</b> Nothing here sits on an egress path.
If this process is down, every host keeps enforcing its own policy and keeps writing its own
chain: what is lost is visibility, never enforcement. The reverse arrangement, a central
authority between every agent and the internet, turns a management outage into an agent outage,
which is how a security tool gets switched off.
</div>`;

function page(title: string, body: string): string {
	return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${esc(title)}</title>
<style>${STYLES}</style>
</head><body><main>${body}</main></body></html>`;
}

function chip(state: string): string {
	return `<span class="chip ${esc(state)}">${esc(state)}</span>`;
}

/** Row class from a host state, so a host nobody could read never renders as a plain row. */
function rowClass(state: HostState): string {
	if (state === "broken" || state === "unreachable") return ' class="broken"';
	if (state === "inconclusive" || state === "stale" || state === "empty") return ' class="note"';
	return "";
}

function age(host: HostEvidence): string {
	if (host.lastSeen === null) return "never delivered anything to this path";
	const source =
		host.lastSeenSource === "record"
			? "newest record"
			: "newest evidence file mtime, which says when a file was touched and not when a decision was made";
	return `${host.lastSeen} (${host.ageSeconds}s ago, ${source})`;
}

/**
 * The coverage table.
 *
 * `observed` and `limit` are separate columns because they are separate claims: the limit is a
 * property of the controls and holds whatever any chain contains, while the count is what this
 * evidence happened to record. A row whose count is null renders the reason, never a zero,
 * because a table where every unmeasurable row reads zero has replaced its gaps with
 * reassurance.
 */
function coverageTable(gaps: readonly CoverageGap[]): string {
	const rows = gaps
		.map(
			(gap) => `<tr${gap.observed === null || gap.observed > 0 ? ' class="note"' : ""}>
	<td><b>${esc(gap.title)}</b><div class="dim">${esc(gap.id)}</div></td>
	<td class="num">${
		// Three outcomes, never two. "not measurable" is a permanent property of the gap;
		// "unmeasured" means this evidence had no population to count against, and it is the
		// one most likely to be misread as a zero. Only a number is a count.
		!gap.measurable ? "not measurable" : gap.observed === null ? "unmeasured" : esc(gap.observed)
	}</td>
	<td>${esc(gap.limit)}
		<div class="dim">${esc(gap.measurement)}</div>
		<div class="dim">${esc(gap.reference)}</div></td>
</tr>`,
		)
		.join("");
	return `<table>
<thead><tr><th>Gap</th><th>Records here</th><th>What is not covered</th></tr></thead>
<tbody>${rows}</tbody>
</table>`;
}

function layerCell(layers: readonly EvidenceLayer[]): string {
	return layers.map((l) => `${esc(l.name)} ${chip(l.state)}`).join("<br>");
}

function hostRow(host: HostEvidence): string {
	const t = host.report?.totals;
	return `<tr${rowClass(host.state)}>
	<td class="wrap"><a href="/evidence/fleet/host/${encodeURIComponent(host.id)}">${esc(host.label)}</a>
		<div class="dim">${esc(host.id)}</div></td>
	<td>${chip(host.state)}<div class="dim">${esc(HOST_STATE_MEANING[host.state])}</div></td>
	<td>${host.report ? layerCell(host.report.layers) : `<span class="fail">not checked</span>`}</td>
	<td class="num">${t ? esc(t.records) : "&mdash;"}</td>
	<td class="num">${t ? esc(t.faulty) : "&mdash;"}</td>
	<td class="num">${esc(host.agents.length)}</td>
	<td class="dim wrap">${esc(age(host))}</td>
</tr>`;
}

function reproduceBlock(host: HostEvidence): string {
	return `<p>Four implementations, written from <code>docs/audit-format.md</code> and held against
the same conformance corpus. They share no code with each other and none with the writer, so
reproducing a row does not require trusting this process, this language, or this machine. That
property is worth strictly more across a fleet than on one host: an auditor checks the
aggregator's answer without the aggregator. Each line runs from the repository root and leaves
you there, so the block can be pasted whole.</p>
<pre>${esc(host.reproduce.bundled)}
${esc(host.reproduce.go)}
${esc(host.reproduce.rust)}
${esc(host.reproduce.python)}</pre>
<p class="dim">A checkpoint signature verifies against the public key the checkpoint itself
carries, so unpinned it proves only internal consistency. Bind it to a key you supply from
outside the evidence:</p>
<pre>${esc(host.reproduce.pinned)}</pre>`;
}

function agentTable(agents: readonly HostAgentRollup[]): string {
	if (agents.length === 0) {
		return `<p class="dim">No record on this host names an agent. That is what an empty or unreadable chain looks like as well as a quiet one, so read the host state above before reading this as "no agents ran".</p>`;
	}
	const rows = agents
		.map((agent) => {
			const destinations =
				agent.destinations.length === 0
					? `<span class="dim">no proxied destination on record</span>`
					: agent.destinations
							.map((d) => `${esc(d.host)} <span class="dim">${esc(d.attempts)} attempt(s), ${esc(d.denied)} refused</span>`)
							.join("<br>") +
						(agent.distinctDestinations > agent.destinations.length
							? `<div class="dim">and ${esc(agent.distinctDestinations - agent.destinations.length)} more distinct destination(s)</div>`
							: "");
			const refused =
				agent.refusedBy.length === 0
					? `<span class="dim">nothing refused</span>`
					: agent.refusedBy.map((r) => `${esc(r.ruleId)} <span class="dim">&times;${esc(r.count)}</span>`).join("<br>");
			return `<tr${agent.denied > 0 ? ' class="note"' : ""}>
	<td class="wrap"><b>${esc(agent.agentId)}</b>
		<div class="dim">${esc(agent.label ?? "no declared label")}</div>
		<div class="dim">identity from: ${esc(agent.matchedOn.join(", ") || "nothing recorded")}${
			agent.declared === null ? "" : agent.declared ? " (declared agent)" : " (no declared agent claimed it)"
		}</div>
		<div class="dim">judged by: ${esc(agent.allowlistSources.join(", ") || "no allowlist named")}</div></td>
	<td class="num">${esc(agent.records)}<div class="dim">${esc(agent.sessions)} session(s)</div></td>
	<td class="num">${esc(agent.allowed)}</td>
	<td class="num">${esc(agent.denied)}</td>
	<td class="num">${esc(agent.approvals)}</td>
	<td class="num">${esc(agent.redactions)}</td>
	<td>${destinations}</td>
	<td>${refused}</td>
	<td>${
		agent.secretTypes.length === 0
			? `<span class="dim">none named</span>`
			: `${esc(agent.secretTypes.join(", "))}<div class="dim">seen in a proxied body and recorded by class. A proxied body is never rewritten, so this was not redacted on the wire.</div>`
	}${
		agent.monitorRecords > 0
			? `<div class="fail">${esc(agent.monitorRecords)} record(s) written in monitor mode, where an allow blocked nothing</div>`
			: ""
	}</td>
	<td class="dim wrap">${esc(agent.firstSeen ?? "no timestamp")}<br>to ${esc(agent.lastSeen ?? "no timestamp")}</td>
</tr>`;
		})
		.join("");
	return `<table>
<thead><tr>
	<th>Agent, and what the identity rests on</th><th>Records</th><th>Allowed</th><th>Refused</th>
	<th>To a human</th><th>Redacted</th><th>Destinations attempted</th><th>Refused by</th>
	<th>Credential material in flight</th><th>Window</th>
</tr></thead>
<tbody>${rows}</tbody>
</table>
<p class="dim">"Allowed" is the decision the record carries, which under monitor means the
connection was observed rather than permitted after a check it could have failed. "Redacted"
counts decisions on the /evaluate plane, where AgentWall returns the content and can rewrite it.
A proxied body is never rewritten, so credential material found on the wire is recorded and, in
guarded or strict, the connection is refused, but the bytes that already left are gone.</p>`;
}

const DOES_NOT_PROVE = `<footer>
<b>What this page does not establish.</b> Completeness, on any host: an intact chain shows that
what was written was not altered afterwards, never that everything which should have been
written was. Anything about a host that is not in the sources file, because this reads exactly
where it is told to look. Anything about a host it could not read: unreachable means the
evidence was not there, which does not distinguish a host that is down from a transport that
is. Any ordering between hosts: the chains are separate and independently anchored, and no
total order across them is claimed or needed.
</footer>`;

export function renderFleetIndex(report: FleetEvidenceReport): string {
	const t = report.totals;
	const unread = t.unreachable + t.inconclusive + t.stale + t.empty;
	return page(
		"AgentWall fleet evidence",
		`<h1>Fleet evidence</h1>
<p class="sub">${esc(t.hosts)} host(s) &middot; read at ${esc(report.generatedAt)} &middot;
freshness bound ${esc(report.staleAfterSeconds)}s &middot;
evidence window ${esc(report.window.from ?? "none")} to ${esc(report.window.to ?? "none")}</p>
${READ_ONLY_BANNER}

<div class="banner ${esc(report.verdict.state)}">
<b>${esc(report.verdict.state.toUpperCase())}.</b> ${esc(report.verdict.headline)}
<p class="dim">${esc(report.verdict.detail)}</p>
</div>

${NOT_A_CONTROL_PLANE}

<h2>Hosts</h2>
<div class="grid">
	<div class="stat"><b>${esc(t.verified)}</b><span>verified</span></div>
	<div class="stat ${t.broken > 0 ? "bad" : ""}"><b>${esc(t.broken)}</b><span>chain broken</span></div>
	<div class="stat ${t.unreachable > 0 ? "bad" : ""}"><b>${esc(t.unreachable)}</b><span>unreachable</span></div>
	<div class="stat ${t.inconclusive > 0 ? "warn" : ""}"><b>${esc(t.inconclusive)}</b><span>not judgeable</span></div>
	<div class="stat ${t.stale > 0 ? "warn" : ""}"><b>${esc(t.stale)}</b><span>stale</span></div>
	<div class="stat ${t.empty > 0 ? "warn" : ""}"><b>${esc(t.empty)}</b><span>recorded nothing</span></div>
	<div class="stat"><b>${esc(t.records)}</b><span>records read</span></div>
	<div class="stat ${t.faulty > 0 ? "bad" : ""}"><b>${esc(t.faulty)}</b><span>do not reproduce</span></div>
	<div class="stat"><b>${esc(t.agents)}</b><span>agents across the fleet</span></div>
</div>
${
	unread > 0
		? `<p class="fail">${esc(unread)} host(s) contribute no current findings to the counts above, and their absence
from those counts is not a zero. "No findings" and "could not look" are different answers and this
page refuses to render them alike.</p>`
		: ""
}

<table>
<thead><tr><th>Host</th><th>State</th><th>Layers, this host's own chain</th><th>Records</th><th>Faulty</th><th>Agents</th><th>Last seen</th></tr></thead>
<tbody>${report.hosts.map(hostRow).join("")}</tbody>
</table>
<p class="dim">Each row is a separate chain, verified on its own bytes by this process. A break
on one host is a finding on that host: nothing in another host's chain links to it, so nothing
in another host's verdict depends on it. That independence is the reason the chains are not
merged.</p>
<p class="dim">A host can read <b>verified</b> while its anchored layer reads <b>fail</b>, and that
is not a contradiction being papered over. <code>agentwall verify</code> fails that layer when
nothing has been anchored off-box, which is an absence of external evidence rather than external
evidence that disagrees. The layer is shown exactly as the CLI reports it, and the consequence is
counted in the coverage table below under <code>no-off-box-anchor</code>: a chain nobody anchored
can be rewritten whole by whoever holds the host, and nothing outside it would object.</p>

<h2>What every one of these verdicts cannot see</h2>
<p>Summed across the hosts that could be read. These are limits of the controls, not of this
page, and they are here rather than in a footnote because an audit answer that omits its own
gaps is worse than no answer.</p>
${coverageTable(report.coverage)}

${
	report.notes.length > 0
		? `<div class="panel"><b>Limits that applied to this read</b>
<ul class="notes">${report.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></div>`
		: ""
}
${DOES_NOT_PROVE}`,
	);
}

export function renderFleetHost(host: HostEvidence): string {
	const t = host.report?.totals;
	return page(
		`Fleet evidence: ${host.label}`,
		`<h1>${esc(host.label)}</h1>
<p class="sub">${esc(host.id)} &middot; ${esc(host.auditPath)} &middot;
<a href="/evidence/fleet">back to the fleet</a></p>
${READ_ONLY_BANNER}

<div class="banner ${host.state === "verified" ? "" : host.state === "broken" || host.state === "unreachable" ? "broken" : "incomplete"}">
<b>${esc(host.state.toUpperCase())}.</b> ${esc(host.detail)}
<p class="dim">Last seen: ${esc(age(host))}</p>
</div>

${
	host.report === null
		? `<h2>Nothing was checked</h2>
<p class="fail">${esc(host.unreachable?.reason ?? "The evidence could not be read.")}</p>
<p>No layer verdict is shown, because none was produced. A page that rendered a verdict over a
file it could not open would be inventing one, and the invented verdict would be either a false
clean or a false tampering alert. Neither is acceptable, so this host shows what it is: unread.</p>
<p class="dim">The path this aggregator looked at was <code class="wrap">${esc(host.auditPath)}</code>.
That is the whole of what was observed, so the cause is not stated here: nothing was read, and a
console that named a cause it did not check would be guessing in an incident. The candidates are
a transport that did not deliver, a path that does not match where the evidence actually lands, a
permission this process does not hold, a host that never wrote a chain because its audit file was
never configured, and a host that is down. Only the first and the last are usually what people
assume. This process makes no network request and holds no credential on any agent host, so it
cannot tell them apart and does not try.</p>`
		: `<h2>Verification, this host's own chain</h2>
<table>
<thead><tr><th>Layer</th><th>This view</th><th>Means</th><th>agentwall verify</th><th>Detail</th></tr></thead>
<tbody>${host.report.layers
				.map(
					(layer) => `<tr${layer.state === "fail" ? ' class="broken"' : layer.state === "pending" ? ' class="note"' : ""}>
	<td><b>${esc(layer.name)}</b></td>
	<td>${chip(layer.state)}</td>
	<td class="dim">${esc(LAYER_STATE_MEANING[layer.state] ?? "")}</td>
	<td>${esc(layer.cliVerdict)}</td>
	<td>${esc(layer.detail)}
		<div class="dim">${esc(LAYER_MEANING[layer.name] ?? "")}</div>
		${layer.divergence ? `<div class="dim">${esc(layer.divergence)}</div>` : ""}
		${layer.problems.length > 0 ? `<ul class="problems">${layer.problems.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}</td>
</tr>`,
				)
				.join("")}</tbody>
</table>

<div class="grid">
	<div class="stat"><b>${esc(t?.records ?? 0)}</b><span>records read</span></div>
	<div class="stat"><b>${esc(t?.intact ?? 0)}</b><span>reproduce their hash</span></div>
	<div class="stat ${(t?.faulty ?? 0) > 0 ? "bad" : ""}"><b>${esc(t?.faulty ?? 0)}</b><span>do not</span></div>
	<div class="stat ${(t?.declaredGaps ?? 0) > 0 ? "warn" : ""}"><b>${esc(t?.declaredGaps ?? 0)}</b><span>writer-declared gaps</span></div>
	<div class="stat"><b>${esc(t?.sessions ?? 0)}</b><span>sessions</span></div>
	<div class="stat"><b>${esc(host.agents.length)}</b><span>agents</span></div>
</div>

<h2>Which agents ran here, and what happened to them</h2>
<p class="dim">Window on this host: ${esc(host.firstSeen ?? "no timestamp")} to ${esc(host.lastSeen ?? "no timestamp")}.</p>
${agentTable(host.agents)}

<h2>What this host's evidence cannot see</h2>
${coverageTable(host.coverage)}`
}

<h2>Reproduce this host's verdict without trusting this page</h2>
${reproduceBlock(host)}
${DOES_NOT_PROVE}`,
	);
}
