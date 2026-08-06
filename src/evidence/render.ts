import {
	LAYER_MEANING,
	LAYER_STATE_MEANING,
	type AnchorReceipt,
	type EvidenceLayer,
	type EvidenceReport,
	type LayerState,
	type SessionScorecard,
} from "./scorecard";
import { FAULT_MEANING, type EvidenceRecord } from "./collect";

/**
 * The evidence viewer's HTML.
 *
 * NO SCRIPT, deliberately, and not only to satisfy the Content-Security-Policy this server
 * sets (`script-src 'self'`, so an inline script would be refused anyway). A page that cannot
 * run code cannot mutate anything, cannot hold state a reviewer did not see, and renders the
 * same bytes for everyone who loads it. The read-only guarantee is structural here rather
 * than a promise in a comment.
 *
 * Every interpolated value goes through esc(). The values are audit records, which carry
 * agent-supplied strings: a URL, a tool argument, a rule id from a policy file. An evidence
 * viewer that executes what it is reviewing is the last place that should happen.
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
main { max-width: 1180px; margin: 0 auto; }
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
.chip.pass { color: var(--pass); }
.chip.fail { color: var(--fail); }
.chip.pending { color: var(--pending); }
.chip.absent { color: var(--absent); }
.chip.confirmed { color: var(--pass); }
.chip.failed { color: var(--fail); }
.chip.unproven { color: var(--fail); }
.dim { color: var(--dim); }
ul.problems { margin: .35rem 0 0; padding-left: 1.1rem; color: var(--fail); }
ul.problems li { margin: .15rem 0; }
ul.notes { margin: .35rem 0 0; padding-left: 1.1rem; color: var(--pending); }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: .75rem; }
.stat { border: 1px solid var(--edge); padding: .55rem .7rem; }
.stat b { display: block; font-size: 1.35rem; font-weight: 600; font-variant-numeric: tabular-nums; }
.stat span { color: var(--dim); font-size: .74rem; text-transform: uppercase; letter-spacing: .07em; }
.wrap { word-break: break-all; }
footer { color: var(--dim); margin-top: 2.5rem; border-top: 1px solid var(--edge); padding-top: 1rem; }
`;

/**
 * HTML-escape. Covers the five characters that can break out of text or an attribute value.
 *
 * `'` is included because attribute values below are single-quote free but a future one may
 * not be, and an escape that is right only for the current markup is an escape that breaks
 * the next time somebody edits the template.
 */
export function esc(value: unknown): string {
	return String(value)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

function chip(state: LayerState | AnchorReceipt["state"]): string {
	return `<span class="chip ${esc(state)}">${esc(state)}</span>`;
}

function problemList(problems: readonly string[]): string {
	if (problems.length === 0) return "";
	return `<ul class="problems">${problems.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>`;
}

/**
 * One layer row.
 *
 * `state` and `cliVerdict` are printed side by side always, even when they agree. A column
 * that appears only on disagreement trains a reader to skim it, and the whole point of the
 * column is that the reviewer can see this page is not inventing a verdict of its own.
 */
function layerRow(layer: EvidenceLayer): string {
	return `<tr${layer.state === "fail" ? ' class="broken"' : layer.state === "pending" ? ' class="note"' : ""}>
	<td><b>${esc(layer.name)}</b></td>
	<td>${chip(layer.state)}</td>
	<td class="dim">${esc(LAYER_STATE_MEANING[layer.state as LayerState] ?? "")}</td>
	<td>${esc(layer.cliVerdict)}</td>
	<td>${esc(layer.detail)}
		<div class="dim">${esc(LAYER_MEANING[layer.name] ?? "")}</div>
		${layer.divergence ? `<div class="dim">${esc(layer.divergence)}</div>` : ""}
		${problemList(layer.problems)}</td>
</tr>`;
}

function layerTable(layers: readonly EvidenceLayer[]): string {
	return `<table>
<thead><tr><th>Layer</th><th>This view</th><th>Means</th><th>agentwall verify</th><th>Detail</th></tr></thead>
<tbody>${layers.map(layerRow).join("")}</tbody>
</table>`;
}

function anchorTable(anchors: readonly AnchorReceipt[]): string {
	if (anchors.length === 0) {
		return `<p class="dim">The anchor log holds no submissions. Nothing here is anchored off-box, and this view says so rather than leaving the layer looking green.</p>`;
	}
	const rows = anchors
		.map((a) => {
			const proof = a.proofProblem
				? `<div class="fail">${esc(a.proofProblem)}</div>`
				: a.proofPath
					? `<div class="dim wrap">${esc(a.proofPath)} (${esc(a.proofBytes)} bytes)</div>`
					: `<div class="dim">no proof file</div>`;
			const attest = [
				a.bitcoinAttestations
					? `${a.bitcoinAttestations} bitcoin attestation(s), block height(s) ${esc(a.bitcoinHeights.join(", "))}`
					: "",
				a.pendingAttestations ? `${a.pendingAttestations} calendar attestation(s), no block yet` : "",
			]
				.filter(Boolean)
				.join("; ");
			return `<tr class="${a.state === "confirmed" ? "" : a.state === "pending" ? "note" : "broken"}">
	<td class="num">${esc(a.line)}</td>
	<td>${esc(a.submittedAt ?? "unstated")}</td>
	<td>${chip(a.state)}${a.overclaimsStatus ? `<div class="dim">the record's own status says "${esc(a.statusClaimed)}"; its proof does not carry that</div>` : ""}</td>
	<td class="num">${esc(a.segments ?? "?")}</td>
	<td class="num">${a.coveredThroughIndex === null ? "unknown" : esc(a.coveredThroughIndex)}</td>
	<td>${esc(attest || "none")}
		${a.error ? `<div class="fail">${esc(a.error)}</div>` : ""}
		${a.digestMatchesCheckpoint ? "" : `<div class="fail">the submitted digest does not recompute from the checkpoint this record embeds, so the proof does not attest to it</div>`}
		<div class="dim wrap">${esc(a.reference || "no calendar answered")}</div>
		${proof}</td>
</tr>`;
		})
		.join("");
	return `<table>
<thead><tr>
	<th>Log line</th><th>Submitted</th><th>State</th><th>Sealed segments</th><th>Commits through record</th><th>Off-box evidence</th>
</tr></thead>
<tbody>${rows}</tbody>
</table>
<p class="dim">"Commits through record" is re-derived from the files on disk by finding which candidate reproduces the composite the checkpoint signed. It is not read off the record, because a record can say anything. "Sealed segments" is the checkpoint's own index, which counts segments and is not a record index.</p>`;
}

function fileTable(report: EvidenceReport): string {
	const rows = report.files
		.map(
			(f) => `<tr class="${f.exists ? (f.skipped ? "note" : "") : "broken"}">
	<td class="wrap">${esc(f.path)}</td>
	<td>${esc(f.role)}</td>
	<td class="num">${esc(f.bytes)}</td>
	<td class="num">${esc(f.records)}</td>
	<td class="num">${f.firstIndex === null ? "" : `${esc(f.firstIndex)} to ${esc(f.lastIndex)}`}</td>
	<td>${f.exists ? esc(f.skipped ?? "read") : "NOT ON DISK"}${
		f.sealedAs
			? `<div class="dim">sealed as ${esc(f.sealedAs.count)} record(s), index ${esc(f.sealedAs.firstIndex)} to ${esc(f.sealedAs.lastIndex)}</div>`
			: ""
	}</td>
</tr>`,
		)
		.join("");
	return `<table>
<thead><tr><th>File</th><th>Role</th><th>Bytes</th><th>Records read</th><th>Index span</th><th>Status</th></tr></thead>
<tbody>${rows}</tbody>
</table>`;
}

function offlineBlock(report: EvidenceReport): string {
	return `<h2>Reproduce this without trusting the page</h2>
<p>Every verdict above comes from the same files these commands read. Run them and you do not
have to take this view's word for anything, which is the only defensible position for a
console over evidence: a viewer must not be the root of trust for the thing it displays.</p>
<pre>${esc(report.offline.bundled)}
${esc(report.offline.bundledJson)}</pre>
<p class="dim">The bundled verifier ships with the service. The independent one shares no code with the writer and has no dependencies beyond the Go standard library:</p>
<pre>${esc(report.offline.independent)}</pre>
<p class="dim">A checkpoint signature verifies against the public key the checkpoint itself carries, so unpinned it proves only internal consistency. Bind it to a key you supply from outside the evidence:</p>
<pre>${esc(report.offline.pinned)}</pre>`;
}

function sessionRow(session: SessionScorecard): string {
	const label = session.sessionId === null ? "records with no session" : session.sessionId;
	const href = session.sessionId === null ? "/evidence/unattributed" : `/evidence/session/${encodeURIComponent(session.sessionId)}`;
	const denied = session.decisions.find((d) => d.decision === "deny")?.count ?? 0;
	const allowed = session.decisions.find((d) => d.decision === "allow")?.count ?? 0;
	return `<tr${session.layers.some((l) => l.state === "fail") ? ' class="broken"' : ""}>
	<td class="wrap"><a href="${esc(href)}">${esc(label)}</a>
		<div class="dim">${esc(session.agentIds.join(", ") || "no agent id")}</div></td>
	<td class="num">${esc(session.records)}</td>
	<td class="num">${esc(allowed)}</td>
	<td class="num">${esc(denied)}</td>
	<td class="num">${esc(session.detections.reduce((sum, d) => sum + d.count, 0))}</td>
	<td>${session.layers.map((l) => `${esc(l.name)} ${chip(l.state)}`).join("<br>")}</td>
	<td class="dim">${esc(session.lastSeen ?? "no timestamp")}</td>
</tr>`;
}

const READ_ONLY_BANNER = `<div class="banner">
<b>Read only.</b> This surface has no approve, deny, or edit path, and serves no script. It
renders records that were already written and hashed. Evidence you can edit from the console
reviewing it is not evidence. To act on a decision, use the operational dashboard or the CLI.
</div>`;

function notesBlock(report: EvidenceReport): string {
	if (report.notes.length === 0) return "";
	return `<div class="panel"><b>Limits that applied to this read</b>
<ul class="notes">${report.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></div>`;
}

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

const DOES_NOT_PROVE = `<footer>
<b>What this page does not establish.</b> Completeness: an intact chain shows that what was
written was not altered afterwards, never that everything which should have been written was.
A decision that was never recorded leaves nothing to detect here or in any verifier. Inclusion
in a Bitcoin block while an anchor is pending: pending means a calendar accepted a submission.
A checkpoint signature, unpinned, proves only that the log and the key travelled together.
</footer>`;

export function renderEvidenceIndex(report: EvidenceReport): string {
	const t = report.totals;
	return page(
		"AgentWall evidence",
		`<h1>Evidence viewer</h1>
<p class="sub">${esc(report.paths.auditPath)}</p>
${READ_ONLY_BANNER}
${notesBlock(report)}

<h2>Verification</h2>
${layerTable(report.layers)}
<p class="dim">Three properties, reported separately because they fail independently. One
combined tick would hide which of them an operator actually has.</p>

<h2>Coverage</h2>
<div class="grid">
	<div class="stat"><b>${esc(t.records)}</b><span>records read</span></div>
	<div class="stat"><b>${esc(t.intact)}</b><span>reproduce their hash</span></div>
	<div class="stat"><b>${esc(t.faulty)}</b><span>do not</span></div>
	<div class="stat"><b>${esc(t.declaredGaps)}</b><span>writer-declared gaps</span></div>
	<div class="stat"><b>${esc(t.sessions)}</b><span>sessions</span></div>
	<div class="stat"><b>${esc(report.anchors.length)}</b><span>anchor submissions</span></div>
</div>

<h2>Signed receipt timeline</h2>
${anchorTable(report.anchors)}

<h2>Evidence files</h2>
${fileTable(report)}

<h2>Sessions</h2>
<table>
<thead><tr><th>Session</th><th>Records</th><th>Allowed</th><th>Denied</th><th>Detections</th><th>Layers, scoped to this session</th><th>Last record</th></tr></thead>
<tbody>${report.sessions.map(sessionRow).join("") || `<tr><td colspan="7" class="dim">No records yet.</td></tr>`}</tbody>
</table>

${offlineBlock(report)}
${DOES_NOT_PROVE}`,
	);
}

function countTable(heading: string, rows: readonly { label: string; count: number }[]): string {
	if (rows.length === 0) return "";
	return `<h3>${esc(heading)}</h3>
<table><tbody>${rows
		.map((r) => `<tr><td>${esc(r.label)}</td><td class="num">${esc(r.count)}</td></tr>`)
		.join("")}</tbody></table>`;
}

function recordTable(records: readonly EvidenceRecord[]): string {
	const rows = records
		.map((rec) => {
			const condemned = rec.faults.length > 0;
			return `<tr class="${condemned ? "broken" : ""}">
	<td class="num">${rec.chainIndex === null ? "" : esc(rec.chainIndex)}</td>
	<td>${esc(rec.timestamp ?? "")}</td>
	<td>${esc(rec.plane ?? "")}</td>
	<td class="wrap">${esc(rec.action ?? "")}</td>
	<td>${esc(rec.decision ?? "")}</td>
	<td>${esc(rec.riskLevel ?? "")}</td>
	<td>${esc(rec.detections.map((d) => `${d.id} (${d.severity})`).join(", "))}</td>
	<td>${
		condemned
			? rec.faults
					.map((f) => `<div><b>${esc(f)}</b>: ${esc(FAULT_MEANING[f])}</div>`)
					.join("")
			: `<span class="dim">chained</span>`
	}${rec.chainGapDeclared ? `<div class="note">the writer declared ${esc(rec.droppedRecords ?? "an unstated number of")} record(s) could not be stored at this point</div>` : ""}</td>
</tr>`;
		})
		.join("");
	return `<table>
<thead><tr><th>Index</th><th>Time</th><th>Plane</th><th>Action</th><th>Decision</th><th>Risk</th><th>Detections</th><th>Integrity</th></tr></thead>
<tbody>${rows}</tbody>
</table>`;
}

export function renderSessionScorecard(report: EvidenceReport, session: SessionScorecard): string {
	const label = session.sessionId === null ? "Records with no session" : session.sessionId;
	const denied = session.decisions.find((d) => d.decision === "deny")?.count ?? 0;
	const allowed = session.decisions.find((d) => d.decision === "allow")?.count ?? 0;
	const approve = session.decisions.find((d) => d.decision === "approve")?.count ?? 0;
	const redact = session.decisions.find((d) => d.decision === "redact")?.count ?? 0;

	return page(
		`Session ${label}`,
		`<h1>${esc(label)}</h1>
<p class="sub">${esc(session.agentIds.join(", ") || "no agent id")} &middot;
${esc(session.firstSeen ?? "no timestamp")} to ${esc(session.lastSeen ?? "no timestamp")} &middot;
chain index ${session.firstIndex === null ? "none" : `${esc(session.firstIndex)} to ${esc(session.lastIndex)}`} &middot;
<a href="/evidence">all sessions</a></p>
${READ_ONLY_BANNER}

<h2>What the agent did</h2>
<div class="grid">
	<div class="stat"><b>${esc(session.records)}</b><span>records</span></div>
	<div class="stat"><b>${esc(allowed)}</b><span>allowed</span></div>
	<div class="stat"><b>${esc(denied)}</b><span>denied</span></div>
	<div class="stat"><b>${esc(approve)}</b><span>sent to approval</span></div>
	<div class="stat"><b>${esc(redact)}</b><span>redacted</span></div>
	<div class="stat"><b>${esc(session.detections.reduce((sum, d) => sum + d.count, 0))}</b><span>detections fired</span></div>
	<div class="stat"><b>${esc(session.highRiskFlows)}</b><span>high risk flows</span></div>
	<div class="stat"><b>${esc(session.intact)}/${esc(session.records)}</b><span>reproduce their hash</span></div>
</div>

<h2>Chain integrity for this span</h2>
${layerTable(session.layers)}
<p class="dim">Scoped to this session's records and to the chain span they occupy. The
"agentwall verify" column is file-wide, because that is what the command checks: there is no
per-session verify, and pretending otherwise would invent a verdict no tool produces. A
session can hold intact records inside a span whose ordering is broken by somebody else's
record, and the chained row above says so when it happens.</p>

${countTable(
	"Detections",
	session.detections.map((d) => ({ label: `${d.id} (${d.severity}) ${d.name}`, count: d.count })),
)}
${countTable(
	"Rules that matched",
	session.matchedRules.map((r) => ({ label: r.ruleId, count: r.count })),
)}
${countTable(
	"Actions",
	session.actions.map((a) => ({ label: a.action, count: a.count })),
)}
${countTable(
	"Planes",
	session.planes.map((p) => ({ label: p.plane, count: p.count })),
)}
${countTable(
	"Risk levels",
	session.riskLevels.map((r) => ({ label: r.riskLevel, count: r.count })),
)}

<h2>Records</h2>
${recordTable(session.chainRecords)}

<h2>Reproduce this without trusting the page</h2>
<p>The verdict is file-wide, so the first command is the one that decides it. The second pulls
this session's records straight out of the JSONL, by member rather than by text match, so it
does not depend on how the writer happened to order the keys.</p>
<pre>${esc(report.offline.bundled)}
${esc(report.offline.session(session.sessionId))}</pre>
${DOES_NOT_PROVE}`,
	);
}
