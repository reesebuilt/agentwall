const REFRESH_MS = 5000;
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const MUTATING_ACTIONS = new Set([
  "approval-mode",
  "shield",
  "normal",
  "session-boost",
  "session-reset",
  "pause",
  "resume",
  "terminate",
  "fleet-issue",
  "fleet-rotate",
  "fleet-revoke",
  "anchor",
  "verify-capture",
  "mcp-wrap",
  "mcp-http-wrap",
  "mcp-http-stop",
  "perimeter-install",
  "perimeter-rollback",
  "perimeter-run",
  "sandbox-build",
  "sandbox-run",
  "intercept-init",
  "intercept-trust",
  "decoy-generate",
]);

const DESTRUCTIVE_ACTIONS = new Set([
  "normal",
  "session-reset",
  "pause",
  "resume",
  "terminate",
  "fleet-issue",
  "fleet-rotate",
  "fleet-revoke",
  "anchor",
  "verify-capture",
  "mcp-wrap",
  "mcp-http-wrap",
  "mcp-http-stop",
  "perimeter-install",
  "perimeter-rollback",
  "perimeter-run",
  "sandbox-build",
  "sandbox-run",
  "intercept-init",
  "intercept-trust",
  "decoy-generate",
]);

const {
  GROUP_TARGETS,
  normalizeActionGroup,
  renderStructuredActionFailure,
  actionResultOutput,
} = globalThis.AgentwallActionCatalog;

const GROUP_LABELS = {
  runtime: "Runtime controls",
  sessions: "Session controls",
  fleet: "Fleet credentials",
  evidence: "Evidence controls",
  mcp: "MCP controls",
  perimeter: "Perimeter controls",
  sandbox: "Sandbox controls",
  interception: "Certificate controls",
  decoy: "Decoy controls",
};

let currentState = null;
let operatorActions = [];
let eventsStream = null;
let pollTimer = null;
let feedbackTimer = null;
let firstStateLoaded = false;

class RequestError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = "RequestError";
    this.status = status;
    this.data = data;
  }
}

function byId(id) {
  return document.getElementById(id);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}

function setText(id, value) {
  const element = byId(id);
  if (element) element.textContent = String(value ?? "");
}

function setDot(id, kind) {
  const dot = byId(id);
  if (!dot) return;
  dot.className = `state-dot state-${kind}`;
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value ?? 0));
}

function formatDateTime(value) {
  if (!value) return "No update";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No update";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function formatRelative(value) {
  if (!value) return "No recent activity";
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return "No recent activity";
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  if (seconds < 10) return "Just now";
  if (seconds < 60) return `${seconds} seconds ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function titleFromId(value) {
  return String(value ?? "")
    .split("-")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function csv(value) {
  return String(value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function stateKind(value) {
  const state = String(value ?? "").toLowerCase();
  if (["critical", "failed", "degraded", "denied", "terminated", "error"].includes(state)) return "danger";
  if (["warning", "stale", "paused", "attention", "high"].includes(state)) return "warning";
  if (["pending", "starting", "waiting", "medium"].includes(state)) return "pending";
  return "ok";
}

function authMessage(status) {
  if (status !== 401 && status !== 403) return null;
  return "This console has no local operator access. Open the console from the bootstrap page, then try again.";
}

async function requestJSON(url, options = {}) {
  const request = {
    method: options.method || "GET",
    credentials: "same-origin",
    headers: { accept: "application/json", ...(options.headers || {}) },
  };
  if (options.body !== undefined) {
    request.headers["content-type"] = "application/json";
    request.body = JSON.stringify(options.body);
  }

  const response = await fetch(url, request);
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json().catch(() => ({}))
    : await response.text().catch(() => "");

  if (!response.ok) {
    const safeMessage = authMessage(response.status)
      || (typeof data === "object" && data ? data.message || data.error || data.detail : data)
      || `Agentwall returned status ${response.status}.`;
    throw new RequestError(String(safeMessage), response.status, data);
  }
  return data;
}

function postJSON(url, body) {
  return requestJSON(url, { method: "POST", body });
}

function setConnectionState(kind, label, detail) {
  setDot("connection-dot", kind);
  setText("connection-state", label);
  setText("last-update", detail);
}

function hideGlobalError() {
  const error = byId("operator-error");
  if (error) error.hidden = true;
}

function showGlobalError(error, title = "Agentwall did not return status.") {
  setText("operator-error-title", error instanceof RequestError && authMessage(error.status)
    ? "Local operator access is missing."
    : title);
  setText("operator-error-detail", error?.message || "Check the service, then try again.");
  const panel = byId("operator-error");
  if (panel) panel.hidden = false;
}

function showFeedback(kind, title, message) {
  window.clearTimeout(feedbackTimer);
  const panel = byId("operator-feedback");
  if (!panel) return;
  panel.className = kind === "error" ? "notice notice-error" : "notice";
  panel.replaceChildren();
  const copy = document.createElement("div");
  const heading = document.createElement("strong");
  heading.textContent = title;
  copy.append(heading);
  if (message) {
    const detail = document.createElement("p");
    detail.textContent = message;
    copy.append(detail);
  }
  panel.append(copy);
  panel.hidden = false;
  feedbackTimer = window.setTimeout(() => {
    panel.hidden = true;
  }, prefersReducedMotion ? 8000 : 6000);
}

function emptyState(title, message, error = false) {
  return `<div class="empty-state${error ? " empty-state-error" : ""}"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(message)}</p></div>`;
}

function stateLabel(label, kind) {
  return `<span class="state-label state-label-${escapeAttribute(kind)}"><span class="state-dot state-${escapeAttribute(kind)}" aria-hidden="true"></span>${escapeHtml(label)}</span>`;
}

function selectNextAction(state) {
  const pending = state?.approvals?.pending || [];
  if (pending.length > 0) {
    const first = pending[0];
    return {
      text: `Review ${first.action || "the next request"} for ${first.agentId || "an agent"}.`,
      href: "#approvals",
      label: "Open approvals",
    };
  }
  const recommended = state?.service?.recommendedActions?.[0];
  if (recommended) {
    return { text: recommended, href: "#operations", label: "Open operations" };
  }
  return {
    text: "No urgent action is open. Review recent evidence when you need proof.",
    href: "#evidence",
    label: "Open evidence",
  };
}

function renderStatus(state) {
  const serviceStatus = String(state?.service?.status || "unknown");
  const attention = Boolean(state?.service?.attentionRequired);
  const kind = attention ? "warning" : stateKind(serviceStatus);
  const protection = serviceStatus === "operational" && !attention
    ? "Protected"
    : attention
      ? "Review required"
      : titleFromId(serviceStatus) || "Unknown";
  const summary = state?.service?.operatorSummary || "Agentwall has not sent a status summary.";
  const generatedAt = state?.generatedAt;
  const pendingCount = state?.approvals?.pending?.length || 0;
  const activeRules = state?.health?.ruleCount ?? state?.policyCatalog?.scopedRules?.length ?? 0;
  const activeAgents = state?.posture?.activeAgentsNow ?? state?.posture?.activeAgents ?? state?.activeAgents?.length ?? 0;
  const mode = state?.floodGuard?.mode || state?.controls?.approvalMode || "unknown";

  byId("status-loading").hidden = true;
  byId("status-content").hidden = false;
  setDot("protection-state-dot", kind);
  setDot("header-state-dot", kind);
  setText("protection-state", protection);
  setText("protection-summary", summary);
  setText("header-service-state", protection);
  setText("current-mode", mode);
  setText("active-agent-count", formatNumber(activeAgents));
  setText("pending-approval-count", formatNumber(pendingCount));
  setText("active-rule-count", formatNumber(activeRules));
  setText("status-timestamp", `Updated ${formatDateTime(generatedAt)}`);

  const warning = byId("important-warning");
  const stale = state?.freshness?.hasLiveActivity && !state?.freshness?.isFresh;
  if (attention || stale) {
    warning.hidden = false;
    setText(
      "important-warning-text",
      stale
        ? "Live status is stale. Check agent heartbeats before you trust the current state."
        : state?.service?.recommendedActions?.[0] || "Agentwall found a state that needs review."
    );
  } else {
    warning.hidden = true;
  }

  const next = selectNextAction(state);
  setText("next-action-text", next.text);
  const link = byId("next-action-link");
  link.href = next.href;
  link.textContent = next.label;
}

function renderApprovals(state) {
  const pending = Array.isArray(state?.approvals?.pending) ? state.approvals.pending : [];
  const container = byId("approvals-list");
  const count = pending.length;
  setText("approvals-count", `${count} open`);
  setText("approval-nav-count", count);
  const navCount = byId("approval-nav-count");
  navCount.hidden = count === 0;

  if (count === 0) {
    container.innerHTML = emptyState(
      "No approvals need review.",
      "Agentwall will show the next decision here."
    );
    return;
  }

  container.innerHTML = pending.map((item) => {
    const kind = stateKind(item.riskLevel || item.status);
    const requestId = escapeAttribute(item.requestId || "");
    const action = item.action || "Agent action";
    const actor = item.agentId || "Unknown agent";
    const reason = item.triageDetail || item.note || item.reasons?.[0] || "Review the request details before you decide.";
    return `<article class="decision-row" data-approval-id="${requestId}">
      <div class="row-main">
        <div class="row-title"><strong>${escapeHtml(action)}</strong>${stateLabel(item.riskLevel || "pending", kind)}</div>
        <p class="row-copy">${escapeHtml(reason)}</p>
        <p class="row-meta">${escapeHtml(actor)} · ${escapeHtml(item.sessionId || "No session")} · ${escapeHtml(formatRelative(item.createdAt))}</p>
      </div>
      <div class="row-actions">
        <button class="button button-small button-primary" type="button" data-approval-decision="approved" data-request-id="${requestId}">Approve</button>
        <button class="button button-small button-danger" type="button" data-approval-decision="denied" data-request-id="${requestId}">Deny</button>
      </div>
    </article>`;
  }).join("");
}

function renderPolicy(state) {
  const catalog = state?.policyCatalog || {};
  const rules = Array.isArray(catalog.scopedRules) ? catalog.scopedRules : [];
  const container = byId("policy-summary");
  setText("policy-file-state", catalog.editable ? "Edit enabled" : "Read only");

  if (rules.length === 0) {
    container.innerHTML = emptyState(
      "No scoped rules are present.",
      catalog.note || "Agentwall still applies the base policy. Add a scoped rule only when you need one."
    );
  } else {
    container.innerHTML = rules.slice(0, 8).map((rule) => {
      const decision = rule.decision || "unknown";
      const kind = decision === "deny" ? "ok" : decision === "allow" ? "warning" : "pending";
      return `<article class="plain-row">
        <div class="row-main">
          <div class="row-title"><strong>${escapeHtml(rule.description || rule.id || "Scoped rule")}</strong>${stateLabel(decision, kind)}</div>
          <p class="row-copy">${escapeHtml(rule.reason || "No rule reason is available.")}</p>
          <p class="row-meta">${escapeHtml(rule.id || "No ID")} · ${escapeHtml(rule.plane || "all")} plane</p>
        </div>
      </article>`;
    }).join("");
  }

  const editor = byId("policy-editor");
  if (editor) editor.hidden = !catalog.editable;
}

function renderChannelFirewall(state) {
  const catalog = state?.policyCatalog || {};
  const channel = catalog.channelFirewall || {};
  const lanes = Array.isArray(channel.lanes) ? channel.lanes : [];
  const container = byId("channel-firewall-summary");
  if (!container) return;

  if (lanes.length === 0) {
    container.innerHTML = emptyState(
      "No channel profiles are set.",
      "Set a profile when an agent uses a channel that needs a clear action limit."
    );
  } else {
    const profiles = channel.profiles && typeof channel.profiles === "object" ? channel.profiles : {};
    container.innerHTML = lanes.slice(0, 12).map((lane) => {
      const profile = String(lane.profile || "observe");
      const label = profiles[profile] || titleFromId(profile);
      const kind = profile === "locked_down" ? "warning" : profile === "observe" ? "pending" : "ok";
      const ruleCount = Array.isArray(lane.rules) ? lane.rules.length : 0;
      return `<article class="plain-row">
        <div class="row-main">
          <div class="row-title"><strong>${escapeHtml(lane.agentId || "Unknown agent")}</strong>${stateLabel(label, kind)}</div>
          <p class="row-copy">Channel ${escapeHtml(lane.channelId || "Unknown channel")}</p>
          <p class="row-meta">${formatNumber(ruleCount)} policy rule${ruleCount === 1 ? "" : "s"}</p>
        </div>
      </article>`;
    }).join("");
  }

  const editor = byId("channel-firewall-editor");
  if (editor) editor.hidden = !catalog.editable;
}

function formatBudget(budget) {
  if (!budget) return "No budget data";
  const requestLimit = budget.maxRequests == null ? "no limit" : formatNumber(budget.maxRequests);
  const byteLimit = budget.maxBytes == null ? "no limit" : formatNumber(budget.maxBytes);
  return `${formatNumber(budget.requests)} of ${requestLimit} requests · ${formatNumber(budget.bytes)} of ${byteLimit} bytes`;
}

function renderAgents(state) {
  const agents = Array.isArray(state?.activeAgents) ? state.activeAgents : [];
  const sessions = Array.isArray(state?.sessions?.recent) ? state.sessions.recent : [];
  const container = byId("agents-list");
  setText("agents-count", `${agents.length} known`);

  if (agents.length === 0 && sessions.length === 0) {
    container.innerHTML = emptyState(
      "No agents have sent activity.",
      "Connect an agent, then get the latest status."
    );
    return;
  }

  const agentRows = agents.slice(0, 8).map((agent) => {
    const identity = agent.declared === true ? agent.label || "Declared identity" : "Identity not resolved";
    const kind = agent.riskLevel === "critical" || agent.riskLevel === "high" ? "warning" : "ok";
    return `<article class="plain-row">
      <div class="row-main">
        <div class="row-title"><strong>${escapeHtml(agent.agentId || "Unknown agent")}</strong>${stateLabel(identity, kind)}</div>
        <p class="row-copy">${escapeHtml(formatBudget(agent.budget))}</p>
        <p class="row-meta">${escapeHtml(agent.lastAction || "No action")} · ${escapeHtml(agent.lastPlane || "No plane")} · ${escapeHtml(formatRelative(agent.lastSeenAt))}</p>
      </div>
    </article>`;
  });

  const sessionRows = sessions.slice(0, 8).map((session) => {
    const kind = stateKind(session.status);
    return `<article class="plain-row">
      <div class="row-main">
        <div class="row-title"><strong>${escapeHtml(session.sessionId || "Unknown session")}</strong>${stateLabel(session.status || "unknown", kind)}</div>
        <p class="row-copy">${escapeHtml(session.note || `${session.pendingApprovals || 0} open approvals and ${session.evidenceCount || 0} evidence records.`)}</p>
        <p class="row-meta">${escapeHtml(session.agentId || "Unknown agent")} · ${escapeHtml(formatRelative(session.lastSeenAt))}</p>
      </div>
    </article>`;
  });

  container.innerHTML = [...agentRows, ...sessionRows].join("");
}

function renderEvidence(state) {
  const records = Array.isArray(state?.evidenceLedger) ? state.evidenceLedger : [];
  const container = byId("evidence-list");
  if (records.length === 0) {
    container.innerHTML = emptyState(
      "No evidence records are present.",
      "Run a protected agent action to create the first record."
    );
    return;
  }

  container.innerHTML = records.slice(0, 8).map((record) => {
    const kind = stateKind(record.status || record.riskLevel);
    return `<article class="plain-row">
      <div class="row-main">
        <div class="row-title"><strong>${escapeHtml(record.title || titleFromId(record.kind))}</strong>${stateLabel(record.status || record.kind || "record", kind)}</div>
        <p class="row-copy">${escapeHtml(record.summary || "No evidence summary is available.")}</p>
        <p class="row-meta">${escapeHtml(record.agentId || "Unknown agent")} · ${escapeHtml(record.sessionId || "No session")} · ${escapeHtml(formatRelative(record.timestamp))}</p>
      </div>
    </article>`;
  }).join("");
}

function renderHelp(state) {
  const entries = Array.isArray(state?.knowledgeBase?.entries) ? state.knowledgeBase.entries : [];
  const visible = entries.filter((entry) => entry.status !== "missing").slice(0, 6);
  const container = byId("help-list");
  if (visible.length === 0) {
    container.innerHTML = emptyState(
      "No local help is available.",
      "Open the repository documents for setup and policy details."
    );
    return;
  }

  container.innerHTML = visible.map((entry) => {
    const href = entry.href && String(entry.href).startsWith("/") ? entry.href : "/dashboard/knowledge-base";
    return `<article class="plain-row">
      <div class="row-main">
        <strong>${escapeHtml(entry.title || "Help topic")}</strong>
        <p class="row-copy">${escapeHtml(entry.summary || entry.excerpt || "Open this topic for details.")}</p>
        <p class="row-meta">${escapeHtml(titleFromId(entry.category || "reference"))}</p>
      </div>
      <a class="text-link" href="${escapeAttribute(href)}">Open</a>
    </article>`;
  }).join("");
}

function renderState(state) {
  currentState = state;
  firstStateLoaded = true;
  hideGlobalError();
  renderStatus(state);
  renderApprovals(state);
  renderPolicy(state);
  renderChannelFirewall(state);
  renderAgents(state);
  renderEvidence(state);
  renderHelp(state);
  setText("last-update", `Updated ${formatRelative(state.generatedAt)}`);
}

function normalizeField(field) {
  const source = field && typeof field === "object" ? field : {};
  const supported = new Set(["text", "number", "select", "textarea", "path", "boolean"]);
  const name = String(source.name || "value");
  let type = supported.has(source.type) ? source.type : "text";
  const options = Array.isArray(source.options) ? source.options.map(String) : [];
  if (name === "command") type = "select";
  return {
    name,
    label: String(source.label || titleFromId(name)),
    type,
    required: Boolean(source.required),
    options,
    placeholder: String(source.placeholder || ""),
  };
}

function normalizeAction(action) {
  const source = typeof action === "string" ? { id: action } : action || {};
  const id = String(source.id || source.action || "unknown-action");
  return {
    id,
    label: String(source.label || titleFromId(id)),
    group: normalizeActionGroup(source.group),
    mutating: typeof source.mutating === "boolean" ? source.mutating : MUTATING_ACTIONS.has(id),
    confirmation: Boolean(source.confirmation) || DESTRUCTIVE_ACTIONS.has(id),
    description: String(source.description || "Agentwall provides this allowlisted action."),
    cli: String(source.cli || `agentwall ${id.replaceAll("-", " ")}`),
    fields: Array.isArray(source.fields) ? source.fields.map(normalizeField) : [],
  };
}

function renderActionField(field, actionId) {
  const id = `action-${actionId}-${field.name}`.replaceAll(/[^a-zA-Z0-9_-]/g, "-");
  const required = field.required ? " required" : "";
  const placeholder = field.placeholder ? ` placeholder="${escapeAttribute(field.placeholder)}"` : "";
  const fieldType = escapeAttribute(field.type);
  const label = escapeHtml(field.label);
  const name = escapeAttribute(field.name);

  if (field.type === "boolean") {
    return `<label class="check-field" for="${id}"><input id="${id}" name="${name}" type="checkbox" data-field-type="boolean"${required} /> ${label}</label>`;
  }

  if (field.type === "select") {
    const options = field.options.length > 0 ? field.options : field.name === "command" ? ["No declared command"] : [];
    const disabled = field.name === "command" && field.options.length === 0 ? " disabled" : "";
    const defaultOption = field.required ? "" : '<option value="">Use default</option>';
    return `<label class="form-field" for="${id}"><span>${label}</span><select id="${id}" name="${name}" data-field-type="select"${required}${disabled}>${defaultOption}${options.map((option) => `<option value="${escapeAttribute(option)}">${escapeHtml(option)}</option>`).join("")}</select>${disabled ? "<small>The server did not declare an executable.</small>" : ""}</label>`;
  }

  if (field.type === "textarea") {
    const helper = field.name === "args" ? "<small>Use one argument per line.</small>" : "";
    return `<label class="form-field form-field-wide" for="${id}"><span>${label}</span><textarea id="${id}" name="${name}" data-field-type="textarea"${required}${placeholder}></textarea>${helper}</label>`;
  }

  const inputType = field.type === "number" ? "number" : "text";
  const mode = field.type === "number" ? " inputmode=\"decimal\"" : "";
  return `<label class="form-field" for="${id}"><span>${label}</span><input id="${id}" name="${name}" type="${inputType}" data-field-type="${fieldType}"${mode}${required}${placeholder} autocomplete="off" /></label>`;
}

function renderOperatorAction(action) {
  const safeId = escapeAttribute(action.id);
  const fields = action.fields.map((field) => renderActionField(field, action.id)).join("");
  const confirm = action.confirmation
    ? `<label class="check-field"><input name="confirm" type="checkbox" data-field-type="boolean" required /> Confirm this action and its stated effect.</label>`
    : "";
  const disabled = action.fields.some((field) => field.name === "command" && field.options.length === 0) ? " disabled" : "";
  const planCopy = action.id === "mcp-wrap"
    ? "Agentwall will prepare a command for the client-owned stdio stream."
    : action.id === "mcp-http-wrap"
      ? "Agentwall will start a local wrapper for the remote MCP server."
      : action.id === "mcp-http-stop"
        ? "Agentwall will stop the selected local MCP wrapper."
        : "Agentwall will run the allowlisted action below. The server will reject undeclared values.";
  const buttonLabel = action.id === "mcp-wrap"
    ? "Confirm and prepare"
    : action.id === "mcp-http-wrap"
      ? "Confirm and start"
      : action.id === "mcp-http-stop"
        ? "Confirm and stop"
        : action.confirmation ? "Confirm and run" : "Run action";

  if (!action.mutating) {
    return `<article class="plain-row read-only-action" data-action="${safeId}">
      <div class="row-main">
        <div class="row-title"><strong>${escapeHtml(action.label)}</strong>${stateLabel("Read only", "ok")}</div>
        <p class="row-copy">${escapeHtml(action.description)}</p>
        <div class="copy-row"><code class="command-line" id="command-${safeId}">${escapeHtml(action.cli)}</code><button class="button button-small button-secondary" type="button" data-copy-source="command-${safeId}">Copy command</button></div>
        <div class="action-result" aria-live="polite"></div>
      </div>
      <form data-operator-form data-action="${safeId}">
        ${fields ? `<div class="form-grid">${fields}</div>` : ""}
        <button class="button button-small button-secondary" type="submit">Get output</button>
      </form>
    </article>`;
  }

  return `<details class="action-disclosure" data-action="${safeId}" data-confirm="${action.confirmation ? "true" : "false"}">
    <summary><span class="action-summary-copy"><strong>${escapeHtml(action.label)}</strong><span>${escapeHtml(action.description)}</span></span></summary>
    <div class="action-body">
      <div><p class="field-label">Action plan</p><p class="row-copy">${escapeHtml(planCopy)}</p></div>
      <div class="copy-row"><code class="command-line" id="command-${safeId}">${escapeHtml(action.cli)}</code><button class="button button-small button-secondary" type="button" data-copy-source="command-${safeId}">Copy command</button></div>
      <form class="typed-form" data-operator-form data-action="${safeId}" data-confirm="${action.confirmation ? "true" : "false"}">
        ${fields ? `<div class="form-grid">${fields}</div>` : ""}
        ${confirm}
        <div class="form-actions"><button class="button ${action.confirmation ? "button-danger" : "button-primary"}" type="submit"${disabled}>${buttonLabel}</button><span class="form-state" aria-live="polite"></span></div>
        <div class="action-result" aria-live="polite"></div>
      </form>
    </div>
  </details>`;
}

function renderActionGroup(container, actions, label) {
  if (!container) return;
  if (actions.length === 0) {
    container.replaceChildren();
    return;
  }
  container.innerHTML = `<h3 class="action-group-heading">${escapeHtml(label)}</h3>${actions.map(renderOperatorAction).join("")}`;
}

function renderOperatorActions(actions) {
  operatorActions = actions.map(normalizeAction).filter((action) => action.id !== "unknown-action");
  for (const targetId of new Set(Object.values(GROUP_TARGETS))) {
    const container = byId(targetId);
    if (container) container.replaceChildren();
  }

  const groups = Object.keys(GROUP_TARGETS);
  for (const group of groups) {
    const target = byId(GROUP_TARGETS[group]);
    const inGroup = operatorActions.filter((action) => action.group === group);
    if (!target || inGroup.length === 0) continue;
    const block = document.createElement("div");
    block.innerHTML = `<h3 class="action-group-heading">${escapeHtml(GROUP_LABELS[group])}</h3>${inGroup.map(renderOperatorAction).join("")}`;
    while (block.firstChild) target.append(block.firstChild);
  }

  const operations = operatorActions.filter((action) => GROUP_TARGETS[action.group] === "operator-catalog");
  const catalog = byId("operator-catalog");
  if (operations.length === 0) {
    catalog.innerHTML = emptyState(
      "No host actions are available.",
      "The server did not return an operations catalog."
    );
  }
  setText("operation-catalog-state", `${operatorActions.length} allowed actions`);
}

function readActionPayload(form) {
  const payload = { action: form.dataset.action };
  for (const control of form.elements) {
    if (!control.name || control.disabled || control.type === "submit") continue;
    const fieldType = control.dataset.fieldType || control.type;
    if (fieldType === "boolean" || control.type === "checkbox") {
      payload[control.name] = Boolean(control.checked);
    } else if (fieldType === "number") {
      payload[control.name] = control.value === "" ? undefined : Number(control.value);
    } else if (control.name === "args") {
      payload[control.name] = String(control.value).split("\n").map((item) => item.trim()).filter(Boolean);
    } else {
      if (control.value === "" && !control.required) continue;
      payload[control.name] = control.value;
    }
  }
  return Object.fromEntries(Object.entries(payload).filter(([, value]) => value !== undefined));
}

function responseSecret(data) {
  if (!data || typeof data !== "object") return null;
  for (const key of ["secret", "credential", "token"]) {
    if (typeof data[key] === "string" && data[key]) return data[key];
  }
  return null;
}

function responseOutput(data) {
  if (data == null) return "No command output is available.";
  if (typeof data === "string") return data;
  if (typeof data.output === "string") return data.output;
  if (typeof data.stdout === "string") return data.stdout;
  return JSON.stringify(data, null, 2);
}

function renderActionResult(form, result) {
  const target = form.querySelector(".action-result") || form.closest(".plain-row")?.querySelector(".action-result");
  if (!target) return;
  target.replaceChildren();

  const secret = responseSecret(result?.data);
  if (secret) {
    const panel = document.createElement("div");
    panel.className = "secret-panel";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = "Copy this secret now.";
    const warning = document.createElement("p");
    warning.textContent = "Agentwall shows this fleet secret once and does not store it in the browser.";
    const value = document.createElement("code");
    value.className = "secret-value";
    value.textContent = secret;
    value.id = `secret-${Date.now()}`;
    copy.append(title, warning, value);
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const copyButton = document.createElement("button");
    copyButton.type = "button";
    copyButton.className = "button button-small button-secondary";
    copyButton.dataset.copySource = value.id;
    copyButton.textContent = "Copy secret";
    const clearButton = document.createElement("button");
    clearButton.type = "button";
    clearButton.className = "button button-small button-secondary";
    clearButton.dataset.clearSecret = "true";
    clearButton.textContent = "Clear secret";
    actions.append(copyButton, clearButton);
    panel.append(copy, actions);
    target.append(panel);
  }

  const visibleOutput = actionResultOutput(result);
  if (visibleOutput !== undefined && !secret) {
    const output = document.createElement("pre");
    output.className = "action-output";
    output.textContent = responseOutput(visibleOutput);
    target.append(output);
  }
}

async function submitOperatorAction(form) {
  const button = form.querySelector('button[type="submit"]');
  const state = form.querySelector(".form-state");
  const payload = readActionPayload(form);
  if (button) {
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
  }
  if (state) {
    state.classList.remove("form-state-error");
    state.textContent = "Agentwall is applying this action.";
  }

  try {
    const result = await postJSON("/api/operator/actions", payload);
    if (state) state.textContent = result.message || "Agentwall completed the action.";
    renderActionResult(form, result);
    showFeedback("success", result.message || "Action complete", result.next || "Get the latest status to confirm the result.");
    await refreshState({ quiet: true });
  } catch (error) {
    const rendered = renderStructuredActionFailure(
      error,
      String(payload.action || "unknown"),
      (_action, result) => renderActionResult(form, result)
    );
    if (state) {
      state.classList.add("form-state-error");
      state.textContent = error.message || "Agentwall could not complete the action.";
    }
    showFeedback("error", "Action failed", error.message || "Check the values, then try again.");
    if (!rendered && error instanceof RequestError && authMessage(error.status)) showGlobalError(error);
  } finally {
    if (button) {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }
}

async function submitApprovalDecision(button) {
  const requestId = button.dataset.requestId;
  const decision = button.dataset.approvalDecision;
  if (!requestId || !decision) return;
  const verb = decision === "approved" ? "approve" : "deny";
  if (!window.confirm(`Confirm that you want to ${verb} this request.`)) return;

  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    await postJSON(`/approval/${encodeURIComponent(requestId)}/respond`, {
      decision,
      note: "Decision from the local operator console.",
    });
    showFeedback("success", `Request ${decision}`, "Agentwall recorded the operator decision.");
    await refreshState({ quiet: true });
  } catch (error) {
    showFeedback("error", "Decision failed", error.message || "Get the latest status, then try again.");
    if (error instanceof RequestError && authMessage(error.status)) showGlobalError(error);
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

async function submitPolicyForm(form) {
  const values = new FormData(form);
  const payload = {
    id: String(values.get("id") || "").trim() || undefined,
    description: String(values.get("description") || "").trim(),
    plane: String(values.get("plane") || "all"),
    decision: String(values.get("decision") || "deny"),
    riskLevel: String(values.get("riskLevel") || "high"),
    reason: String(values.get("reason") || "").trim(),
    subjectAgentIds: csv(values.get("subjectAgentIds")),
    actionIncludes: csv(values.get("actionIncludes")),
    enabled: values.get("enabled") === "on",
  };
  const feedback = byId("policy-form-state");
  const button = form.querySelector('button[type="submit"]');

  if (payload.decision === "allow" && !window.confirm("This rule can allow an action. Confirm the policy change.")) {
    feedback.textContent = "Agentwall did not change the rule.";
    return;
  }

  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  feedback.classList.remove("form-state-error");
  feedback.textContent = "Agentwall is saving the rule.";
  try {
    await postJSON("/api/dashboard/control/policy-scoped-rule", payload);
    feedback.textContent = "Agentwall saved the rule.";
    showFeedback("success", "Policy saved", "Agentwall loaded the new scoped rule.");
    await refreshState({ quiet: true });
  } catch (error) {
    feedback.classList.add("form-state-error");
    feedback.textContent = error.message || "Agentwall could not save the rule.";
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

async function submitChannelFirewallForm(form) {
  const values = new FormData(form);
  const payload = {
    agentId: String(values.get("agentId") || "").trim(),
    channelId: String(values.get("channelId") || "").trim(),
    profile: String(values.get("profile") || "observe"),
  };
  const feedback = byId("channel-firewall-form-state");
  const button = form.querySelector('button[type="submit"]');

  if (!window.confirm("Confirm this channel profile change.")) {
    if (feedback) feedback.textContent = "Agentwall did not change the profile.";
    return;
  }

  if (button) {
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
  }
  if (feedback) {
    feedback.classList.remove("form-state-error");
    feedback.textContent = "Agentwall is saving the profile.";
  }
  try {
    await postJSON("/api/dashboard/control/channel-firewall-profile", payload);
    if (feedback) feedback.textContent = "Agentwall saved the profile.";
    showFeedback("success", "Channel profile saved", "Agentwall loaded the new channel controls.");
    await refreshState({ quiet: true });
  } catch (error) {
    if (feedback) {
      feedback.classList.add("form-state-error");
      feedback.textContent = error.message || "Agentwall could not save the profile.";
    }
    if (error instanceof RequestError && authMessage(error.status)) showGlobalError(error);
  } finally {
    if (button) {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }
}

async function copyTextFrom(sourceId, button) {
  const source = byId(sourceId);
  const text = source?.textContent || "";
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    const previous = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => { button.textContent = previous; }, 1600);
  } catch {
    showFeedback("error", "Copy failed", "Select the text and copy it with the keyboard.");
  }
}

async function loadOperatorActions() {
  const data = await requestJSON("/api/operator/actions");
  const actions = Array.isArray(data?.actions) ? data.actions : [];
  renderOperatorActions(actions);
}

async function refreshState(options = {}) {
  try {
    const state = await requestJSON("/api/dashboard/state");
    renderState(state);
    setConnectionState("ok", eventsStream ? "Live" : "Connected", `Updated ${formatRelative(state.generatedAt)}`);
    return state;
  } catch (error) {
    setConnectionState(navigator.onLine ? "warning" : "danger", navigator.onLine ? "Retry" : "Offline", "Status is not current");
    if (!options.quiet || !firstStateLoaded) showGlobalError(error);
    throw error;
  }
}

function stopPolling() {
  if (pollTimer) window.clearInterval(pollTimer);
  pollTimer = null;
}

function startPolling() {
  if (pollTimer) return;
  setConnectionState("warning", "Poll mode", "Live updates are not available");
  pollTimer = window.setInterval(() => {
    refreshState({ quiet: true }).catch(() => {});
  }, REFRESH_MS);
}

function installEventStream() {
  if (!("EventSource" in window) || !navigator.onLine) {
    startPolling();
    return;
  }
  if (eventsStream) eventsStream.close();

  const stream = new EventSource("/api/dashboard/events", { withCredentials: true });
  eventsStream = stream;
  setConnectionState("pending", "Connect", "Live status will start soon");

  stream.addEventListener("dashboard-state", (event) => {
    try {
      renderState(JSON.parse(event.data));
      stopPolling();
      setConnectionState("ok", "Live", `Updated ${formatRelative(currentState?.generatedAt)}`);
    } catch {
      setConnectionState("warning", "Poll mode", "Live data was invalid");
      stream.close();
      eventsStream = null;
      startPolling();
    }
  });

  stream.addEventListener("dashboard-error", () => {
    setConnectionState("warning", "Poll mode", "Live status failed");
  });

  stream.onerror = () => {
    stream.close();
    if (eventsStream === stream) eventsStream = null;
    startPolling();
  };
}

function scrollToArea(id) {
  const target = byId(id);
  if (!target) return;
  target.scrollIntoView({ behavior: prefersReducedMotion ? "auto" : "smooth", block: "start" });
  window.setTimeout(() => target.querySelector("h2")?.focus?.(), prefersReducedMotion ? 0 : 220);
}

function installNavigation() {
  const links = Array.from(document.querySelectorAll("[data-nav-link]"));
  const sections = links.map((link) => byId(link.getAttribute("href").slice(1))).filter(Boolean);
  const observer = new IntersectionObserver((entries) => {
    const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    for (const link of links) {
      if (link.getAttribute("href") === `#${visible.target.id}`) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
  }, { rootMargin: "-20% 0px -65% 0px", threshold: [0, 0.2, 0.5] });
  sections.forEach((section) => observer.observe(section));

  document.addEventListener("keydown", (event) => {
    const target = event.target;
    const editable = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement || target?.isContentEditable;
    if (event.altKey && /^[1-7]$/.test(event.key)) {
      event.preventDefault();
      const link = links.find((item) => item.dataset.shortcut === event.key);
      if (link) scrollToArea(link.getAttribute("href").slice(1));
      return;
    }
    if (!editable && event.key.toLowerCase() === "r") {
      event.preventDefault();
      refreshState().catch(() => {});
      return;
    }
    if (!editable && event.key === "?") {
      event.preventDefault();
      const help = byId("help");
      const details = help?.querySelector("details");
      if (details) details.open = true;
      scrollToArea("help");
    }
  });
}
function installActions() {
  document.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    if (button.matches("[data-retry]")) {
      Promise.allSettled([refreshState(), loadOperatorActions()]).then(() => installEventStream());
      return;
    }
    if (button.matches("[data-approval-decision]")) {
      submitApprovalDecision(button);
      return;
    }
    if (button.dataset.copySource) {
      copyTextFrom(button.dataset.copySource, button);
      return;
    }
    if (button.dataset.clearSecret) {
      button.closest(".secret-panel")?.remove();
      showFeedback("success", "Secret cleared", "Agentwall removed the secret from this page.");
    }
  });

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.matches("[data-operator-form]")) {
      event.preventDefault();
      submitOperatorAction(form);
      return;
    }
    if (form.id === "policy-form") {
      event.preventDefault();
      submitPolicyForm(form);
    }
    if (form.id === "channel-firewall-form") {
      event.preventDefault();
      submitChannelFirewallForm(form);
    }
  });
}

async function boot() {
  installNavigation();
  installActions();
  setConnectionState("pending", "Connect", "Wait for the first status");

  const results = await Promise.allSettled([refreshState(), loadOperatorActions()]);
  const stateFailure = results[0].status === "rejected" ? results[0].reason : null;
  const actionFailure = results[1].status === "rejected" ? results[1].reason : null;

  if (actionFailure) {
    byId("operator-catalog").innerHTML = emptyState(
      "Operator actions are not available.",
      actionFailure.message || "Check local operator access, then try again.",
      true
    );
    setText("operation-catalog-state", "Catalog error");
    if (!stateFailure && actionFailure instanceof RequestError && authMessage(actionFailure.status)) showGlobalError(actionFailure);
  }

  if (stateFailure && !firstStateLoaded) {
    byId("status-loading").hidden = true;
  }
  if (window.location.pathname.includes("knowledge-base")) {
    scrollToArea("help");
  }


  installEventStream();
  window.addEventListener("online", () => {
    hideGlobalError();
    refreshState({ quiet: true }).catch(() => {});
    installEventStream();
  });
  window.addEventListener("offline", () => {
    if (eventsStream) eventsStream.close();
    eventsStream = null;
    setConnectionState("danger", "Offline", "The last status stays visible");
  });
}

boot();
