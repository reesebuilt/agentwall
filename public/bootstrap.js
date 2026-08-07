const STATUS_REFRESH_MS = 1500;
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const BOOTSTRAP_ROUTES = Object.freeze({
  status: "/api/bootstrap/status",
  setup: "/api/bootstrap/setup",
  init: "/api/bootstrap/init",
  onboard: "/api/bootstrap/onboard",
  start: "/api/bootstrap/start",
  dev: "/api/bootstrap/dev",
  stop: "/api/bootstrap/stop",
});


let statusTimer = null;
let feedbackTimer = null;
let currentStatus = null;

class BootstrapRequestError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "BootstrapRequestError";
    this.status = status;
  }
}

function byId(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const element = byId(id);
  if (element) element.textContent = String(value ?? "");
}

function setDot(id, kind) {
  const dot = byId(id);
  if (dot) dot.className = `state-dot state-${kind}`;
}

function stateKind(value) {
  const state = String(value ?? "").toLowerCase();
  if (["failed", "error"].includes(state)) return "danger";
  if (["missing", "stopped"].includes(state)) return "warning";
  if (["starting", "stopping", "pending"].includes(state)) return "pending";
  return "ok";
}

function titleFromState(value) {
  const state = String(value ?? "unknown");
  return state.charAt(0).toUpperCase() + state.slice(1).replaceAll("_", " ");
}

function formatTime(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) return "No update";
  return new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function setConnectionState(kind, label, detail) {
  setDot("bootstrap-connection-dot", kind);
  setText("bootstrap-connection", label);
  setText("bootstrap-last-update", detail);
}

async function requestJSON(url, options = {}) {
  const request = {
    method: options.method || "GET",
    credentials: "same-origin",
    headers: { accept: "application/json" },
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
    const authMessage = response.status === 401 || response.status === 403
      ? "The local bootstrap session is not valid. Reload this page, then try again."
      : null;
    const message = authMessage
      || (typeof data === "object" && data ? data.message || data.error || data.detail : data)
      || `The bootstrap service returned status ${response.status}.`;
    throw new BootstrapRequestError(String(message), response.status);
  }
  return data;
}

function postJSON(url, body) {
  return requestJSON(url, { method: "POST", body });
}

function hideError() {
  byId("bootstrap-error").hidden = true;
}

function showError(error, title = "The bootstrap service did not return status.") {
  setText(
    "bootstrap-error-title",
    error instanceof BootstrapRequestError && [401, 403].includes(error.status)
      ? "The local bootstrap session is not valid."
      : title
  );
  setText("bootstrap-error-detail", error?.message || "Check this local process, then try again.");
  byId("bootstrap-error").hidden = false;
}

function showFeedback(kind, title, message) {
  window.clearTimeout(feedbackTimer);
  const panel = byId("bootstrap-feedback");
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

function normalizeStatus(status) {
  const source = status && typeof status === "object" ? status : {};
  const serviceSource = source.service;
  const service = typeof serviceSource === "object"
    ? serviceSource.status || serviceSource.state || "unknown"
    : serviceSource || source.status || "unknown";
  const setupSource = source.setup;
  const setup = typeof setupSource === "object"
    ? setupSource.status || setupSource.state || (setupSource.created ? "ready" : "unknown")
    : setupSource || "unknown";
  return {
    service: String(service),
    setup: String(setup),
    host: String(source.host || source.serviceHost || serviceSource?.host || "127.0.0.1"),
    port: Number(source.port || source.servicePort || serviceSource?.port || 3000),
    dashboardUrl: String(source.dashboardUrl || serviceSource?.dashboardUrl || "/dashboard"),
    message: String(source.message || serviceSource?.message || ""),
    updatedAt: source.updatedAt || source.generatedAt || new Date().toISOString(),
  };
}

function serviceCopy(status) {
  if (status.service === "running") return "Agentwall is ready for local operator access.";
  if (status.service === "starting") return "Agentwall will open the operator console after startup.";
  if (status.service === "stopping") return "Agentwall will report a stopped state soon.";
  if (status.service === "failed") return status.message || "Agentwall could not start. Review the process output.";
  if (status.setup === "missing") return "Create the local setup before you start Agentwall.";
  if (status.service === "stopped") return "The setup is ready. Start Agentwall when you want to use the console.";
  return status.message || "The bootstrap service has not sent a complete state.";
}

function safeDashboardUrl(status) {
  try {
    const raw = status.dashboardUrl || "/dashboard";
    const target = raw.startsWith("/")
      ? new URL(raw, window.location.origin)
      : new URL(raw);
    if (!["http:", "https:"].includes(target.protocol)) return "#";
    const loopback = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
    const currentHost = window.location.hostname;
    if (loopback.has(target.hostname) && loopback.has(currentHost)) {
      target.hostname = currentHost;
    } else if (target.hostname !== currentHost) {
      return "#";
    }
    if (raw.startsWith("/")) target.port = String(status.port);
    return target.href;
  } catch {
    return "#";
  }
}

function renderStatus(rawStatus) {
  const status = normalizeStatus(rawStatus);
  currentStatus = status;
  const kind = stateKind(status.service === "unknown" ? status.setup : status.service);
  const label = titleFromState(status.service);
  byId("bootstrap-loading").hidden = true;
  byId("bootstrap-status-content").hidden = false;
  setDot("bootstrap-service-dot", kind);
  setDot("bootstrap-protection-dot", kind);
  setText("bootstrap-service-state", label);
  setText("bootstrap-service-value", label);
  setText("bootstrap-service-copy", serviceCopy(status));
  setText("bootstrap-setup-value", titleFromState(status.setup));
  setText("bootstrap-process-value", label);
  setText("bootstrap-host-value", status.host);
  setText("bootstrap-port-value", status.port);
  setText("bootstrap-status-time", `Updated ${formatTime(status.updatedAt)}`);
  setText("bootstrap-last-update", `Updated ${formatTime(status.updatedAt)}`);

  const handoff = byId("dashboard-handoff");
  handoff.hidden = status.service !== "running";
  if (status.service === "running") {
    const link = byId("dashboard-link");
    link.href = safeDashboardUrl(status);
    link.toggleAttribute("aria-disabled", link.getAttribute("href") === "#");
  }
}

function setupPayload(form) {
  const values = new FormData(form);
  return {
    mode: String(values.get("mode") || "monitor"),
    host: String(values.get("host") || "127.0.0.1").trim(),
    port: Number(values.get("port") || 3000),
    allowedHosts: String(values.get("allowedHosts") || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    lanAccess: values.get("lanAccess") === "on",
    force: values.get("force") === "on",
  };
}

function onboardPayload(form) {
  const values = new FormData(form);
  return {
    profileId: String(values.get("profileId") || "generic").trim(),
    agentId: String(values.get("agentId") || "generic").trim(),
  };
}

function actionPayload(form, action) {
  if (action === "setup") return setupPayload(form);
  if (action === "onboard") return onboardPayload(form);
  return {};
}

function oneTimeEnvironment(result) {
  if (Array.isArray(result?.env)) return result.env.join("\n");
  if (typeof result?.env === "string") return result.env;
  if (result?.env && typeof result.env === "object") {
    return Object.entries(result.env).map(([key, value]) => `${key}=${value}`).join("\n");
  }
  if (Array.isArray(result?.data?.env)) return result.data.env.join("\n");
  if (typeof result?.data?.env === "string") return result.data.env;
  if (result?.data?.env && typeof result.data.env === "object") {
    return Object.entries(result.data.env).map(([key, value]) => `${key}=${value}`).join("\n");
  }
  return null;
}

function showOneTimeEnvironment(form, environment) {
  const target = form.querySelector(".bootstrap-secret");
  if (!target || !environment) return;
  target.replaceChildren();
  const panel = document.createElement("div");
  panel.className = "secret-panel";
  const copy = document.createElement("div");
  const title = document.createElement("strong");
  title.textContent = "Copy this environment now.";
  const warning = document.createElement("p");
  warning.textContent = "Copy this environment now. AgentWall does not store the credential.";
  const value = document.createElement("pre");
  value.className = "command-line secret-value";
  value.textContent = environment;
  value.id = `bootstrap-env-${Date.now()}`;
  copy.append(title, warning, value);
  const actions = document.createElement("div");
  actions.className = "row-actions";
  const copyButton = document.createElement("button");
  copyButton.type = "button";
  copyButton.className = "button button-small button-secondary";
  copyButton.dataset.bootstrapCopy = value.id;
  copyButton.textContent = "Copy environment";
  const clearButton = document.createElement("button");
  clearButton.type = "button";
  clearButton.className = "button button-small button-secondary";
  clearButton.dataset.bootstrapClear = "true";
  clearButton.textContent = "Clear environment";
  actions.append(copyButton, clearButton);
  panel.append(copy, actions);
  target.append(panel);
}

async function submitAction(form) {
  const action = form.dataset.bootstrapAction;
  if (!action) return;
  const payload = actionPayload(form, action);
  if (action === "setup" && payload.force && !window.confirm("Confirm that setup can replace existing local setup files.")) return;

  const button = form.querySelector('button[type="submit"]');
  const state = form.querySelector(".form-state");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  if (state) {
    state.classList.remove("form-state-error");
    state.textContent = "Agentwall is applying this action.";
  }

  try {
    const result = await postJSON(BOOTSTRAP_ROUTES[action], payload);
    const environment = action === "onboard" ? oneTimeEnvironment(result) : null;
    if (environment) showOneTimeEnvironment(form, environment);
    if (state) state.textContent = result.message || "Agentwall completed this action.";
    showFeedback("success", result.message || "Action complete", result.next || "Review the current service status.");
    await loadStatus({ quiet: true });
  } catch (error) {
    if (state) {
      state.classList.add("form-state-error");
      state.textContent = error.message || "Agentwall could not complete this action.";
    }
    showFeedback("error", "Action failed", error.message || "Check the values, then try again.");
    if (error instanceof BootstrapRequestError && [401, 403].includes(error.status)) showError(error);
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

async function copyValue(sourceId, button) {
  const value = byId(sourceId)?.textContent || "";
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    const previous = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => { button.textContent = previous; }, 1600);
  } catch {
    showFeedback("error", "Copy failed", "Select the environment and copy it with the keyboard.");
  }
}

async function loadStatus(options = {}) {
  try {
    const status = await requestJSON(BOOTSTRAP_ROUTES.status);
    hideError();
    renderStatus(status);
    setConnectionState("ok", "Connected", `Updated ${formatTime(status.updatedAt || status.generatedAt)}`);
    return status;
  } catch (error) {
    setConnectionState(navigator.onLine ? "warning" : "danger", navigator.onLine ? "Retry" : "Offline", "Status is not current");
    if (!options.quiet || !currentStatus) showError(error);
    throw error;
  }
}

function startStatusRefresh() {
  if (statusTimer) window.clearInterval(statusTimer);
  statusTimer = window.setInterval(() => {
    if (navigator.onLine) loadStatus({ quiet: true }).catch(() => {});
  }, STATUS_REFRESH_MS);
}

function installActions() {
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.dataset.bootstrapAction) return;
    event.preventDefault();
    submitAction(form);
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    if (button.dataset.bootstrapRetry !== undefined) {
      loadStatus().catch(() => {});
      return;
    }
    if (button.dataset.bootstrapCopy) {
      copyValue(button.dataset.bootstrapCopy, button);
      return;
    }
    if (button.dataset.bootstrapClear) {
      button.closest(".secret-panel")?.remove();
      showFeedback("success", "Environment cleared", "Agentwall removed the environment from this page.");
    }
  });

  document.addEventListener("keydown", (event) => {
    const target = event.target;
    const editable = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement;
    if (!editable && event.key.toLowerCase() === "r") {
      event.preventDefault();
      loadStatus().catch(() => {});
    }
  });
}

async function boot() {
  installActions();
  setConnectionState("pending", "Connect", "Wait for the first status");
  await loadStatus().catch(() => {
    byId("bootstrap-loading").hidden = true;
  });
  startStatusRefresh();

  window.addEventListener("online", () => {
    hideError();
    loadStatus({ quiet: true }).catch(() => {});
  });
  window.addEventListener("offline", () => {
    setConnectionState("danger", "Offline", "The last status stays visible");
  });
}

boot();
