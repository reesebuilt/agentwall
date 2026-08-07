(function (global) {
  "use strict";

  const GROUP_TARGETS = Object.freeze({
    runtime: "runtime-actions",
    sessions: "session-actions",
    fleet: "fleet-actions",
    evidence: "evidence-actions",
    mcp: "operator-catalog",
    perimeter: "operator-catalog",
    sandbox: "operator-catalog",
    interception: "operator-catalog",
    decoy: "operator-catalog",
    policy: "operator-catalog",
    status: "operator-catalog",
  });

  function normalizeActionGroup(group) {
    const normalized = String(group || "").toLowerCase();
    return GROUP_TARGETS[normalized] ? normalized : "decoy";
  }

  function renderStructuredActionFailure(error, action, render) {
    if (!error || typeof error !== "object" || !("data" in error)) return false;
    const result = error.data;
    if (!result || typeof result !== "object" || Array.isArray(result)) return false;
    if (!("action" in result) || typeof result.action !== "string") return false;
    if (!("ok" in result) || typeof result.ok !== "boolean") return false;
    render(action, result);
    return true;
  }

  function actionResultOutput(result) {
    if (!result || typeof result !== "object" || Array.isArray(result)) return undefined;
    if (result.ok === false) return result;
    return "data" in result && result.data !== undefined ? result.data : undefined;
  }

  const api = {
    GROUP_TARGETS,
    normalizeActionGroup,
    renderStructuredActionFailure,
    actionResultOutput,
  };
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    global.AgentwallActionCatalog = api;
  }
})(typeof globalThis === "object" ? globalThis : this);
