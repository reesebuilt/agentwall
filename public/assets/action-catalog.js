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

  const api = { GROUP_TARGETS, normalizeActionGroup };
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    global.AgentwallActionCatalog = api;
  }
})(typeof globalThis === "object" ? globalThis : this);
