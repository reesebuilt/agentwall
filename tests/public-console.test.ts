import { readFileSync } from "fs";
import { join } from "path";
import { describe, expect, it, jest } from "@jest/globals";

const publicDir = join(__dirname, "..", "public");
const html = readFileSync(join(publicDir, "index.html"), "utf8");
const script = readFileSync(join(publicDir, "app.js"), "utf8");
const styles = readFileSync(join(publicDir, "styles.css"), "utf8");

const mutatingActions = [
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
];

describe("public operator console contract", () => {
  it("contains the simple operator areas and accessible state regions", () => {
    expect(html).toContain("Agentwall status");
    expect(html).toContain("Next action");
    expect(html).toContain("Approvals");
    expect(html).toContain("Policy");
    expect(html).toContain("Agents");
    expect(html).toContain("Evidence");
    expect(html).toContain("Help");
    expect(html).toContain("Operations");
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('data-action="operator"');
  });

  it("loads state and renders the typed operator action catalog", () => {
    expect(script).toContain('/api/dashboard/state');
    expect(script).toContain('/api/dashboard/events');
    expect(script).toContain('/api/operator/actions');
    expect(script).toContain("function renderOperatorAction");
    expect(html).toContain("/assets/action-catalog.js");
    expect(script).toContain("prefers-reduced-motion");
    expect(script).not.toContain("shell-input");
    expect(script).toContain('credentials: "same-origin"');
    expect(script).not.toContain("localStorage");
    expect(script).toContain('field.name === "command"');
    expect(script).toContain('<option value="">Use default</option>');
    expect(script).toContain('control.value === "" && !control.required');
    expect(script).toContain('${fields ? `<div class="form-grid">${fields}</div>` : ""}');
  });

  it("recognizes every supported mutating action", () => {
    for (const action of mutatingActions) {
      expect(script).toContain(`\"${action}\"`);
    }
  });

  it("keeps hidden console states out of layout", () => {
    expect(styles).toContain("[hidden] { display: none !important; }");
  });

  it("defines small-screen, focus, and reduced-motion states", () => {
    expect(styles).toContain("@media (max-width: 599px)");
    expect(styles).toContain(":focus-visible");
    expect(styles).toContain("@media (prefers-reduced-motion: reduce)");
  });

  it("maps real server catalog group names to visible UI areas", () => {
    const actionCatalog = require("../public/assets/action-catalog.js") as {
      normalizeActionGroup: (group: unknown) => string;
      renderStructuredActionFailure: (
        error: unknown,
        action: string,
        render: (action: string, result: unknown) => void,
      ) => boolean;
    };

    expect(actionCatalog.normalizeActionGroup("Runtime")).toBe("runtime");
    expect(actionCatalog.normalizeActionGroup("Sessions")).toBe("sessions");
    expect(actionCatalog.normalizeActionGroup("MCP")).toBe("mcp");
    expect(actionCatalog.normalizeActionGroup("Decoys")).toBe("decoy");
  });

  it("renders a structured non-2xx action result instead of discarding it", () => {
    const { renderStructuredActionFailure, actionResultOutput } = require("../public/assets/action-catalog.js") as {
      renderStructuredActionFailure: (
        error: unknown,
        action: string,
        render: (action: string, result: unknown) => void,
      ) => boolean;
      actionResultOutput: (result: unknown) => unknown;
    };
    const render = jest.fn();
    const result = { action: "anchor", ok: false, failed: 1, message: "Anchor failed." };

    expect(renderStructuredActionFailure({ data: result }, "anchor", render)).toBe(true);
    expect(render).toHaveBeenCalledWith("anchor", result);
    expect(actionResultOutput(result)).toBe(result);
  });
});
